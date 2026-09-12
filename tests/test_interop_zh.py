"""SIP 国密套件（ZH）互操作测试 —— 主库 ↔ 参考实现（SPEC v1.1 §14 验证链）

与 tests/test_interop.py（EN）同构的三类双向断言，全部走 ZH 套件：
1. 向量回放：消费 tests/vectors/sip_test_vectors_zh.json（静态 + CI 即时重建），
   参考实现以独立实现（手工 HMAC-SM3/HKDF-SM3/Jacobian SM2 点乘）复算
2. 活体对话：主库与参考实现实时互为对端，握手→消息→rekey 闭环
3. 负路径：篡改签名/密文 + 套件协商失败（不匹配/未知值/字段剥离）
"""

import base64
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts" / "interop"))

import reference_impl as ref  # noqa: E402

from sip_protocol.crypto.suite import SUITE_ZH  # noqa: E402
from sip_protocol.exceptions import SuiteNegotiationError  # noqa: E402
from sip_protocol.protocol.handshake import (  # noqa: E402
    complete_handshake,
    initiate_handshake,
    respond_handshake,
)
from sip_protocol.protocol.message import decrypt_message, encrypt_message  # noqa: E402
from sip_protocol.protocol.rekey import RekeyManager  # noqa: E402
from sip_protocol.transport.encrypted_channel import EncryptedChannel  # noqa: E402
from sip_protocol.transport.message import AgentMessage  # noqa: E402

PSK = b"interop-vector-psk-2026"
VECTOR_FILE = Path(__file__).resolve().parents[1] / "tests" / "vectors" / "sip_test_vectors_zh.json"

# 回放历史 transcript：跳过时间戳新鲜度（HMAC/签名仍全程验证）——见 reference_impl
REPLAY = {"check_timestamp": False}


def _fresh_vectors() -> dict:
    """CI 通路：即时重建 ZH 向量（生成→参考实现消费→双向断言）"""
    from generate_vectors import build_vectors_zh

    return build_vectors_zh()


VECTOR_SOURCES = [
    pytest.param(lambda: json.loads(VECTOR_FILE.read_text()), id="committed-zh"),
    pytest.param(_fresh_vectors, id="fresh-ci-zh"),
]


def _keys_from_hex(d: dict) -> dict[str, bytes]:
    return {k: bytes.fromhex(v) for k, v in d.items()}


# ═════════════════ 1. 向量回放 ═════════════════


class TestVectorReplayZH:
    @pytest.mark.parametrize("source", VECTOR_SOURCES)
    def test_handshake_keys_rederived_initiator_side(self, source):
        """参考实现扮演 initiator：SM2 私钥 + Auth → 独立派生密钥 == 主库导出值"""
        v = source()
        hs = v["handshake"]
        state = {
            "psk": bytes.fromhex(v["psk_hex"]),
            "identity_priv": bytes.fromhex(hs["initiator_identity_priv"]),
            "ephemeral_priv": bytes.fromhex(hs["initiator_ephemeral_priv"]),
            "nonce": bytes.fromhex(hs["hello"]["nonce"]),
            "suite": "ZH",
        }
        keys = ref.ReferenceSIP.initiator_finish(hs["auth"], state, **REPLAY)
        assert keys == _keys_from_hex(hs["expected_keys"])
        assert len(keys["encryption_key"]) == 16  # SM4-128

    @pytest.mark.parametrize("source", VECTOR_SOURCES)
    def test_handshake_keys_rederived_responder_side(self, source):
        """参考实现扮演 responder：SM2 私钥 + Hello → 独立派生同一组密钥"""
        v = source()
        hs = v["handshake"]
        _auth, keys = ref.ReferenceSIP.responder_handle_hello(
            hs["hello"],
            bytes.fromhex(v["psk_hex"]),
            identity_priv=bytes.fromhex(hs["responder_identity_priv"]),
            ephemeral_priv=bytes.fromhex(hs["responder_ephemeral_priv"]),
            nonce=bytes.fromhex(hs["auth"]["auth_data"]["nonce"]),
            suite=SUITE_ZH,
            **REPLAY,
        )
        assert keys == _keys_from_hex(hs["expected_keys"])

    @pytest.mark.parametrize("source", VECTOR_SOURCES)
    def test_auth_hmac_sm3_verified_byte_exact(self, source):
        """Auth 签名 transcript 逐字节验证（HMAC-SM3 + §4.4 json.dumps 分隔符复刻）"""
        v = source()
        hs = v["handshake"]
        keys = _keys_from_hex(hs["expected_keys"])
        transcript = ref.ReferenceSIP.auth_transcript(
            hs["auth"]["auth_data"]["ephemeral_pub"],
            hs["auth"]["auth_data"]["nonce"],
            hs["auth"]["timestamp"],
        )
        expected = ref.hmac_digest(keys["auth_key"], transcript, "ZH")
        assert base64.b64encode(expected).decode() == hs["auth"]["signature"]

    @pytest.mark.parametrize("source", VECTOR_SOURCES)
    def test_message_decrypted_by_reference(self, source):
        """参考实现按 §6.2 顺序解开主库 SM4-GCM 密文"""
        v = source()
        m = v["message"]
        session = ref.ReferenceSession(
            {
                "encryption_key": bytes.fromhex(m["encryption_key_hex"]),
                "auth_key": b"x" * 32,
                "replay_key": bytes.fromhex(m["replay_key_hex"]),
            },
            agent_id=m["recipient_id"],
            suite=SUITE_ZH,
        )
        assert session.decrypt(m["encrypted"]) == m["plaintext"]

    @pytest.mark.parametrize("source", VECTOR_SOURCES)
    def test_reference_encrypts_main_lib_decrypts(self, source):
        """反向：参考实现加密（同 nonce/计数器）→ 密文与主库逐字节一致"""
        v = source()
        m = v["message"]
        session = ref.ReferenceSession(
            _keys_from_hex(
                {
                    "encryption_key": m["encryption_key_hex"],
                    "replay_key": m["replay_key_hex"],
                }
            ),
            agent_id=m["sender_id"],
            suite=SUITE_ZH,
        )
        session.send_counter = m["message_counter"] - 1
        out = session.encrypt(m["plaintext"], m["recipient_id"], nonce=bytes.fromhex(m["nonce_hex"]))
        assert out["payload"] == m["encrypted"]["payload"]
        assert out["auth_tag"] == m["encrypted"]["auth_tag"]
        assert out["replay_tag"] == m["encrypted"]["replay_tag"]
        assert decrypt_message(bytes.fromhex(m["encryption_key_hex"]), out) == m["plaintext"]

    @pytest.mark.parametrize("source", VECTOR_SOURCES)
    def test_rekey_keys_rederived(self, source):
        """参考实现复算 ZH rekey：HMAC-SM3 签名验证 + SM2 DH + 独立派生新钥"""
        v = source()
        r = v["rekey"]
        old_keys = _keys_from_hex(r["old_keys"])

        _response, new_keys_resp = ref.handle_rekey_request(
            old_keys, r["request"], ephemeral_priv=bytes.fromhex(r["response_ephemeral_priv"]),
            nonce=bytes.fromhex(r["response_nonce_hex"]), suite=SUITE_ZH, **REPLAY,
        )
        assert new_keys_resp == _keys_from_hex(r["expected_new_keys"])

        initiator = ref.ReferenceRekey(old_keys, suite=SUITE_ZH)
        initiator._eph_priv = bytes.fromhex(r["request_ephemeral_priv"])
        initiator._nonce = bytes.fromhex(r["request_nonce_hex"])
        initiator.sequence = r["request"]["sequence"] + 1
        new_keys_init = initiator.process_response(r["response"], **REPLAY)
        assert new_keys_init == _keys_from_hex(r["expected_new_keys"])

    @pytest.mark.parametrize("source", VECTOR_SOURCES)
    def test_filetransfer_reference_unpacks_lib_artifact(self, source):
        """参考实现按 SPEC §9 解开主库 ZH 工件（SM4-GCM 头认证 + tag 链 + EOF）"""
        v = source()
        f = v["filetransfer"]
        plaintext, header = ref.unpack_artifact(
            bytes.fromhex(f["artifact_hex"]), bytes.fromhex(f["master_key_hex"]), SUITE_ZH
        )
        assert plaintext == bytes.fromhex(f["plaintext_hex"])
        assert header["total_chunks"] == 2

    @pytest.mark.parametrize("source", VECTOR_SOURCES)
    def test_filetransfer_lib_unpacks_reference_artifact(self, source, tmp_path):
        """反向：参考实现 ZH 打包 → 主库 unpack_file(suite=ZH) 解开"""
        from sip_protocol.filetransfer import unpack_file

        v = source()
        f = v["filetransfer"]
        master_key = bytes.fromhex(f["master_key_hex"])
        plaintext = bytes.fromhex(f["plaintext_hex"])
        artifact = ref.pack_artifact(
            plaintext,
            master_key,
            file_name="ref-packed-zh.bin",
            chunk_size=f["chunk_size"],
            file_id=bytes.fromhex("ffeeddccbbaa99887766554433221100"),
            suite=SUITE_ZH,
        )
        src = tmp_path / "ref-packed-zh.bin.sipft"
        src.write_bytes(artifact)
        result = unpack_file(str(src), master_key, output_path=str(tmp_path / "out"), suite=SUITE_ZH)
        assert result.chunks_verified == 2
        assert (tmp_path / "out").read_bytes() == plaintext


# ═════════════════ 2. 活体对话（实时互为对端） ═════════════════


class TestLiveInteropZH:
    def test_full_live_conversation(self):
        """主库 ZH initiator ↔ 参考实现 ZH responder：握手→双向消息"""
        hello, state = initiate_handshake(PSK, suite=SUITE_ZH)
        auth, ref_keys = ref.ReferenceSIP.responder_handle_hello(hello, PSK, suite=SUITE_ZH)
        lib_keys, _lib_session_state = complete_handshake(auth, state)

        assert lib_keys["encryption_key"] == ref_keys["encryption_key"]
        assert lib_keys["replay_key"] == ref_keys["replay_key"]

        ref_session = ref.ReferenceSession(ref_keys, agent_id="agent:ref", suite=SUITE_ZH)
        for i, text in enumerate(["hello ref zh", "第二轮国密 ✓", ""], start=1):
            enc = encrypt_message(
                lib_keys["encryption_key"], text, "agent:lib", "agent:ref", i,
                lib_keys["replay_key"], SUITE_ZH,
            )
            assert ref_session.decrypt(enc) == text

        for text in ["hi lib", "国密回声"]:
            ref_msg = ref_session.encrypt(text, "agent:lib")
            assert decrypt_message(lib_keys["encryption_key"], ref_msg) == text

    def test_reference_initiates_lib_responds(self):
        """参考实现 ZH 发起 → 主库 ZH 响应 → 双方密钥一致"""
        hello, ref_state = ref.ReferenceSIP.initiator_start(PSK, suite=SUITE_ZH)
        auth, _state_b, lib_keys = respond_handshake(hello, PSK, suite=SUITE_ZH)
        ref_keys = ref.ReferenceSIP.initiator_finish(auth, ref_state)
        assert ref_keys == lib_keys

    def test_live_rekey_reference_initiates(self):
        """参考实现发起 ZH rekey → 主库响应 → 双方新钥一致"""
        hello, state = initiate_handshake(PSK, suite=SUITE_ZH)
        auth, ref_keys = ref.ReferenceSIP.responder_handle_hello(hello, PSK, suite=SUITE_ZH)
        lib_keys, _sess = complete_handshake(auth, state)
        old_keys = {
            "encryption_key": lib_keys["encryption_key"],
            "auth_key": lib_keys["auth_key"],
            "replay_key": lib_keys["replay_key"],
        }

        ref_rekey = ref.ReferenceRekey(ref_keys, suite=SUITE_ZH)
        request = ref_rekey.create_request(reason="manual")

        lib_responder = RekeyManager(dict(old_keys, suite=SUITE_ZH), is_initiator=False)
        response = lib_responder.process_rekey_request(request)
        lib_new_keys = lib_responder.temp_new_keys

        ref_new_keys = ref_rekey.process_response(response)
        assert ref_new_keys["encryption_key"] == lib_new_keys["encryption_key"]
        assert len(ref_new_keys["encryption_key"]) == 16

    def test_live_rekey_lib_initiates(self):
        """主库发起 ZH rekey → 参考实现响应 → 双方新钥一致"""
        hello, state = initiate_handshake(PSK, suite=SUITE_ZH)
        auth, ref_keys = ref.ReferenceSIP.responder_handle_hello(hello, PSK, suite=SUITE_ZH)
        lib_keys, _sess = complete_handshake(auth, state)
        old_keys = {
            "encryption_key": lib_keys["encryption_key"],
            "auth_key": lib_keys["auth_key"],
            "replay_key": lib_keys["replay_key"],
        }

        lib_mgr = RekeyManager(dict(old_keys, suite=SUITE_ZH), is_initiator=True)
        request = lib_mgr.create_rekey_request(reason="scheduled")

        response, ref_new_keys = ref.handle_rekey_request(ref_keys, request, suite=SUITE_ZH)
        lib_new_keys = lib_mgr.process_rekey_response(response)
        assert lib_new_keys["encryption_key"] == ref_new_keys["encryption_key"]
        assert lib_new_keys["replay_key"] == ref_new_keys["replay_key"]

    def test_live_channel_envelope_interop(self):
        """EncryptedChannel（信封层）↔ 参考实现：ZH 完整 AgentMessage 往返"""
        channel = EncryptedChannel(agent_id="agent:lib", psk=PSK, suite=SUITE_ZH)

        hello_msg = channel.initiate()
        hello = hello_msg.payload["data"]
        assert hello["suite"] == "ZH"
        auth, ref_keys = ref.ReferenceSIP.responder_handle_hello(hello, PSK, suite=SUITE_ZH)

        auth_msg = AgentMessage(
            sender_id="agent:ref",
            recipient_id="agent:lib",
            payload={"action": "handshake_complete", "data": auth},
        )
        channel.complete_handshake(auth_msg)
        assert channel.is_established

        sent = channel.send("channel zh interop ✓", "agent:ref")
        ref_session = ref.ReferenceSession(ref_keys, agent_id="agent:ref", suite=SUITE_ZH)
        assert ref_session.decrypt(sent.payload) == "channel zh interop ✓"

        from sip_protocol.transport.message import MessageType

        ref_reply = ref_session.encrypt("ack zh", "agent:lib")
        reply_msg = AgentMessage(
            type=MessageType.ENCRYPTED,
            sender_id="agent:ref",
            recipient_id="agent:lib",
            payload=ref_reply,
        )
        assert channel.receive(reply_msg) == "ack zh"


# ═════════════════ 3. 负路径（双方都必须拒绝） ═════════════════


class TestNegativeInteropZH:
    def test_tampered_auth_signature_rejected_by_both(self):
        """Auth 签名翻转一字节：主库与参考实现都必须在 HMAC-SM3 处拒绝"""
        hello, state = initiate_handshake(PSK, suite=SUITE_ZH)
        auth, _ = ref.ReferenceSIP.responder_handle_hello(hello, PSK, suite=SUITE_ZH)

        sig = bytearray(base64.b64decode(auth["signature"]))
        sig[0] ^= 0xFF
        auth["signature"] = base64.b64encode(bytes(sig)).decode()

        from sip_protocol.crypto.dh import serialize_private_key

        ref_state = {
            "psk": PSK,
            "identity_priv": bytes.fromhex(serialize_private_key(state["identity_private_key"]).hex()),
            "ephemeral_priv": bytes.fromhex(serialize_private_key(state["ephemeral_private_key"]).hex()),
            "nonce": bytes.fromhex(hello["nonce"]),
            "suite": "ZH",
        }
        with pytest.raises(ValueError, match="HMAC"):
            ref.ReferenceSIP.initiator_finish(auth, ref_state, **REPLAY)
        with pytest.raises(ValueError, match="HMAC"):
            complete_handshake(auth, state)

    def test_tampered_ciphertext_rejected_by_reference(self):
        hello, state = initiate_handshake(PSK, suite=SUITE_ZH)
        auth, ref_keys = ref.ReferenceSIP.responder_handle_hello(hello, PSK, suite=SUITE_ZH)
        lib_keys, _sess = complete_handshake(auth, state)

        enc = encrypt_message(
            lib_keys["encryption_key"], "payload", "a", "b", 1, lib_keys["replay_key"], SUITE_ZH
        )
        raw = bytearray(base64.b64decode(enc["payload"]))
        raw[0] ^= 0xFF
        enc["payload"] = base64.b64encode(bytes(raw)).decode()

        session = ref.ReferenceSession(ref_keys, agent_id="b", suite=SUITE_ZH)
        with pytest.raises(Exception):
            session.decrypt(enc)

    def test_zh_initiator_vs_en_reference_rejected(self):
        """主库 ZH 发起 → 参考 EN 端点：协商失败（无降级）"""
        hello, _state = initiate_handshake(PSK, suite=SUITE_ZH)
        with pytest.raises(ValueError, match="套件协商失败"):
            ref.ReferenceSIP.responder_handle_hello(hello, PSK)

    def test_en_initiator_vs_zh_reference_rejected(self):
        """主库 EN 发起（无字段）→ 参考 ZH 端点：协商失败（旧 peer 兼容语义）"""
        hello, _state = initiate_handshake(PSK)
        with pytest.raises(ValueError, match="套件协商失败"):
            ref.ReferenceSIP.responder_handle_hello(hello, PSK, suite=SUITE_ZH)

    def test_unknown_suite_rejected_by_reference(self):
        hello, _state = initiate_handshake(PSK, suite=SUITE_ZH)
        hello["suite"] = "XX"
        with pytest.raises(ValueError, match="未知的密码套件"):
            ref.ReferenceSIP.responder_handle_hello(hello, PSK, suite=SUITE_ZH)

    def test_stripped_suite_field_rejected_by_reference(self):
        """降级场景：剥离 suite 字段的 ZH hello → 参考 EN 端在公钥解析处拒绝"""
        hello, _state = initiate_handshake(PSK, suite=SUITE_ZH)
        stripped = {k: v for k, v in hello.items() if k != "suite"}
        with pytest.raises((ValueError, SuiteNegotiationError)):
            ref.ReferenceSIP.responder_handle_hello(stripped, PSK)

    def test_zh_and_en_vectors_are_independent(self):
        """ZH 向量密钥与 EN 向量密钥无交集（SM3 ≠ SHA256 派生域隔离）"""
        zh = json.loads(VECTOR_FILE.read_text())
        en = json.loads((VECTOR_FILE.parent / "sip_test_vectors.json").read_text())
        assert zh["suite"] == "ZH"
        assert zh["handshake"]["expected_keys"]["auth_key"] != (
            en["handshake"]["expected_keys"]["auth_key"]
        )
        assert len(bytes.fromhex(zh["handshake"]["expected_keys"]["encryption_key"])) == 16
