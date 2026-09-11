"""SIP 互操作测试 —— 主库 ↔ 参考实现（SPEC §14 验证链）

参考实现 scripts/interop/reference_impl.py 仅依 docs/SPEC.md 实现（不 import 主库），
本文件做三类双向断言：

1. 向量回放：消费主库导出的测试向量（tests/vectors/sip_test_vectors.json 静态文件
   + CI 每次运行即时重建的 fresh 向量），参考实现独立复算握手/消息/rekey/工件
2. 活体对话：主库与参考实现实时互为对端，完整走 握手→消息→rekey 闭环
3. 负路径：篡改签名/密文/replay_tag/版本，双方都必须拒绝
"""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts" / "interop"))

import reference_impl as ref  # noqa: E402

from sip_protocol.protocol.handshake import (  # noqa: E402
    complete_handshake,
    initiate_handshake,
    respond_handshake,
)
from sip_protocol.protocol.message import decrypt_message  # noqa: E402
from sip_protocol.protocol.rekey import RekeyManager  # noqa: E402
from sip_protocol.transport.encrypted_channel import EncryptedChannel  # noqa: E402
from sip_protocol.transport.message import AgentMessage  # noqa: E402

PSK = b"interop-vector-psk-2026"
VECTOR_FILE = Path(__file__).resolve().parents[1] / "tests" / "vectors" / "sip_test_vectors.json"

# 回放历史 transcript：跳过时间戳新鲜度（HMAC/签名仍全程验证）——见 reference_impl
REPLAY = {"check_timestamp": False}


def _fresh_vectors() -> dict:
    """CI 通路：即时重建向量（生成→参考实现消费→双向断言）"""
    from generate_vectors import build_vectors

    return build_vectors()


VECTOR_SOURCES = [
    pytest.param(lambda: json.loads(VECTOR_FILE.read_text()), id="committed"),
    pytest.param(_fresh_vectors, id="fresh-ci"),
]


def _keys_from_hex(d: dict) -> dict[str, bytes]:
    return {k: bytes.fromhex(v) for k, v in d.items()}


# ═════════════════ 1. 向量回放 ═════════════════


class TestVectorReplay:
    @pytest.mark.parametrize("source", VECTOR_SOURCES)
    def test_handshake_keys_rederived_initiator_side(self, source):
        """参考实现扮演 initiator：私钥+Auth 消息 → 独立派生密钥 == 主库导出值"""
        v = source()
        hs = v["handshake"]
        state = {
            "psk": bytes.fromhex(v["psk_hex"]),
            "identity_priv": bytes.fromhex(hs["initiator_identity_priv"]),
            "ephemeral_priv": bytes.fromhex(hs["initiator_ephemeral_priv"]),
            "nonce": bytes.fromhex(hs["hello"]["nonce"]),
        }
        keys = ref.ReferenceSIP.initiator_finish(hs["auth"], state, **REPLAY)
        assert keys == _keys_from_hex(hs["expected_keys"])

    @pytest.mark.parametrize("source", VECTOR_SOURCES)
    def test_handshake_keys_rederived_responder_side(self, source):
        """参考实现扮演 responder：私钥+Hello → 独立派生同一组密钥"""
        v = source()
        hs = v["handshake"]
        _auth, keys = ref.ReferenceSIP.responder_handle_hello(
            hs["hello"],
            bytes.fromhex(v["psk_hex"]),
            identity_priv=bytes.fromhex(hs["responder_identity_priv"]),
            ephemeral_priv=bytes.fromhex(hs["responder_ephemeral_priv"]),
            nonce=bytes.fromhex(hs["auth"]["auth_data"]["nonce"]),
            **REPLAY,
        )
        assert keys == _keys_from_hex(hs["expected_keys"])

    @pytest.mark.parametrize("source", VECTOR_SOURCES)
    def test_auth_hmac_verified_byte_exact(self, source):
        """Auth 签名 transcript 逐字节验证（SPEC §4.4 json.dumps 分隔符复刻）"""
        v = source()
        hs = v["handshake"]
        keys = _keys_from_hex(hs["expected_keys"])
        transcript = ref.ReferenceSIP.auth_transcript(
            hs["auth"]["auth_data"]["ephemeral_pub"],
            hs["auth"]["auth_data"]["nonce"],
            hs["auth"]["timestamp"],
        )
        # 与 Python json.dumps 默认输出逐字节一致（规范 §4.4 的可移植性要求）
        import hmac as hmac_mod

        expected = hmac_mod.new(keys["auth_key"], transcript, "sha256").digest()
        import base64 as b64

        assert b64.b64encode(expected).decode() == hs["auth"]["signature"]

    @pytest.mark.parametrize("source", VECTOR_SOURCES)
    def test_message_decrypted_by_reference(self, source):
        """参考实现按 §6.2 顺序（replay_tag→计数器→AEAD）解开主库密文"""
        v = source()
        m = v["message"]
        session = ref.ReferenceSession(
            {
                "encryption_key": bytes.fromhex(m["encryption_key_hex"]),
                "auth_key": b"x" * 32,
                "replay_key": bytes.fromhex(m["replay_key_hex"]),
            },
            agent_id=m["recipient_id"],
        )
        assert session.decrypt(m["encrypted"]) == m["plaintext"]

    @pytest.mark.parametrize("source", VECTOR_SOURCES)
    def test_reference_encrypts_main_lib_decrypts(self, source):
        """反向：参考实现加密（同 nonce/计数器）→ 密文与主库逐字节一致，主库可解"""
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
        )
        session.send_counter = m["message_counter"] - 1
        out = session.encrypt(m["plaintext"], m["recipient_id"], nonce=bytes.fromhex(m["nonce_hex"]))
        # 密码学字段逐字节一致（timestamp 除外）
        assert out["iv"] == m["encrypted"]["iv"]
        assert out["payload"] == m["encrypted"]["payload"]
        assert out["auth_tag"] == m["encrypted"]["auth_tag"]
        assert out["replay_tag"] == m["encrypted"]["replay_tag"]
        # 主库解参考实现的密文
        assert decrypt_message(bytes.fromhex(m["encryption_key_hex"]), out) == m["plaintext"]

    @pytest.mark.parametrize("source", VECTOR_SOURCES)
    def test_rekey_keys_rederived(self, source):
        """参考实现复算 rekey：验证签名 + 独立派生新钥 == 主库导出值"""
        v = source()
        r = v["rekey"]
        old_keys = _keys_from_hex(r["old_keys"])

        # 响应方视角：验证请求签名 → DH → 派生
        _response, new_keys_resp = ref.handle_rekey_request(
            old_keys, r["request"], ephemeral_priv=bytes.fromhex(r["response_ephemeral_priv"]),
            nonce=bytes.fromhex(r["response_nonce_hex"]), **REPLAY,
        )
        assert new_keys_resp == _keys_from_hex(r["expected_new_keys"])

        # 发起方视角：消费响应 → 同一组新钥
        initiator = ref.ReferenceRekey(old_keys)
        initiator._eph_priv = bytes.fromhex(r["request_ephemeral_priv"])
        initiator._nonce = bytes.fromhex(r["request_nonce_hex"])
        initiator.sequence = r["request"]["sequence"] + 1
        new_keys_init = initiator.process_response(r["response"], **REPLAY)
        assert new_keys_init == _keys_from_hex(r["expected_new_keys"])

    @pytest.mark.parametrize("source", VECTOR_SOURCES)
    def test_filetransfer_reference_unpacks_lib_artifact(self, source):
        """参考实现按 SPEC §9 解开主库 SIPFT 工件（头认证+tag 链+EOF 全过）"""
        v = source()
        f = v["filetransfer"]
        plaintext, header = ref.unpack_artifact(
            bytes.fromhex(f["artifact_hex"]), bytes.fromhex(f["master_key_hex"])
        )
        assert plaintext == bytes.fromhex(f["plaintext_hex"])
        assert header["file_name"] == f["file_name"]
        assert header["total_chunks"] == 2  # 1536B / 1024B 块

    @pytest.mark.parametrize("source", VECTOR_SOURCES)
    def test_filetransfer_lib_unpacks_reference_artifact(self, source, tmp_path):
        """反向：参考实现打包 → 主库 unpack_file 解开"""
        from sip_protocol.filetransfer import unpack_file

        v = source()
        f = v["filetransfer"]
        master_key = bytes.fromhex(f["master_key_hex"])
        plaintext = bytes.fromhex(f["plaintext_hex"])
        artifact = ref.pack_artifact(
            plaintext,
            master_key,
            file_name="ref-packed.bin",
            chunk_size=f["chunk_size"],
            file_id=bytes.fromhex("ffeeddccbbaa99887766554433221100"),
        )
        src = tmp_path / "ref-packed.bin.sipft"
        src.write_bytes(artifact)
        result = unpack_file(str(src), master_key, output_path=str(tmp_path / "out"))
        assert result.chunks_verified == 2
        assert (tmp_path / "out").read_bytes() == plaintext


# ═════════════════ 2. 活体对话（实时互为对端） ═════════════════


class TestLiveInterop:
    def test_full_live_conversation(self):
        """主库 initiator ↔ 参考实现 responder：握手→双向消息→多轮"""
        hello, state = initiate_handshake(PSK)
        auth, ref_keys = ref.ReferenceSIP.responder_handle_hello(hello, PSK)
        lib_keys, _lib_session_state = complete_handshake(auth, state)

        # 双方独立派生的密钥一致（活体，非向量）
        assert lib_keys["encryption_key"] == ref_keys["encryption_key"]
        assert lib_keys["replay_key"] == ref_keys["replay_key"]

        lib_session_keys = {
            "encryption_key": lib_keys["encryption_key"],
            "auth_key": lib_keys["auth_key"],
            "replay_key": lib_keys["replay_key"],
        }
        ref_session = ref.ReferenceSession(ref_keys, agent_id="agent:ref")

        # 主库 → 参考
        from sip_protocol.protocol.message import encrypt_message

        for i, text in enumerate(["hello ref", "第二轮 ✓", ""], start=1):
            enc = encrypt_message(
                lib_keys["encryption_key"], text, "agent:lib", "agent:ref", i, lib_keys["replay_key"]
            )
            assert ref_session.decrypt(enc) == text

        # 参考 → 主库（参考实现的消息计数器独立递增）
        for text in ["hi lib", "回声"]:
            ref_msg = ref_session.encrypt(text, "agent:lib")
            assert decrypt_message(lib_keys["encryption_key"], ref_msg) == text

        # lib_session_keys 参与后续 rekey 测试的语义在此闭合
        assert set(lib_session_keys) == {"encryption_key", "auth_key", "replay_key"}

    def test_live_rekey_reference_initiates(self):
        """参考实现发起 rekey → 主库响应 → 双方新钥一致且旧钥消息被拒"""
        hello, state = initiate_handshake(PSK)
        auth, ref_keys = ref.ReferenceSIP.responder_handle_hello(hello, PSK)
        lib_keys, _lib_session_state = complete_handshake(auth, state)
        old_keys = {
            "encryption_key": lib_keys["encryption_key"],
            "auth_key": lib_keys["auth_key"],
            "replay_key": lib_keys["replay_key"],
        }

        ref_rekey = ref.ReferenceRekey(ref_keys)
        request = ref_rekey.create_request(reason="manual")

        lib_responder = RekeyManager(dict(old_keys), is_initiator=False)
        response = lib_responder.process_rekey_request(request)
        lib_new_keys = lib_responder.temp_new_keys
        lib_responder.apply_new_keys(lib_new_keys)

        ref_new_keys = ref_rekey.process_response(response)
        assert ref_new_keys["encryption_key"] == lib_new_keys["encryption_key"]

        # 新钥下双向消息
        from sip_protocol.protocol.message import encrypt_message

        enc = encrypt_message(
            lib_new_keys["encryption_key"], "after rekey", "agent:lib", "agent:ref", 1,
            lib_new_keys["replay_key"],
        )
        ref_after = ref.ReferenceSession(ref_new_keys, agent_id="agent:ref")
        assert ref_after.decrypt(enc) == "after rekey"

        # 旧钥密文必须被参考实现拒绝（AEAD 认证失败）
        stale = encrypt_message(
            old_keys["encryption_key"], "stale", "agent:lib", "agent:ref", 2,
            old_keys["replay_key"],
        )
        with pytest.raises(ValueError):
            ref_after.decrypt(stale)

    def test_live_rekey_lib_initiates(self):
        """主库发起 rekey → 参考实现响应 → 双方新钥一致"""
        hello, state = initiate_handshake(PSK)
        auth, ref_keys = ref.ReferenceSIP.responder_handle_hello(hello, PSK)
        lib_keys, _lib_session_state = complete_handshake(auth, state)
        old_keys = {
            "encryption_key": lib_keys["encryption_key"],
            "auth_key": lib_keys["auth_key"],
            "replay_key": lib_keys["replay_key"],
        }

        lib_mgr = RekeyManager(dict(old_keys), is_initiator=True)
        request = lib_mgr.create_rekey_request(reason="scheduled")

        response, ref_new_keys = ref.handle_rekey_request(ref_keys, request)

        lib_new_keys = lib_mgr.process_rekey_response(response)
        assert lib_new_keys["encryption_key"] == ref_new_keys["encryption_key"]
        assert lib_new_keys["replay_key"] == ref_new_keys["replay_key"]

    def test_live_channel_envelope_interop(self):
        """EncryptedChannel（信封层）↔ 参考实现：完整 AgentMessage 往返"""
        channel = EncryptedChannel(agent_id="agent:lib", psk=PSK)

        hello_msg = channel.initiate()  # AgentMessage(control, handshake_init)
        hello = hello_msg.payload["data"]
        auth, ref_keys = ref.ReferenceSIP.responder_handle_hello(hello, PSK)

        auth_msg = AgentMessage(
            sender_id="agent:ref",
            recipient_id="agent:lib",
            payload={"action": "handshake_complete", "data": auth},
        )
        channel.complete_handshake(auth_msg)
        assert channel.is_established

        # 主库通道 → 参考会话（信封 JSON → payload 字典）
        sent = channel.send("channel interop ✓", "agent:ref")
        ref_session = ref.ReferenceSession(ref_keys, agent_id="agent:ref")
        assert ref_session.decrypt(sent.payload) == "channel interop ✓"

        # 参考会话 → 主库通道（构造 ENCRYPTED 信封）
        from sip_protocol.transport.message import MessageType

        ref_reply = ref_session.encrypt("ack from ref", "agent:lib")
        reply_msg = AgentMessage(
            type=MessageType.ENCRYPTED,
            sender_id="agent:ref",
            recipient_id="agent:lib",
            payload=ref_reply,
        )
        assert channel.receive(reply_msg) == "ack from ref"


# ═════════════════ 3. 负路径（双方都必须拒绝） ═════════════════


class TestNegativeInterop:
    def test_tampered_auth_signature_rejected_by_both(self):
        """Auth 签名翻转一字节：主库与参考实现都必须在 HMAC 处拒绝"""
        hello, state = initiate_handshake(PSK)
        auth, _ = ref.ReferenceSIP.responder_handle_hello(hello, PSK)

        import base64 as b64

        sig = bytearray(b64.b64decode(auth["signature"]))
        sig[0] ^= 0xFF
        auth["signature"] = b64.b64encode(bytes(sig)).decode()

        # 参考实现侧：注入真实 initiator 私钥（从主库 state 序列化），走到 HMAC 检查
        from cryptography.hazmat.primitives import serialization

        def _raw(priv):
            return priv.private_bytes(
                serialization.Encoding.Raw,
                serialization.PrivateFormat.Raw,
                serialization.NoEncryption(),
            )

        ref_state = {
            "psk": PSK,
            "identity_priv": _raw(state["identity_private_key"]),
            "ephemeral_priv": _raw(state["ephemeral_private_key"]),
            "nonce": bytes.fromhex(hello["nonce"]),
        }
        with pytest.raises(ValueError, match="HMAC"):
            ref.ReferenceSIP.initiator_finish(auth, ref_state, **REPLAY)
        with pytest.raises(ValueError, match="HMAC"):
            complete_handshake(auth, state)

    def test_tampered_ciphertext_rejected_by_reference(self):
        hello, state = initiate_handshake(PSK)
        auth, ref_keys = ref.ReferenceSIP.responder_handle_hello(hello, PSK)
        lib_keys, _lib_session_state = complete_handshake(auth, state)

        from sip_protocol.protocol.message import encrypt_message

        enc = encrypt_message(
            lib_keys["encryption_key"], "payload", "a", "b", 1, lib_keys["replay_key"]
        )
        import base64 as b64

        raw = bytearray(b64.b64decode(enc["payload"]))
        raw[0] ^= 0xFF
        enc["payload"] = b64.b64encode(bytes(raw)).decode()

        session = ref.ReferenceSession(ref_keys, agent_id="b")
        with pytest.raises(Exception):
            session.decrypt(enc)

    def test_tampered_replay_tag_rejected_by_reference(self):
        hello, state = initiate_handshake(PSK)
        auth, ref_keys = ref.ReferenceSIP.responder_handle_hello(hello, PSK)
        lib_keys, _lib_session_state = complete_handshake(auth, state)

        from sip_protocol.protocol.message import encrypt_message

        enc = encrypt_message(
            lib_keys["encryption_key"], "msg", "a", "b", 1, lib_keys["replay_key"]
        )
        enc["replay_tag"] = "0" * 64
        session = ref.ReferenceSession(ref_keys, agent_id="b")
        with pytest.raises(ValueError, match="replay_tag"):
            session.decrypt(enc)

    def test_counter_replay_rejected_by_reference(self):
        """同计数器重放：即便 replay_tag 被同步伪造，计数器单调性仍拦截"""
        hello, state = initiate_handshake(PSK)
        auth, ref_keys = ref.ReferenceSIP.responder_handle_hello(hello, PSK)
        lib_keys, _lib_session_state = complete_handshake(auth, state)

        from sip_protocol.protocol.message import encrypt_message

        enc = encrypt_message(
            lib_keys["encryption_key"], "once", "a", "b", 1, lib_keys["replay_key"]
        )
        session = ref.ReferenceSession(ref_keys, agent_id="b")
        assert session.decrypt(enc) == "once"
        with pytest.raises(ValueError, match="计数器"):
            session.decrypt(enc)

    def test_wrong_version_rejected_by_reference(self):
        hello, _ = initiate_handshake(PSK)
        hello["version"] = "SIP-2.0"
        with pytest.raises(ValueError, match="版本"):
            ref.ReferenceSIP.responder_handle_hello(hello, PSK)

    def test_filetransfer_tamper_rejected_by_reference(self):
        v = json.loads(VECTOR_FILE.read_text())
        f = v["filetransfer"]
        artifact = bytearray(bytes.fromhex(f["artifact_hex"]))
        # 篡改第一块密文区域（头部之后约 12+230+16+12 偏移处）
        artifact[len(artifact) // 2] ^= 0xFF
        with pytest.raises(ValueError):
            ref.unpack_artifact(bytes(artifact), bytes.fromhex(f["master_key_hex"]))
