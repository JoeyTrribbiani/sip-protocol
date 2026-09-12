"""国密套件（ZH）协议级测试 —— 握手协商/消息/Rekey/通道/文件工件/MCP

红线守护：EN wire 逐位不变（default 调用无 suite 字段）+ 既有向量不动；
ZH 全链路（握手→会话→rekey→文件）+ 协商负路径（不匹配/未知值/字段剥离）。
"""

import json
import base64

import pytest

from sip_protocol.crypto.suite import SUITE_EN, SUITE_ZH
from sip_protocol.exceptions import (
    ArtifactCorruptedError,
    SuiteNegotiationError,
)
from sip_protocol.filetransfer import pack_file, unpack_file
from sip_protocol.managers.session import SessionState
from sip_protocol.protocol.handshake import (
    initiate_handshake,
    respond_handshake,
    complete_handshake,
)
from sip_protocol.protocol.message import (
    decrypt_message,
    encrypt_message,
    generate_replay_tag,
    verify_replay_tag,
)
from sip_protocol.protocol.rekey import RekeyManager
from sip_protocol.transport.encrypted_channel import EncryptedChannel
from sip_protocol.transport.message import AgentMessage

PSK = b"zh-suite-test-psk"


def _zh_handshake():
    """完成一次 ZH 握手，返回 (hello, state_a, auth, keys_a, keys_b)"""
    hello, state_a = initiate_handshake(PSK, suite=SUITE_ZH)
    auth, _state_b, keys_b = respond_handshake(hello, PSK, suite=SUITE_ZH)
    keys_a, _session = complete_handshake(auth, state_a)
    assert keys_a["encryption_key"] == keys_b["encryption_key"]
    return hello, state_a, auth, keys_a, keys_b


class TestZHHandshake:
    """ZH 握手全流程与 wire 形态"""

    def test_full_handshake_both_sides_agree(self):
        _hello, _state, _auth, keys_a, keys_b = _zh_handshake()
        assert keys_a == keys_b
        assert len(keys_a["encryption_key"]) == 16
        assert len(keys_a["auth_key"]) == 32
        assert len(keys_a["replay_key"]) == 32

    def test_wire_fields(self):
        hello, _state, auth, _ka, _kb = _zh_handshake()
        assert hello["suite"] == "ZH"
        assert len(bytes.fromhex(hello["identity_pub"])) == 65  # SM2 非压缩点
        assert len(bytes.fromhex(hello["ephemeral_pub"])) == 65
        assert hello["version"] == "SIP-1.0"  # 线协议版本不变（§11.3 演进规则）
        assert auth["suite"] == "ZH"
        assert len(bytes.fromhex(auth["identity_pub"])) == 65

    def test_timestamp_still_enforced(self):
        hello, _state = initiate_handshake(PSK, suite=SUITE_ZH)
        hello["timestamp"] -= 10 * 60 * 1000
        with pytest.raises(ValueError, match="时间戳"):
            respond_handshake(hello, PSK, suite=SUITE_ZH)


class TestENWireUnchanged:
    """红线回归：EN 缺省调用的 wire 与序列化不携带 suite（逐位不变）"""

    def test_en_handshake_dicts_have_no_suite_field(self):
        hello, state_a = initiate_handshake(PSK)
        assert "suite" not in hello
        auth, _s, keys = respond_handshake(hello, PSK)
        assert "suite" not in auth
        keys_a, session = complete_handshake(auth, state_a)
        assert keys_a["encryption_key"] == keys["encryption_key"]
        assert "suite" not in session["handshake_complete"]

    def test_en_message_dict_has_no_suite_field(self):
        hello, state_a = initiate_handshake(PSK)
        auth, _sb, keys_b = respond_handshake(hello, PSK)
        _ka, _sess = complete_handshake(auth, state_a)
        msg = encrypt_message(
            keys_b["encryption_key"], "en", "a", "b", 1, keys_b["replay_key"]
        )
        assert "suite" not in msg

    def test_en_session_serialization_has_no_suite_field(self):
        state = SessionState()
        raw = json.loads(base64.b64decode(state.serialize()))
        assert "suite" not in raw
        assert SessionState.deserialize(state.serialize()).suite == "EN"


class TestSuiteNegotiation:
    """协商语义（SPEC §4.5）：单选、无降级、缺字段=EN"""

    def test_zh_initiator_vs_en_responder_rejected(self):
        hello, _state = initiate_handshake(PSK, suite=SUITE_ZH)
        with pytest.raises(SuiteNegotiationError) as exc:
            respond_handshake(hello, PSK)
        assert "ZH" in str(exc.value) and "EN" in str(exc.value)
        assert exc.value.code == "SIP-PROTO-005"

    def test_en_initiator_vs_zh_responder_rejected(self):
        """旧 peer（无 suite 字段=EN）对话 ZH 端点：明确协商失败"""
        hello, _state = initiate_handshake(PSK)  # EN，无字段
        with pytest.raises(SuiteNegotiationError):
            respond_handshake(hello, PSK, suite=SUITE_ZH)

    def test_unknown_suite_value_rejected(self):
        hello, _state = initiate_handshake(PSK, suite=SUITE_ZH)
        hello["suite"] = "XX"
        with pytest.raises(SuiteNegotiationError, match="未知"):
            respond_handshake(hello, PSK, suite=SUITE_ZH)

    def test_stripped_suite_field_rejected_with_clear_error(self):
        """降级攻击面：剥离 ZH hello 的 suite 字段 → EN 端在公钥长度处明确拒绝"""
        hello, _state = initiate_handshake(PSK, suite=SUITE_ZH)
        stripped = {k: v for k, v in hello.items() if k != "suite"}
        with pytest.raises(SuiteNegotiationError, match="公钥长度"):
            respond_handshake(stripped, PSK)

    def test_auth_missing_suite_rejected_by_zh_initiator(self):
        hello, state_a = initiate_handshake(PSK, suite=SUITE_ZH)
        auth, _sb, _kb = respond_handshake(hello, PSK, suite=SUITE_ZH)
        del auth["suite"]
        with pytest.raises(SuiteNegotiationError):
            complete_handshake(auth, state_a)

    def test_en_peer_enjoy_backward_compat(self):
        """缺省双端 EN：完全不经协商路径（等价于历史行为）"""
        hello, state_a = initiate_handshake(PSK)
        auth, _sb, keys_b = respond_handshake(hello, PSK)
        keys_a, _sess = complete_handshake(auth, state_a)
        assert keys_a["auth_key"] == keys_b["auth_key"]


class TestZHMessaging:
    """ZH 会话消息 + 防重放（SPEC §6）"""

    def test_roundtrip_and_replay_tag(self):
        _h, _s, _a, keys_a, keys_b = _zh_handshake()
        msg = encrypt_message(
            keys_a["encryption_key"], "你好，国密", "a", "b", 1, keys_a["replay_key"], SUITE_ZH
        )
        assert msg["suite"] == "ZH"
        assert decrypt_message(keys_b["encryption_key"], msg) == "你好，国密"
        assert verify_replay_tag(keys_b["replay_key"], "a", 1, msg["replay_tag"], SUITE_ZH)
        assert not verify_replay_tag(keys_b["replay_key"], "a", 2, msg["replay_tag"], SUITE_ZH)

    def test_replay_tag_digest_is_sm3(self):
        """ZH replay_tag 必须是 HMAC-SM3（16 进制 64 字符，与 EN 标签不同值）"""
        from sip_protocol.crypto.sm3 import hmac_sm3

        tag = generate_replay_tag(b"rk" * 16, "a", 1, SUITE_ZH)
        assert tag == hmac_sm3(b"rk" * 16, b"a:1").hex()
        assert tag != generate_replay_tag(b"rk" * 16, "a", 1)  # EN（SHA256）值不同

    def test_tampered_ciphertext_rejected(self):
        _h, _s, _a, keys_a, keys_b = _zh_handshake()
        msg = encrypt_message(
            keys_a["encryption_key"], "m", "a", "b", 1, keys_a["replay_key"], SUITE_ZH
        )
        raw = bytearray(base64.b64decode(msg["payload"]))
        raw[0] ^= 0xFF
        msg["payload"] = base64.b64encode(bytes(raw)).decode()
        with pytest.raises(ValueError, match="解密失败"):
            decrypt_message(keys_b["encryption_key"], msg)

    def test_unknown_suite_in_message_rejected(self):
        _h, _s, _a, keys_a, _kb = _zh_handshake()
        msg = encrypt_message(
            keys_a["encryption_key"], "m", "a", "b", 1, None, SUITE_ZH
        )
        msg["suite"] = "XX"
        with pytest.raises(ValueError, match="未知的密码套件"):
            decrypt_message(keys_a["encryption_key"], msg)

    def test_counter_replay_rejected(self):
        """同计数器重放：即使 replay_tag 一致，单调计数器仍拦截（通道级语义）"""
        ch_a = EncryptedChannel("agent:a", PSK, suite=SUITE_ZH)
        ch_b = EncryptedChannel("agent:b", PSK, suite=SUITE_ZH)
        hello_msg = ch_a.initiate()
        auth_msg = ch_b.respond_to_handshake(hello_msg)
        ch_a.complete_handshake(auth_msg)
        sent = ch_a.send("once", "agent:b")
        assert ch_b.receive(AgentMessage.from_json(sent.to_json())) == "once"
        with pytest.raises(ValueError, match="计数器"):
            ch_b.receive(AgentMessage.from_json(sent.to_json()))


class TestZHRekey:
    """ZH Rekey 全流程（SPEC §7）"""

    def test_full_rekey_flow(self):
        _h, _s, _a, keys_a, keys_b = _zh_handshake()
        old = dict(keys_a)
        mgr_a = RekeyManager(dict(old, suite=SUITE_ZH), is_initiator=True)
        request = mgr_a.create_rekey_request(reason="scheduled")

        mgr_b = RekeyManager(dict(keys_b, suite=SUITE_ZH), is_initiator=False)
        response = mgr_b.process_rekey_request(request)
        new_b = mgr_b.temp_new_keys
        mgr_b.apply_new_keys(new_b)

        new_a = mgr_a.process_rekey_response(response)
        mgr_a.apply_new_keys(new_a)
        assert new_a["encryption_key"] == new_b["encryption_key"]
        assert len(new_a["encryption_key"]) == 16
        assert new_a["auth_key"] != old["auth_key"]

    def test_rekey_ephemeral_pub_is_65_bytes(self):
        _h, _s, _a, keys_a, _kb = _zh_handshake()
        mgr = RekeyManager(dict(keys_a, suite=SUITE_ZH), is_initiator=True)
        request = mgr.create_rekey_request()
        assert len(base64.b64decode(request["request"]["ephemeral_pub"])) == 65

    def test_tampered_rekey_signature_rejected(self):
        _h, _s, _a, keys_a, keys_b = _zh_handshake()
        mgr_a = RekeyManager(dict(keys_a, suite=SUITE_ZH), is_initiator=True)
        request = mgr_a.create_rekey_request()
        request["signature"] = base64.b64encode(bytes(32)).decode()
        mgr_b = RekeyManager(dict(keys_b, suite=SUITE_ZH), is_initiator=False)
        with pytest.raises(ValueError, match="Invalid rekey request"):
            mgr_b.process_rekey_request(request)

    def test_cross_suite_rekey_rejected(self):
        """ZH rekey 请求打到 EN 会话上：签名验证失败（fail-closed）"""
        _h, _s, _a, keys_a, _kb = _zh_handshake()
        mgr_zh = RekeyManager(dict(keys_a, suite=SUITE_ZH), is_initiator=True)
        request = mgr_zh.create_rekey_request()
        en_state = {
            "encryption_key": b"e" * 32,
            "auth_key": b"a" * 32,
            "replay_key": b"r" * 32,
        }
        mgr_en = RekeyManager(en_state, is_initiator=False)
        with pytest.raises(ValueError, match="Invalid rekey request"):
            mgr_en.process_rekey_request(request)


class TestZHChannel:
    """ZH 通道端到端：握手→双向消息→rekey→会话序列化"""

    def _channel_pair(self):
        ch_a = EncryptedChannel("agent:a", PSK, suite=SUITE_ZH)
        ch_b = EncryptedChannel("agent:b", PSK, suite=SUITE_ZH)
        hello_msg = ch_a.initiate()
        auth_msg = ch_b.respond_to_handshake(AgentMessage.from_json(hello_msg.to_json()))
        ch_a.complete_handshake(AgentMessage.from_json(auth_msg.to_json()))
        assert ch_a.is_established and ch_b.is_established
        return ch_a, ch_b

    def test_bidirectional_messaging(self):
        ch_a, ch_b = self._channel_pair()
        sent = ch_a.send("国密通道消息", "agent:b")
        assert ch_b.receive(AgentMessage.from_json(sent.to_json())) == "国密通道消息"
        back = ch_b.send("回复", "agent:a")
        assert ch_a.receive(AgentMessage.from_json(back.to_json())) == "回复"

    def test_replay_rejected_at_channel(self):
        ch_a, ch_b = self._channel_pair()
        sent = ch_a.send("once", "agent:b")
        wire = AgentMessage.from_json(sent.to_json())
        assert ch_b.receive(wire) == "once"
        with pytest.raises(ValueError, match="计数器"):
            ch_b.receive(AgentMessage.from_json(sent.to_json()))

    def test_channel_rekey_e2e(self):
        ch_a, ch_b = self._channel_pair()
        old_key = ch_a.session_keys["encryption_key"]
        request = ch_a._initiate_rekey()
        response = ch_b.handle_rekey_request(request)
        ch_a.process_rekey_response(response)
        assert ch_a.session_keys["encryption_key"] != old_key
        sent = ch_a.send("after rekey", "agent:b")
        assert ch_b.receive(AgentMessage.from_json(sent.to_json())) == "after rekey"

    def test_session_state_carries_suite(self):
        ch_a, ch_b = self._channel_pair()
        assert ch_a._session_state.suite == "ZH"
        restored = SessionState.deserialize(ch_a._session_state.serialize())
        assert restored.suite == "ZH"

    def test_mismatched_channels_fail(self):
        ch_a = EncryptedChannel("agent:a", PSK, suite=SUITE_ZH)
        ch_b = EncryptedChannel("agent:b", PSK)  # EN
        hello_msg = ch_a.initiate()
        with pytest.raises(SuiteNegotiationError):
            ch_b.respond_to_handshake(hello_msg)

    def test_invalid_suite_rejected_at_construction(self):
        with pytest.raises(ValueError, match="未知的密码套件"):
            EncryptedChannel("agent:a", PSK, suite="XX")


class TestZHMCP:
    """ZH 模式 MCP Server：工具流程可用且响应结构与 EN 完全一致（冻结基线）"""

    def test_full_tool_flow_structure_frozen(self):
        import io

        from sip_protocol.transport.sip_mcp_server import SipMcpServer

        server = SipMcpServer(psk=PSK, agent_id="zh-mcp", suite=SUITE_ZH)
        init_resp = server.handle_request(
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
        )
        assert '"serverInfo"' in init_resp

        hello_resp = server.handle_request(
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": "sip_handshake", "arguments": {"role": "initiator"}},
            }
        )
        payload = json.loads(hello_resp)
        text = json.loads(payload["result"]["content"][0]["text"])
        assert set(text.keys()) == {"success", "role", "state", "hello_message", "instruction"}
        assert text["success"] is True

        # ZH 对端（参考通道）回应 → complete 走通
        hello_b64 = text["hello_message"]
        hello_json = base64.b64decode(hello_b64).decode()
        envelope = json.loads(hello_json)
        hello_dict = envelope["payload"]["data"]
        assert hello_dict["suite"] == "ZH"

        responder = SipMcpServer(psk=PSK, agent_id="peer", suite=SUITE_ZH)
        responder.handle_request(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {},
            }
        )
        auth_resp = responder.handle_request(
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "sip_handshake",
                    "arguments": {"role": "responder", "message": hello_b64},
                },
            }
        )
        auth_payload = json.loads(auth_resp)
        auth_text = json.loads(auth_payload["result"]["content"][0]["text"])
        assert set(auth_text.keys()) == {
            "success", "role", "state", "auth_message", "remote_agent_id", "instruction",
        }

        complete_resp = server.handle_request(
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "sip_handshake",
                    "arguments": {"role": "complete", "message": auth_text["auth_message"]},
                },
            }
        )
        done = json.loads(json.loads(complete_resp)["result"]["content"][0]["text"])
        assert done["success"] is True and done["state"] == "established"

        # 加解密工具
        enc_resp = server.handle_request(
            {
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {
                    "name": "sip_encrypt",
                    "arguments": {"plaintext": "mcp-zh", "recipient_id": "peer"},
                },
            }
        )
        enc_text = json.loads(json.loads(enc_resp)["result"]["content"][0]["text"])
        assert enc_text["success"] is True
        assert "encrypted_message" in enc_text


class TestZHFileTransfer:
    """ZH 文件工件：往返 + 篡改拒绝 + 跨套件拒绝 + EN 缺省不变"""

    def test_roundtrip(self, tmp_path):
        src = tmp_path / "zh.txt"
        src.write_bytes(bytes(range(256)) * 4)
        master = bytes(range(32))
        result = pack_file(str(src), master, chunk_size=1024, suite=SUITE_ZH)
        out = unpack_file(
            result.artifact_path, master, output_path=str(tmp_path / "out"), suite=SUITE_ZH
        )
        assert out.chunks_verified == 1
        assert (tmp_path / "out").read_bytes() == src.read_bytes()

    def test_tamper_rejected(self, tmp_path):
        from sip_protocol.exceptions import ChunkIntegrityError

        src = tmp_path / "zh2.bin"
        src.write_bytes(bytes(range(256)) * 8)
        master = bytes(range(32))
        result = pack_file(str(src), master, chunk_size=1024, suite=SUITE_ZH)
        artifact = bytearray((tmp_path / "zh2.bin.sipft").read_bytes())
        artifact[len(artifact) // 2] ^= 0xFF
        tampered = tmp_path / "tampered.sipft"
        tampered.write_bytes(bytes(artifact))
        with pytest.raises((ChunkIntegrityError, ArtifactCorruptedError)):
            unpack_file(str(tampered), master, output_path=str(tmp_path / "o2"), suite=SUITE_ZH)

    def test_cross_suite_unpack_rejected(self, tmp_path):
        """EN 套件解 ZH 工件：头部认证失败（套件不符与密钥错误不可区分，防 oracle）"""
        src = tmp_path / "cross.bin"
        src.write_bytes(b"x" * 2048)
        master = bytes(range(32))
        result = pack_file(str(src), master, chunk_size=1024, suite=SUITE_ZH)
        with pytest.raises(ArtifactCorruptedError):
            unpack_file(result.artifact_path, master, output_path=str(tmp_path / "o3"))

    def test_en_default_unchanged(self, tmp_path):
        src = tmp_path / "en.bin"
        src.write_bytes(b"y" * 2048)
        master = bytes(range(32))
        result = pack_file(str(src), master, chunk_size=1024)
        out = unpack_file(result.artifact_path, master, output_path=str(tmp_path / "o4"))
        assert (tmp_path / "o4").read_bytes() == b"y" * 2048
