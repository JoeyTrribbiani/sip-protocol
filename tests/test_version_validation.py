"""版本校验一致性测试（SPEC §11.2 / 偏差 D7 补齐）

覆盖四个版本拒绝点：
1. 握手 hello/auth 的 "SIP-1.0"
2. rekey 请求/响应的 "SIP-1.0"
3. AgentMessage 信封的 "SIP-TRANSPORT-1.0"
4. SIPFT 工件魔数 "SIPFT1.0" 与头部 format=1（既有行为回归确认）
"""

import io
import json

import pytest

from sip_protocol.crypto.hkdf import derive_keys_triple_dh
from sip_protocol.exceptions import (
    ArtifactCorruptedError,
    MessageSchemaError,
    VersionNegotiationError,
)
from sip_protocol.filetransfer.format import ArtifactHeader, read_prefix
from sip_protocol.protocol.handshake import (
    PROTOCOL_VERSION,
    complete_handshake,
    initiate_handshake,
    respond_handshake,
)
from sip_protocol.protocol.rekey import RekeyManager
from sip_protocol.transport.message import AgentMessage, parse_raw_message


@pytest.fixture
def handshake_pair():
    """真实完成的握手，供 auth/responder 状态复用"""
    psk = b"version-test-psk"
    hello, state_a = initiate_handshake(psk)
    auth, _state_b, _keys = respond_handshake(hello, psk)
    return psk, hello, state_a, auth


def _fake_session_state():
    """固定输入的三元组会话状态（版本校验用，无需真实握手）"""
    enc, auth, replay = derive_keys_triple_dh(
        b"a" * 32, b"b" * 32, b"c" * 32, b"k" * 32, b"n" * 16, b"m" * 16
    )
    return {"encryption_key": enc, "auth_key": auth, "replay_key": replay}


class TestHandshakeVersion:
    """握手消息版本拒绝（SIP-PROTO-003）"""

    def test_hello_wrong_version_rejected(self, handshake_pair):
        _psk, hello, _state, _auth = handshake_pair
        hello["version"] = "SIP-2.0"
        with pytest.raises(VersionNegotiationError) as exc_info:
            respond_handshake(hello, b"version-test-psk")
        assert "SIP-2.0" in str(exc_info.value)
        assert exc_info.value.code == "SIP-PROTO-003"

    def test_hello_missing_version_rejected(self, handshake_pair):
        _psk, hello, _state, _auth = handshake_pair
        del hello["version"]
        with pytest.raises(VersionNegotiationError):
            respond_handshake(hello, b"version-test-psk")

    def test_auth_wrong_version_rejected(self, handshake_pair):
        _psk, _hello, state_a, auth = handshake_pair
        auth["version"] = "SIP-0.9"
        with pytest.raises(VersionNegotiationError):
            complete_handshake(auth, state_a)

    def test_version_error_is_value_error(self, handshake_pair):
        """双继承保持既有 except ValueError 捕获路径兼容（MCP -32005 映射依赖）"""
        _psk, hello, _state, _auth = handshake_pair
        hello["version"] = "SIP-2.0"
        with pytest.raises(ValueError):
            respond_handshake(hello, b"version-test-psk")

    def test_correct_version_accepted(self, handshake_pair):
        """正路径：本版本消息照常通过（回归保护）"""
        psk, hello, state_a, _auth = handshake_pair
        auth2, _state_b, _keys = respond_handshake(hello, psk)
        assert auth2["version"] == PROTOCOL_VERSION
        keys_a, _ = complete_handshake(auth2, state_a)
        assert len(keys_a["encryption_key"]) == 32


class TestRekeyVersion:
    """rekey 消息版本拒绝（validate 返回 bool，与既有语义一致）"""

    def test_request_wrong_version_invalid(self):
        request = RekeyManager(_fake_session_state(), is_initiator=True).create_rekey_request()
        request["version"] = "SIP-2.0"
        peer = RekeyManager(_fake_session_state(), is_initiator=False)
        assert peer.validate_rekey_request(request) is False
        with pytest.raises(ValueError):
            peer.process_rekey_request(request)

    def test_request_missing_version_invalid(self):
        request = RekeyManager(_fake_session_state(), is_initiator=True).create_rekey_request()
        del request["version"]
        peer = RekeyManager(_fake_session_state(), is_initiator=False)
        assert peer.validate_rekey_request(request) is False

    def test_response_wrong_version_invalid(self):
        state = _fake_session_state()
        mgr = RekeyManager(dict(state), is_initiator=True)
        request = mgr.create_rekey_request()
        peer = RekeyManager(dict(state), is_initiator=False)
        response = peer.process_rekey_request(request)
        response["version"] = "SIP-9.9"
        assert mgr.validate_rekey_response(response) is False
        with pytest.raises(ValueError):
            mgr.process_rekey_response(response)

    def test_correct_version_valid(self):
        state = _fake_session_state()
        request = RekeyManager(dict(state), is_initiator=True).create_rekey_request()
        peer = RekeyManager(dict(state), is_initiator=False)
        assert peer.validate_rekey_request(request) is True


class TestEnvelopeVersion:
    """AgentMessage 信封版本拒绝（SIP-MSG-001）"""

    def test_wrong_envelope_version_rejected(self):
        data = json.loads(AgentMessage.to_json(AgentMessage()))
        data["version"] = "SIP-TRANSPORT-2.0"
        with pytest.raises(MessageSchemaError) as exc_info:
            AgentMessage.from_dict(data)
        assert exc_info.value.code == "SIP-MSG-001"

    def test_missing_version_defaults_to_current(self):
        """缺省 version 视为本版本（lenient-on-absent, strict-on-wrong）"""
        data = AgentMessage(sender_id="a", recipient_id="b").to_dict()
        del data["version"]
        assert AgentMessage.from_dict(data).version == "SIP-TRANSPORT-1.0"

    def test_parse_raw_message_wraps_version_error(self):
        data = json.loads(AgentMessage.to_json(AgentMessage()))
        data["version"] = "SIP-TRANSPORT-0.1"
        with pytest.raises(ValueError, match="不支持的信封版本"):
            parse_raw_message(json.dumps(data))

    def test_current_envelope_version_roundtrip(self):
        msg = AgentMessage(sender_id="a", recipient_id="b", payload={"text": "hi"})
        assert AgentMessage.from_json(msg.to_json()).version == "SIP-TRANSPORT-1.0"


class TestArtifactVersion:
    """SIPFT 工件版本闸（既有强制行为回归确认）"""

    def test_bad_magic_rejected(self):
        with pytest.raises(ArtifactCorruptedError):
            read_prefix(io.BytesIO(b"SIPFT2.0\x00\x00\x00\x00"))

    def test_bad_header_format_rejected(self):
        with pytest.raises(ArtifactCorruptedError, match="格式版本"):
            ArtifactHeader.from_json_bytes(b'{"format": 2}')
