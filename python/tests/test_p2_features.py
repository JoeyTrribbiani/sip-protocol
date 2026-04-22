"""
P2功能测试
测试协议版本协商、消息分片、连接恢复
"""

import pytest
import time
import base64
import json
from sip_protocol.protocol.version import (
    negotiate_version,
    validate_version,
    version_compare,
    is_backward_compatible,
    PROTOCOL_VERSIONS,
    DEFAULT_VERSION,
)
from sip_protocol.protocol.fragment import (
    FragmentBuffer,
    generate_fragment_id,
    fragment_message,
    reassemble_fragment,
    MAX_MESSAGE_SIZE,
    MAX_PAYLOAD_SIZE,
)
from sip_protocol.protocol.resume import (
    SessionResumeState,
    serialize_session_state,
    deserialize_session_state,
    create_session_resume_message,
    verify_session_resume,
    create_session_resume_ack_message,
    is_session_expired,
    validate_message_counter,
)


class TestVersionNegotiation:
    """测试协议版本协商"""

    def test_negotiate_version_success(self):
        """测试成功协商版本"""
        supported_local = ["SIP-1.0", "SIP-1.1", "SIP-1.2"]
        supported_remote = ["SIP-1.1", "SIP-1.2", "SIP-1.3"]

        result = negotiate_version(supported_local, supported_remote)
        assert result == "SIP-1.2"  # 应该选择最新的共同版本

    def test_negotiate_version_no_common(self):
        """测试没有共同版本"""
        supported_local = ["SIP-1.0", "SIP-1.1"]
        supported_remote = ["SIP-2.0", "SIP-2.1"]

        result = negotiate_version(supported_local, supported_remote)
        assert result is None

    def test_validate_version_valid(self):
        """测试验证有效版本"""
        for version in PROTOCOL_VERSIONS:
            assert validate_version(version) is True

    def test_validate_version_invalid(self):
        """测试验证无效版本"""
        assert validate_version("SIP-0.1") is False
        assert validate_version("SIP-2.0") is False
        assert validate_version("INVALID") is False
        assert validate_version("SIP-1") is False

    def test_version_compare(self):
        """测试版本比较"""
        assert version_compare("SIP-1.0", "SIP-1.0") == 0
        assert version_compare("SIP-1.1", "SIP-1.0") == 1
        assert version_compare("SIP-1.0", "SIP-1.1") == -1

    def test_is_backward_compatible(self):
        """测试向后兼容性"""
        assert is_backward_compatible("SIP-1.0", "SIP-1.1") is True
        assert is_backward_compatible("SIP-1.1", "SIP-1.2") is True
        assert is_backward_compatible("SIP-1.0", "SIP-2.0") is False


class TestMessageFragmentation:
    """测试消息分片"""

    def test_generate_fragment_id(self):
        """测试生成分片ID"""
        fragment_id = generate_fragment_id(123, "agent:test")
        assert len(fragment_id) == 16
        assert isinstance(fragment_id, str)

    def test_generate_fragment_id_consistency(self):
        """测试分片ID一致性"""
        id1 = generate_fragment_id(123, "agent:test")
        id2 = generate_fragment_id(123, "agent:test")
        assert id1 == id2

    def test_fragment_small_message(self):
        """测试小消息不分片"""
        message = {
            "version": "SIP-1.0",
            "type": "message",
            "timestamp": int(time.time() * 1000),
            "sender_id": "agent:test",
            "recipient_id": "agent:remote",
            "message_counter": 1,
            "iv": "base64_iv",
            "payload": {"text": "Hello, world!"},
            "auth_tag": "base64_tag",
            "replay_tag": "base64_replay",
        }

        fragments = fragment_message(message, 1, "agent:test")
        assert len(fragments) == 1
        assert fragments[0]["type"] == "message"  # 不应该是分片消息

    def test_fragment_large_message(self):
        """测试大消息分片"""
        # 创建一个大payload（>1MB）
        large_text = "A" * (MAX_MESSAGE_SIZE + 1000)

        message = {
            "version": "SIP-1.0",
            "type": "message",
            "timestamp": int(time.time() * 1000),
            "sender_id": "agent:test",
            "recipient_id": "agent:remote",
            "message_counter": 1,
            "iv": "base64_iv",
            "payload": {"text": large_text},
            "auth_tag": "base64_tag",
            "replay_tag": "base64_replay",
        }

        fragments = fragment_message(message, 1, "agent:test")
        assert len(fragments) > 1
        assert fragments[0]["type"] == "message_fragment"

        # 验证分片信息
        fragment_info = fragments[0]["fragment_info"]
        assert "fragment_id" in fragment_info
        assert "fragment_index" in fragment_info
        assert "fragment_total" in fragment_info
        assert fragment_info["fragment_index"] == 1
        assert fragment_info["fragment_total"] == len(fragments)

    def test_reassemble_fragments(self):
        """测试重组分片"""
        buffer = FragmentBuffer()

        # 创建一个大payload
        large_text = "A" * (MAX_MESSAGE_SIZE + 1000)

        message = {
            "version": "SIP-1.0",
            "type": "message",
            "timestamp": int(time.time() * 1000),
            "sender_id": "agent:test",
            "recipient_id": "agent:remote",
            "message_counter": 1,
            "iv": "base64_iv",
            "payload": {"text": large_text},
            "auth_tag": "base64_tag",
            "replay_tag": "base64_replay",
        }

        # 分片
        fragments = fragment_message(message, 1, "agent:test")

        # 重组
        reassembled_payload = None
        for fragment in fragments:
            result = reassemble_fragment(fragment, buffer)
            if result is not None:
                reassembled_payload = result

        # 验证
        assert reassembled_payload is not None
        original_payload = json.dumps({"text": large_text}).encode()
        assert reassembled_payload == original_payload

    def test_fragment_buffer_timeout(self):
        """测试分片缓冲区超时"""
        buffer = FragmentBuffer(timeout=1)

        # 添加一个分片
        buffer.add_fragment(
            fragment_id="test123",
            fragment_index=1,
            fragment_total=2,
            fragment_size=100,
            payload=b"test_data",
        )

        # 等待超时
        time.sleep(1.1)

        # 清理过期分片
        cleaned = buffer.cleanup_expired_fragments()
        assert cleaned == 1

    def test_fragment_buffer_cleanup(self):
        """测试分片缓冲区清理"""
        buffer = FragmentBuffer()

        # 添加多个分片
        buffer.add_fragment("id1", 1, 1, 100, b"data1")
        buffer.add_fragment("id2", 1, 1, 100, b"data2")

        # 清理指定的分片
        buffer.remove_fragment("id1")

        # 验证
        assert "id1" not in buffer.fragments
        assert "id2" in buffer.fragments


class TestSessionResume:
    """测试连接恢复"""

    def test_serialize_deserialize_session_state(self):
        """测试会话状态序列化和反序列化"""
        state = SessionResumeState(
            session_id="session:abc123",
            partner_id="agent:remote",
            established_at=int(time.time()),
            encryption_key=base64.b64encode(b"encryption_key").decode(),
            auth_key=base64.b64encode(b"auth_key").decode(),
            replay_key=base64.b64encode(b"replay_key").decode(),
            message_counter_send=100,
            message_counter_receive=100,
            last_rekey_sequence=5,
            rekey_key_derived=True,
        )

        # 序列化
        serialized = serialize_session_state(state)
        assert isinstance(serialized, str)

        # 反序列化
        deserialized = deserialize_session_state(serialized)
        assert deserialized.session_id == state.session_id
        assert deserialized.partner_id == state.partner_id
        assert deserialized.message_counter_send == state.message_counter_send

    def test_create_session_resume_message(self):
        """测试创建Session_Resume消息"""
        state = SessionResumeState(
            session_id="session:abc123",
            partner_id="agent:remote",
            established_at=int(time.time()),
            encryption_key=base64.b64encode(b"encryption_key").decode(),
            auth_key=base64.b64encode(b"auth_key").decode(),
            replay_key=base64.b64encode(b"replay_key").decode(),
            message_counter_send=100,
            message_counter_receive=100,
            last_rekey_sequence=5,
            rekey_key_derived=True,
        )

        message = create_session_resume_message(state, 101)

        assert message["type"] == "session_resume"
        assert message["session_id"] == state.session_id
        assert message["message_counter"] == 101
        assert "signature" in message

    def test_verify_session_resume(self):
        """测试验证Session_Resume消息"""
        state = SessionResumeState(
            session_id="session:abc123",
            partner_id="agent:remote",
            established_at=int(time.time()),
            encryption_key=base64.b64encode(b"encryption_key").decode(),
            auth_key=base64.b64encode(b"auth_key").decode(),
            replay_key=base64.b64encode(b"replay_key").decode(),
            message_counter_send=100,
            message_counter_receive=100,
            last_rekey_sequence=5,
            rekey_key_derived=True,
        )

        # 创建消息
        message = create_session_resume_message(state, 101)

        # 验证消息
        auth_key = b"auth_key"
        is_valid = verify_session_resume(message, auth_key)
        assert is_valid is True

        # 测试无效签名
        message["signature"] = base64.b64encode(b"invalid_signature").decode()
        is_valid = verify_session_resume(message, auth_key)
        assert is_valid is False

    def test_create_session_resume_ack_message(self):
        """测试创建Session_Resume_Ack消息"""
        state = SessionResumeState(
            session_id="session:abc123",
            partner_id="agent:remote",
            established_at=int(time.time()),
            encryption_key=base64.b64encode(b"encryption_key").decode(),
            auth_key=base64.b64encode(b"auth_key").decode(),
            replay_key=base64.b64encode(b"replay_key").decode(),
            message_counter_send=100,
            message_counter_receive=100,
            last_rekey_sequence=5,
            rekey_key_derived=True,
        )

        message = create_session_resume_ack_message(state, 101)

        assert message["type"] == "session_resume_ack"
        assert message["session_id"] == state.session_id
        assert message["message_counter"] == 101
        assert "signature" in message

    def test_is_session_expired(self):
        """测试会话过期检查"""
        # 创建一个过期的会话
        old_time = int(time.time()) - 25 * 60 * 60  # 25小时前
        state = SessionResumeState(
            session_id="session:abc123",
            partner_id="agent:remote",
            established_at=old_time,
            encryption_key=base64.b64encode(b"encryption_key").decode(),
            auth_key=base64.b64encode(b"auth_key").decode(),
            replay_key=base64.b64encode(b"replay_key").decode(),
            message_counter_send=100,
            message_counter_receive=100,
            last_rekey_sequence=5,
            rekey_key_derived=True,
        )

        assert is_session_expired(state) is True

        # 创建一个未过期的会话
        recent_time = int(time.time()) - 10 * 60  # 10分钟前
        state2 = SessionResumeState(
            session_id="session:abc123",
            partner_id="agent:remote",
            established_at=recent_time,
            encryption_key=base64.b64encode(b"encryption_key").decode(),
            auth_key=base64.b64encode(b"auth_key").decode(),
            replay_key=base64.b64encode(b"replay_key").decode(),
            message_counter_send=100,
            message_counter_receive=100,
            last_rekey_sequence=5,
            rekey_key_derived=True,
        )

        assert is_session_expired(state2) is False

    def test_validate_message_counter(self):
        """测试消息计数器验证"""
        # 有效差异
        assert validate_message_counter(100, 105) is True
        assert validate_message_counter(100, 95) is True

        # 无效差异
        assert validate_message_counter(100, 1101) is False
        assert validate_message_counter(100, -901) is False

        # 完全匹配
        assert validate_message_counter(100, 100) is True
