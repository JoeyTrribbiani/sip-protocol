"""SIP异常类体系测试"""

import pytest

from sip_protocol.exceptions import (
    ErrorSeverity,
    SIPError,
)


class TestErrorSeverity:
    """ErrorSeverity 枚举测试"""

    def test_enum_values(self):
        assert ErrorSeverity.LOW.value == "low"
        assert ErrorSeverity.MEDIUM.value == "medium"
        assert ErrorSeverity.HIGH.value == "high"
        assert ErrorSeverity.CRITICAL.value == "critical"

    def test_enum_members(self):
        assert len(ErrorSeverity) == 4


class TestSIPError:
    """SIPError 基类测试"""

    def test_basic_construction(self):
        err = SIPError(
            code="SIP-TEST-001",
            message="测试错误",
        )
        assert err.code == "SIP-TEST-001"
        assert err.message == "测试错误"
        assert str(err) == "[SIP-TEST-001] 测试错误"
        assert err.severity == ErrorSeverity.MEDIUM
        assert err.recoverable is True
        assert err.details == {}

    def test_default_severity_is_medium(self):
        err = SIPError(code="X", message="Y")
        assert err.severity == ErrorSeverity.MEDIUM

    def test_default_recoverable_is_true(self):
        err = SIPError(code="X", message="Y")
        assert err.recoverable is True

    def test_custom_severity(self):
        err = SIPError(
            code="X",
            message="Y",
            severity=ErrorSeverity.CRITICAL,
            recoverable=False,
        )
        assert err.severity == ErrorSeverity.CRITICAL
        assert err.recoverable is False

    def test_details_dict(self):
        err = SIPError(
            code="X",
            message="Y",
            details={"key": "value"},
        )
        assert err.details == {"key": "value"}

    def test_to_dict(self):
        err = SIPError(
            code="SIP-TEST-002",
            message="序列化测试",
            severity=ErrorSeverity.HIGH,
            recoverable=False,
            details={"reason": "test"},
        )
        d = err.to_dict()
        assert d["code"] == "SIP-TEST-002"
        assert d["message"] == "序列化测试"
        assert d["severity"] == "high"
        assert d["recoverable"] is False
        assert d["details"] == {"reason": "test"}

    def test_from_dict_unknown_code_returns_base(self):
        d = {
            "code": "SIP-UNKNOWN-999",
            "message": "未知错误",
            "severity": "low",
            "recoverable": True,
            "details": {},
        }
        err = SIPError.from_dict(d)
        assert isinstance(err, SIPError)
        assert err.code == "SIP-UNKNOWN-999"
        assert err.message == "未知错误"

    def test_from_dict_roundtrip(self):
        err = SIPError(
            code="SIP-TEST-003",
            message="往返测试",
            severity=ErrorSeverity.LOW,
            recoverable=True,
            details={"nested": {"a": 1}},
        )
        d = err.to_dict()
        err2 = SIPError.from_dict(d)
        assert err2.code == err.code
        assert err2.message == err.message
        assert err2.severity == err.severity
        assert err2.recoverable == err.recoverable
        assert err2.details == err.details

    def test_is_exception(self):
        assert issubclass(SIPError, Exception)
        err = SIPError(code="X", message="Y")
        assert isinstance(err, Exception)

    def test_can_be_raised(self):
        with pytest.raises(SIPError, match="\\[SIP-TEST-001\\]"):
            raise SIPError(code="SIP-TEST-001", message="test raise")


from sip_protocol.exceptions import (
    CryptoError,
    EncryptionError,
    DecryptionError,
    KeyDerivationError,
    ProtocolError,
    HandshakeError,
    RekeyError,
    VersionNegotiationError,
    FragmentError,
)


class TestCryptoExceptions:
    def test_crypto_error_inherits_sip(self):
        err = CryptoError(message="crypto fail")
        assert isinstance(err, SIPError)
        assert err.code == "SIP-CRYPTO-000"

    def test_encryption_error(self):
        err = EncryptionError()
        assert err.code == "SIP-CRYPTO-001"
        assert err.message == "加密失败"

    def test_decryption_error_not_recoverable(self):
        err = DecryptionError()
        assert err.recoverable is False

    def test_key_derivation_error_not_recoverable(self):
        err = KeyDerivationError()
        assert err.recoverable is False

    def test_encryption_error_custom_message(self):
        err = EncryptionError(message="密钥无效")
        assert err.message == "密钥无效"
        assert err.code == "SIP-CRYPTO-001"


class TestProtocolExceptions:
    def test_protocol_error_inherits_sip(self):
        err = ProtocolError(message="proto fail")
        assert isinstance(err, SIPError)
        assert err.code == "SIP-PROTO-000"

    def test_handshake_error(self):
        err = HandshakeError()
        assert err.code == "SIP-PROTO-001"
        assert err.recoverable is True

    def test_rekey_error(self):
        err = RekeyError()
        assert err.code == "SIP-PROTO-002"

    def test_version_negotiation_error(self):
        err = VersionNegotiationError(message="版本不兼容")
        assert err.code == "SIP-PROTO-003"

    def test_fragment_error(self):
        err = FragmentError(message="分片丢失")
        assert err.code == "SIP-PROTO-004"


from sip_protocol.exceptions import (
    MessageError,
    MessageSchemaError,
    MessageExpiredError,
    TransportError,
    SIPConnectionError,
    AdapterError,
    AgentError,
    CapabilityNotFoundError,
    AgentNotAvailableError,
    TaskError,
    TaskTimeoutError,
    GroupError,
    MemberNotFoundError,
    GroupKeyError,
)


class TestMessageExceptions:
    def test_message_error_code(self):
        assert MessageError("", code="SIP-MSG-000").code == "SIP-MSG-000"

    def test_message_schema_error(self):
        assert MessageSchemaError("", code="SIP-MSG-001").code == "SIP-MSG-001"

    def test_message_expired_error(self):
        assert MessageExpiredError("", code="SIP-MSG-002").code == "SIP-MSG-002"


class TestTransportExceptions:
    def test_transport_error_code(self):
        assert TransportError("", code="SIP-TRANSPORT-000").code == "SIP-TRANSPORT-000"

    def test_sip_connection_error(self):
        assert SIPConnectionError("", code="SIP-TRANSPORT-001").code == "SIP-TRANSPORT-001"

    def test_adapter_error(self):
        assert AdapterError("", code="SIP-TRANSPORT-002").code == "SIP-TRANSPORT-002"

    def test_connection_error_does_not_shadow_builtin(self):
        """SIPConnectionError不应隐藏Python内置ConnectionError"""
        import builtins

        assert SIPConnectionError is not builtins.ConnectionError
        assert issubclass(SIPConnectionError, Exception)


class TestAgentExceptions:
    def test_agent_error_code(self):
        assert AgentError("", code="SIP-AGENT-000").code == "SIP-AGENT-000"

    def test_capability_not_found_error(self):
        err = CapabilityNotFoundError("sql_query")
        assert err.code == "SIP-AGENT-001"
        assert "sql_query" in err.message

    def test_capability_not_found_empty(self):
        err = CapabilityNotFoundError()
        assert "能力不存在" in err.message

    def test_agent_not_available_error(self):
        err = AgentNotAvailableError("agent-hermes")
        assert err.code == "SIP-AGENT-002"
        assert "agent-hermes" in err.message

    def test_task_error_code(self):
        assert TaskError("", code="SIP-AGENT-003").code == "SIP-AGENT-003"

    def test_task_timeout_error(self):
        err = TaskTimeoutError("task-xxx", 30.0)
        assert err.code == "SIP-AGENT-004"
        assert "task-xxx" in err.message
        assert "30.0" in err.message

    def test_task_timeout_error_no_id(self):
        err = TaskTimeoutError()
        assert "任务超时" in err.message


class TestGroupExceptions:
    def test_group_error_code(self):
        assert GroupError("", code="SIP-GROUP-000").code == "SIP-GROUP-000"

    def test_member_not_found_error(self):
        err = MemberNotFoundError("agent-c")
        assert err.code == "SIP-GROUP-001"
        assert "agent-c" in err.message

    def test_group_key_error(self):
        assert GroupKeyError("", code="SIP-GROUP-002").code == "SIP-GROUP-002"


class TestErrorRegistry:
    def test_all_errors_registered(self):
        """所有异常类都应已注册到_ERROR_REGISTRY"""
        from sip_protocol.exceptions import _ERROR_REGISTRY

        expected = {
            "SIP-ERROR-000",
            "SIP-CRYPTO-000",
            "SIP-CRYPTO-001",
            "SIP-CRYPTO-002",
            "SIP-CRYPTO-003",
            "SIP-PROTO-000",
            "SIP-PROTO-001",
            "SIP-PROTO-002",
            "SIP-PROTO-003",
            "SIP-PROTO-004",
            "SIP-MSG-000",
            "SIP-MSG-001",
            "SIP-MSG-002",
            "SIP-TRANSPORT-000",
            "SIP-TRANSPORT-001",
            "SIP-TRANSPORT-002",
            "SIP-AGENT-000",
            "SIP-AGENT-001",
            "SIP-AGENT-002",
            "SIP-AGENT-003",
            "SIP-AGENT-004",
            "SIP-GROUP-000",
            "SIP-GROUP-001",
            "SIP-GROUP-002",
        }
        assert set(_ERROR_REGISTRY.keys()) == expected

    def test_unknown_code_returns_base(self):
        from sip_protocol.exceptions import _ERROR_REGISTRY

        assert _ERROR_REGISTRY.get("SIP-UNKNOWN") is None


class TestSubclassFromDictRoundtrip:
    """所有已注册异常子类的 to_dict/from_dict 往返测试"""

    @pytest.mark.parametrize(
        "cls",
        [
            SIPError,
            CryptoError,
            EncryptionError,
            DecryptionError,
            KeyDerivationError,
            ProtocolError,
            HandshakeError,
            RekeyError,
            VersionNegotiationError,
            FragmentError,
            MessageError,
            MessageSchemaError,
            MessageExpiredError,
            TransportError,
            SIPConnectionError,
            AdapterError,
            AgentError,
            CapabilityNotFoundError,
            AgentNotAvailableError,
            TaskError,
            TaskTimeoutError,
            GroupError,
            MemberNotFoundError,
            GroupKeyError,
        ],
    )
    def test_roundtrip_preserves_all_fields(self, cls):
        """to_dict → from_dict 往返后，所有字段必须一致且类型正确"""
        original = cls()
        d = original.to_dict()
        recovered = SIPError.from_dict(d)

        assert isinstance(recovered, cls), (
            f"from_dict 返回了 {type(recovered).__name__}，期望 {cls.__name__}"
        )
        assert recovered.code == original.code
        assert recovered.message == original.message
        assert recovered.severity == original.severity
        assert recovered.recoverable == original.recoverable
        assert recovered.details == original.details

    def test_roundtrip_with_custom_fields(self):
        """自定义字段（severity、recoverable、details）也能正确往返"""
        err = EncryptionError(
            message="密钥已过期",
            severity=ErrorSeverity.CRITICAL,
            recoverable=False,
            details={"algorithm": "x25519"},
        )
        d = err.to_dict()
        recovered = SIPError.from_dict(d)

        assert isinstance(recovered, EncryptionError)
        assert recovered.message == "密钥已过期"
        assert recovered.severity == ErrorSeverity.CRITICAL
        assert recovered.recoverable is False
        assert recovered.details == {"algorithm": "x25519"}

