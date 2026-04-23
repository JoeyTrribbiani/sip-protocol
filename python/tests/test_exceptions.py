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
