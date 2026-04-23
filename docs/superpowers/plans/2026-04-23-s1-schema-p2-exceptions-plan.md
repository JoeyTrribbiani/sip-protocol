# S1 混合 Schema + P2 异常类体系 实现计划（v2）

> **给执行者：** 必须使用 superpowers:subagent-driven-development（推荐）或 superpowers:executing-plans 逐任务执行本计划。步骤使用复选框（`- [ ]`）语法追踪进度。

**目标：** 实现 SIP 混合 Schema（S1）和分层异常体系（P2）。SIP 定位为加密层（TLS for Agent Communication），采用信封 + 结构化消息的混合模式。

**架构：** `sip_protocol/` 下新增 `schema/`（消息类型、信封、数据类、验证）和顶层 `exceptions.py`（异常层级）。纯数据结构，零加密/传输依赖。

**设计文档：** `docs/superpowers/specs/2026-04-23-sip-hybrid-schema-design.md`

**技术栈：** Python 3.11+, pytest, dataclasses（标准库）, enum（标准库）。无新第三方依赖。

---

## 文件结构

```
python/src/sip_protocol/
├── exceptions.py              # P2: 全部异常类（包根目录，跨层使用）
├── schema/                     # S1: SIP 混合 Schema
│   ├── __init__.py           # 公共导出（含 SIPEnvelope）
│   ├── types.py              # MessageType, Priority, RecipientType
│   ├── parts.py              # 8种Part类型
│   ├── envelope.py           # 新增: SIPEnvelope 信封数据类
│   ├── message.py            # SIPMessage 数据类（结构化消息，在 payload 里）
│   └── validation.py         # validate_message(), validate_parts()
python/tests/
├── test_exceptions.py         # P2: 异常类体系测试
├── test_schema.py            # S1: Schema 测试
└── test_envelope.py           # S1: SIPEnvelope 测试
```

---

## 任务 1：异常基础 — ErrorSeverity 枚举, SIPError 基类

**涉及文件：**
- 新建：`python/src/sip_protocol/exceptions.py`
- 测试：`python/tests/test_exceptions.py`

- [ ] **步骤 1：编写失败测试**

```python
# tests/test_exceptions.py
"""SIP异常类体系测试"""

import pytest
from sip_protocol.exceptions import (
    SIPError,
    ErrorSeverity,
)


class TestErrorSeverity:
    def test_enum_values(self):
        assert ErrorSeverity.LOW.value == "low"
        assert ErrorSeverity.MEDIUM.value == "medium"
        assert ErrorSeverity.HIGH.value == "high"
        assert ErrorSeverity.CRITICAL.value == "critical"

    def test_enum_members(self):
        assert len(ErrorSeverity) == 4


class TestSIPError:
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
            code="X", message="Y",
            severity=ErrorSeverity.CRITICAL,
            recoverable=False,
        )
        assert err.severity == ErrorSeverity.CRITICAL
        assert err.recoverable is False

    def test_details_dict(self):
        err = SIPError(
            code="X", message="Y",
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
```

- [ ] **步骤 2：运行测试，确认失败**

运行：`cd python && python -m pytest tests/test_exceptions.py::TestSIPError -v`
预期：失败（ModuleNotFoundError）

- [ ] **步骤 3：编写最小实现**

创建 `python/src/sip_protocol/exceptions.py`：

```python
"""SIP协议异常类体系

分层、可序列化、与SIP协议栈对齐的异常体系。
异常是跨层使用的，放在包根目录而非子模块中。
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any


class ErrorSeverity(str, enum.Enum):
    """错误严重级别"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# 错误注册表：code → 异常类
_ERROR_REGISTRY: dict[str, type[SIPError]] = {}


def _register_error(cls: type[SIPError]) -> type[SIPError]:
    """将异常类注册到注册表（内部装饰器）"""
    instance = cls("", "")
    _ERROR_REGISTRY[instance.code] = cls
    return cls


@_register_error
@dataclass
class SIPError(Exception):
    """SIP协议基础异常"""

    code: str = "SIP-ERROR-000"
    message: str = ""
    severity: ErrorSeverity = ErrorSeverity.MEDIUM
    recoverable: bool = True
    details: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        super().__init__(self.message)

    def __str__(self) -> str:
        return f"[{self.code}] {self.message}"

    def to_dict(self) -> dict[str, Any]:
        """序列化为字典，用于跨Agent传输"""
        return {
            "code": self.code,
            "message": self.message,
            "severity": self.severity.value,
            "recoverable": self.recoverable,
            "details": self.details,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SIPError:
        """从字典反序列化为异常实例"""
        error_cls = _ERROR_REGISTRY.get(data.get("code", ""))
        if error_cls is None:
            error_cls = SIPError
        return error_cls(
            code=data.get("code", "SIP-ERROR-000"),
            message=data.get("message", ""),
            severity=ErrorSeverity(data.get("severity", "medium")),
            recoverable=data.get("recoverable", True),
            details=data.get("details", {}),
        )
```

- [ ] **步骤 4：运行测试，确认通过**

运行：`cd python && python -m pytest tests/test_exceptions.py::TestSIPError -v`
预期：全部通过（15个测试）

- [ ] **步骤 5：提交**

```bash
cd python
git add src/sip_protocol/exceptions.py tests/test_exceptions.py
git commit -m "feat: 新增SIPError基类与序列化支持"
```

---

## 任务 2：加密层与协议层异常

**涉及文件：**
- 修改：`python/src/sip_protocol/exceptions.py`

- [ ] **步骤 1：编写失败测试**

追加到 `tests/test_exceptions.py`：

```python
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
```

- [ ] **步骤 2：运行测试，确认失败**

运行：`cd python && python -m pytest tests/test_exceptions.py::TestCryptoExceptions -v`
预期：失败（ImportError: CryptoError 未定义）

- [ ] **步骤 3：在 exceptions.py 中添加加密层和协议层异常**

在 SIPError 类之后、`_ERROR_REGISTRY` 之前插入：

```python
# ==================== 加密层异常 ====================

@_register_error
@dataclass
class CryptoError(SIPError):
    """加密层基础异常"""
    def __init__(self, message: str = "加密层错误", **kwargs: Any) -> None:
        super().__init__(code="SIP-CRYPTO-000", message=message, **kwargs)


@_register_error
@dataclass
class EncryptionError(CryptoError):
    """加密失败"""
    def __init__(self, message: str = "加密失败", **kwargs: Any) -> None:
        super().__init__(message=message, code="SIP-CRYPTO-001", **kwargs)


@_register_error
@dataclass
class DecryptionError(CryptoError):
    """解密失败"""
    def __init__(self, message: str = "解密失败", **kwargs: Any) -> None:
        super().__init__(message=message, code="SIP-CRYPTO-002",
                         recoverable=False, **kwargs)


@_register_error
@dataclass
class KeyDerivationError(CryptoError):
    """密钥派生失败"""
    def __init__(self, message: str = "密钥派生失败", **kwargs: Any) -> None:
        super().__init__(message=message, code="SIP-CRYPTO-003",
                         recoverable=False, **kwargs)


# ==================== 协议层异常 ====================

@_register_error
@dataclass
class ProtocolError(SIPError):
    """协议层基础异常"""
    def __init__(self, message: str = "协议层错误", **kwargs: Any) -> None:
        super().__init__(code="SIP-PROTO-000", message=message, **kwargs)


@_register_error
@dataclass
class HandshakeError(ProtocolError):
    """握手失败"""
    def __init__(self, message: str = "握手失败", **kwargs: Any) -> None:
        super().__init__(message=message, code="SIP-PROTO-001",
                         recoverable=True, **kwargs)


@_register_error
@dataclass
class RekeyError(ProtocolError):
    """密钥轮换失败"""
    def __init__(self, message: str = "密钥轮换失败", **kwargs: Any) -> None:
        super().__init__(message=message, code="SIP-PROTO-002",
                         recoverable=True, **kwargs)


@_register_error
@dataclass
class VersionNegotiationError(ProtocolError):
    """协议版本协商失败"""
    def __init__(self, message: str = "协议版本协商失败", **kwargs: Any) -> None:
        super().__init__(message=message, code="SIP-PROTO-003", **kwargs)


@_register_error
@dataclass
class FragmentError(ProtocolError):
    """消息分片错误"""
    def __init__(self, message: str = "消息分片错误", **kwargs: Any) -> None:
        super().__init__(message=message, code="SIP-PROTO-004", **kwargs)
```

- [ ] **步骤 4：运行测试，确认通过**

运行：`cd python && python -m pytest tests/test_exceptions.py::TestCryptoExceptions tests/test_exceptions.py::TestProtocolExceptions -v`
预期：全部通过

- [ ] **步骤 5：提交**

```bash
git add src/sip_protocol/exceptions.py tests/test_exceptions.py
git commit -m "feat: 新增加密层和协议层异常子类"
```

---

## 任务 3：消息层、传输层、Agent层、群组层异常

**涉及文件：**
- 修改：`python/src/sip_protocol/exceptions.py`

- [ ] **步骤 1：编写失败测试**

追加到 `tests/test_exceptions.py`：

```python
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
        expected = {
            "SIP-ERROR-000", "SIP-CRYPTO-000", "SIP-CRYPTO-001",
            "SIP-CRYPTO-002", "SIP-CRYPTO-003", "SIP-PROTO-000",
            "SIP-PROTO-001", "SIP-PROTO-002", "SIP-PROTO-003",
            "SIP-PROTO-004", "SIP-MSG-000", "SIP-MSG-001",
            "SIP-MSG-002", "SIP-TRANSPORT-000", "SIP-TRANSPORT-001",
            "SIP-TRANSPORT-002", "SIP-AGENT-000", "SIP-AGENT-001",
            "SIP-AGENT-002", "SIP-AGENT-003", "SIP-AGENT-004",
            "SIP-GROUP-000", "SIP-GROUP-001", "SIP-GROUP-002",
        }
        assert set(_ERROR_REGISTRY.keys()) == expected

    def test_unknown_code_returns_base(self):
        from sip_protocol.exceptions import _ERROR_REGISTRY
        assert _ERROR_REGISTRY.get("SIP-UNKNOWN") is None
```

- [ ] **步骤 2：运行测试，确认失败**

运行：`cd python && python -m pytest tests/test_exceptions.py -v`
预期：失败（ImportError: MessageError 等未定义）

- [ ] **步骤 3：在 exceptions.py 中添加剩余异常类**

追加到 `python/src/sip_protocol/exceptions.py`：

```python
# ==================== 消息层异常 ====================

@_register_error
@dataclass
class MessageError(SIPError):
    """消息层基础异常"""
    def __init__(self, message: str = "消息层错误", **kwargs: Any) -> None:
        super().__init__(code="SIP-MSG-000", message=message, **kwargs)


@_register_error
@dataclass
class MessageSchemaError(MessageError):
    """消息Schema验证失败"""
    def __init__(self, message: str = "消息Schema验证失败", **kwargs: Any) -> None:
        super().__init__(message=message, code="SIP-MSG-001", **kwargs)


@_register_error
@dataclass
class MessageExpiredError(MessageError):
    """消息已过期"""
    def __init__(self, message: str = "消息已过期", **kwargs: Any) -> None:
        super().__init__(message=message, code="SIP-MSG-002", **kwargs)


# ==================== 传输层异常 ====================

@_register_error
@dataclass
class TransportError(SIPError):
    """传输层基础异常"""
    def __init__(self, message: str = "传输层错误", **kwargs: Any) -> None:
        super().__init__(code="SIP-TRANSPORT-000", message=message, **kwargs)


@_register_error
@dataclass
class SIPConnectionError(TransportError):
    """连接失败（SIP前缀避免与内置ConnectionError冲突）"""
    def __init__(self, message: str = "连接失败", **kwargs: Any) -> None:
        super().__init__(message=message, code="SIP-TRANSPORT-001",
                         recoverable=True, **kwargs)


@_register_error
@dataclass
class AdapterError(TransportError):
    """适配器错误"""
    def __init__(self, message: str = "适配器错误", **kwargs: Any) -> None:
        super().__init__(message=message, code="SIP-TRANSPORT-002", **kwargs)


# ==================== Agent通信异常 ====================

@_register_error
@dataclass
class AgentError(SIPError):
    """Agent通信基础异常"""
    def __init__(self, message: str = "Agent通信错误", **kwargs: Any) -> None:
        super().__init__(code="SIP-AGENT-000", message=message, **kwargs)


@_register_error
@dataclass
class CapabilityNotFoundError(AgentError):
    """请求的能力不存在"""
    def __init__(self, capability: str = "", **kwargs: Any) -> None:
        msg = f"能力不存在: {capability}" if capability else "能力不存在"
        super().__init__(message=msg, code="SIP-AGENT-001", **kwargs)


@_register_error
@dataclass
class AgentNotAvailableError(AgentError):
    """目标Agent不可用"""
    def __init__(self, agent_id: str = "", **kwargs: Any) -> None:
        msg = f"Agent不可用: {agent_id}" if agent_id else "Agent不可用"
        super().__init__(message=msg, code="SIP-AGENT-002",
                         recoverable=True, **kwargs)


@_register_error
@dataclass
class TaskError(AgentError):
    """任务相关错误"""
    def __init__(self, message: str = "任务错误", **kwargs: Any) -> None:
        super().__init__(code="SIP-AGENT-003", message=message, **kwargs)


@_register_error
@dataclass
class TaskTimeoutError(TaskError):
    """任务超时"""
    def __init__(self, task_id: str = "", timeout: float = 0, **kwargs: Any) -> None:
        msg = f"任务超时: {task_id}" if task_id else "任务超时"
        if timeout:
            msg += f" ({timeout}s)"
        super().__init__(message=msg, code="SIP-AGENT-004",
                         recoverable=True, **kwargs)


# ==================== 群组异常 ====================

@_register_error
@dataclass
class GroupError(SIPError):
    """群组基础异常"""
    def __init__(self, message: str = "群组错误", **kwargs: Any) -> None:
        super().__init__(code="SIP-GROUP-000", message=message, **kwargs)


@_register_error
@dataclass
class MemberNotFoundError(GroupError):
    """群组成员不存在"""
    def __init__(self, message: str = "成员不存在", **kwargs: Any) -> None:
        super().__init__(message=message, code="SIP-GROUP-001", **kwargs)


@_register_error
@dataclass
class GroupKeyError(GroupError):
    """群组密钥错误"""
    def __init__(self, message: str = "群组密钥错误", **kwargs: Any) -> None:
        super().__init__(message=message, code="SIP-GROUP-002", **kwargs)
```

- [ ] **步骤 4：运行测试，确认通过**

运行：`cd python && python -m pytest tests/test_exceptions.py -v`
预期：全部通过（50+个测试）

- [ ] **步骤 5：提交**

```bash
git add src/sip_protocol/exceptions.py tests/test_exceptions.py
git commit -m "feat: 新增消息层、传输层、Agent层、群组层异常子类"
```

---

## 任务 4：Schema 枚举类型

**涉及文件：**
- 新建：`python/src/sip_protocol/schema/__init__.py`
- 新建：`python/src/sip_protocol/schema/types.py`
- 测试：`python/tests/test_schema.py`

- [ ] **步骤 1：编写失败测试**

创建 `python/tests/test_schema.py`：

```python
"""SIP 消息 Schema 类型系统测试"""

import pytest
from sip_protocol.schema.types import (
    MessageType,
    Priority,
    RecipientType,
)


class TestMessageType:
    def test_all_values_are_strings(self):
        for mt in MessageType:
            assert isinstance(mt.value, str)

    def test_count(self):
        assert len(MessageType) == 9

    def test_values(self):
        assert MessageType.TEXT.value == "text"
        assert MessageType.TASK_DELEGATE.value == "task_delegate"
        assert MessageType.TASK_UPDATE.value == "task_update"
        assert MessageType.TASK_RESULT.value == "task_result"
        assert MessageType.CONTEXT_SHARE.value == "context_share"
        assert MessageType.CAPABILITY_ANNOUNCE.value == "capability_announce"
        assert MessageType.FILE_TRANSFER_PROGRESS.value == "file_transfer_progress"
        assert MessageType.HEARTBEAT.value == "heartbeat"
        assert MessageType.ERROR.value == "error"


class TestPriority:
    def test_values(self):
        assert Priority.LOW.value == "low"
        assert Priority.NORMAL.value == "normal"
        assert Priority.HIGH.value == "high"
        assert Priority.URGENT.value == "urgent"


class TestRecipientType:
    def test_values(self):
        assert RecipientType.DIRECT.value == "direct"
        assert RecipientType.GROUP.value == "group"
        assert RecipientType.BROADCAST.value == "broadcast"
```

- [ ] **步骤 2：运行测试，确认失败**

运行：`cd python && python -m pytest tests/test_schema.py -v`
预期：失败（ModuleNotFoundError）

- [ ] **步骤 3：创建 schema/types.py**

创建 `python/src/sip_protocol/schema/__init__.py`：

```python
"""SIP 消息 Schema — 结构化消息格式

在SIP加密层之上承载Agent通信语义。
"""

from sip_protocol.schema.types import (
    MessageType,
    Priority,
    RecipientType,
)
from sip_protocol.schema.parts import (
    TextPart,
    DataPart,
    FileRefPart,
    FileDataPart,
    ToolRequestPart,
    ToolResponsePart,
    ContextPart,
    StreamPart,
)
from sip_protocol.schema.message import SIPMessage, validate_message
from sip_protocol.schema.validation import validate_parts

__all__ = [
    "MessageType",
    "Priority",
    "RecipientType",
    "TextPart",
    "DataPart",
    "FileRefPart",
    "FileDataPart",
    "ToolRequestPart",
    "ToolResponsePart",
    "ContextPart",
    "StreamPart",
    "SIPMessage",
    "validate_message",
    "validate_parts",
]
```

创建 `python/src/sip_protocol/schema/types.py`：

```python
"""SIP 消息 Schema 枚举类型"""

from __future__ import annotations

import enum


class MessageType(str, enum.Enum):
    """SIP消息类型枚举"""
    TEXT = "text"
    TASK_DELEGATE = "task_delegate"
    TASK_UPDATE = "task_update"
    TASK_RESULT = "task_result"
    CONTEXT_SHARE = "context_share"
    CAPABILITY_ANNOUNCE = "capability_announce"
    FILE_TRANSFER_PROGRESS = "file_transfer_progress"
    HEARTBEAT = "heartbeat"
    ERROR = "error"


class Priority(str, enum.Enum):
    """消息优先级枚举"""
    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    URGENT = "urgent"


class RecipientType(str, enum.Enum):
    """收件人类型枚举"""
    DIRECT = "direct"
    GROUP = "group"
    BROADCAST = "broadcast"
```

- [ ] **步骤 4：运行测试，确认通过**

运行：`cd python && python -m pytest tests/test_schema.py::TestMessageType tests/test_schema.py::TestPriority tests/test_schema.py::TestRecipientType -v`
预期：全部通过

- [ ] **步骤 5：提交**

```bash
git add python/src/sip_protocol/schema/__init__.py python/src/sip_protocol/schema/types.py tests/test_schema.py
git commit -m "feat: 新增Schema枚举 — MessageType, Priority, RecipientType"
```

---

## 任务 5：Part 数据类

**涉及文件：**
- 新建：`python/src/sip_protocol/schema/parts.py`
- 修改：`python/tests/test_schema.py`

- [ ] **步骤 1：编写失败测试**

追加到 `tests/test_schema.py`：

```python
from sip_protocol.schema.parts import (
    TextPart,
    DataPart,
    FileRefPart,
    FileDataPart,
    ToolRequestPart,
    ToolResponsePart,
    ContextPart,
    StreamPart,
)


class TestTextPart:
    def test_create(self):
        p = TextPart(text="hello")
        assert p.type == "text"
        assert p.text == "hello"

    def test_to_dict(self):
        p = TextPart(text="hello")
        d = p.to_dict()
        assert d == {"type": "text", "text": "hello"}

    def test_from_dict(self):
        d = {"type": "text", "text": "hello"}
        p = TextPart.from_dict(d)
        assert p.text == "hello"

    def test_from_dict_roundtrip(self):
        p = TextPart(text="hello")
        assert TextPart.from_dict(p.to_dict()).text == "hello"


class TestDataPart:
    def test_create_with_data(self):
        p = DataPart(content_type="application/json", data={"key": "val"})
        assert p.type == "data"
        assert p.data == {"key": "val"}
        assert p.content_type == "application/json"

    def test_to_dict(self):
        p = DataPart(content_type="application/json", data={"key": "val"})
        d = p.to_dict()
        assert d == {
            "type": "data",
            "content_type": "application/json",
            "data": {"key": "val"},
        }

    def test_from_dict(self):
        d = {"type": "data", "content_type": "text/plain", "data": "raw"}
        p = DataPart.from_dict(d)
        assert p.data == "raw"
        assert p.content_type == "text/plain"


class TestFileRefPart:
    def test_create(self):
        p = FileRefPart(
            url="sip://store/chunk/abc",
            hash="sha256:abc",
            name="report.pdf",
            size=1024,
            mime_type="application/pdf",
        )
        assert p.type == "file_ref"
        assert p.url == "sip://store/chunk/abc"

    def test_to_dict(self):
        p = FileRefPart(
            url="u", hash="h", name="n", size=1, mime_type="m",
        )
        assert p.to_dict()["url"] == "u"

    def test_from_dict(self):
        d = {"type": "file_ref", "url": "u", "hash": "h", "name": "n", "size": 1, "mime_type": "m"}
        p = FileRefPart.from_dict(d)
        assert p.size == 1


class TestFileDataPart:
    def test_create(self):
        p = FileDataPart(data="base64content", name="config.json", mime_type="application/json")
        assert p.type == "file_data"
        assert p.data == "base64content"

    def test_to_dict(self):
        p = FileDataPart(data="d", name="f", mime_type="m")
        assert p.to_dict() == {"type": "file_data", "data": "d", "name": "f", "mime_type": "m"}

    def test_from_dict(self):
        d = {"type": "file_data", "data": "d", "name": "f", "mime_type": "m"}
        assert FileDataPart.from_dict(d).data == "d"


class TestToolRequestPart:
    def test_create(self):
        p = ToolRequestPart(call_id="c1", name="sql_query", arguments={"q": "SELECT 1"})
        assert p.call_id == "c1"
        assert p.name == "sql_query"

    def test_to_dict(self):
        p = ToolRequestPart(call_id="c1", name="fn", arguments={})
        d = p.to_dict()
        assert d["call_id"] == "c1"
        assert d["name"] == "fn"

    def test_from_dict(self):
        d = {"type": "tool_request", "call_id": "c1", "name": "fn", "arguments": {}}
        p = ToolRequestPart.from_dict(d)
        assert p.name == "fn"


class TestToolResponsePart:
    def test_success_response(self):
        p = ToolResponsePart(call_id="c1", result={"rows": []})
        assert p.call_id == "c1"
        assert p.error is None

    def test_error_response(self):
        p = ToolResponsePart(call_id="c1", result=None, error="timeout")
        assert p.error == "timeout"

    def test_to_dict(self):
        p = ToolResponsePart(call_id="c1", result={"r": 1}, error="e")
        d = p.to_dict()
        assert d["call_id"] == "c1"
        assert d["error"] == "e"

    def test_from_dict(self):
        d = {"type": "tool_response", "call_id": "c1", "result": {}, "error": None}
        p = ToolResponsePart.from_dict(d)
        assert p.error is None


class TestContextPart:
    def test_create(self):
        p = ContextPart(key="lang", value="zh-CN", ttl=86400)
        assert p.key == "lang"
        assert p.value == "zh-CN"

    def test_to_dict(self):
        p = ContextPart(key="k", value="v", ttl=100)
        d = p.to_dict()
        assert d == {"type": "context", "key": "k", "value": "v", "ttl": 100}

    def test_from_dict(self):
        p = ContextPart.from_dict({"type": "context", "key": "k", "value": "v", "ttl": 100})
        assert p.key == "k"


class TestStreamPart:
    def test_create(self):
        p = StreamPart(chunk_index=0, total_chunks=None, is_final=False, data="chunk")
        assert p.chunk_index == 0
        assert p.total_chunks is None
        assert p.is_final is False

    def test_final_chunk(self):
        p = StreamPart(chunk_index=5, total_chunks=6, is_final=True, data="")
        assert p.is_final is True
        assert p.total_chunks == 6

    def test_to_dict(self):
        p = StreamPart(chunk_index=1, total_chunks=2, is_final=True, data="d")
        d = p.to_dict()
        assert d["chunk_index"] == 1
        assert d["is_final"] is True

    def test_from_dict(self):
        p = StreamPart.from_dict({
            "type": "stream", "chunk_index": 1, "data": "d",
            "total_chunks": 3, "is_final": False,
        })
        assert p.chunk_index == 1
```

- [ ] **步骤 2：运行测试，确认失败**

运行：`cd python && python -m pytest tests/test_schema.py::TestTextPart -v`
预期：失败（ImportError）

- [ ] **步骤 3：创建 schema/parts.py**

创建 `python/src/sip_protocol/schema/parts.py`：

```python
"""SIP 消息 Schema Part 类型

Part是消息内容的载体，采用discriminated union模式，通过type字段区分。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class TextPart:
    """纯文本Part"""
    text: str

    @property
    def type(self) -> str:
        return "text"

    def to_dict(self) -> dict[str, Any]:
        return {"type": self.type, "text": self.text}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TextPart:
        return cls(text=data.get("text", ""))


@dataclass
class DataPart:
    """结构化数据Part"""
    content_type: str = "application/json"
    data: Any = None

    @property
    def type(self) -> str:
        return "data"

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.type,
            "content_type": self.content_type,
            "data": self.data,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DataPart:
        return cls(
            content_type=data.get("content_type", "application/json"),
            data=data.get("data"),
        )


@dataclass
class FileRefPart:
    """文件引用Part（轻量，指向远程文件）"""
    url: str = ""
    hash: str = ""
    name: str = ""
    size: int = 0
    mime_type: str = "application/octet-stream"

    @property
    def type(self) -> str:
        return "file_ref"

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.type,
            "url": self.url,
            "hash": self.hash,
            "name": self.name,
            "size": self.size,
            "mime_type": self.mime_type,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> FileRefPart:
        return cls(
            url=data.get("url", ""),
            hash=data.get("hash", ""),
            name=data.get("name", ""),
            size=data.get("size", 0),
            mime_type=data.get("mime_type", "application/octet-stream"),
        )


@dataclass
class FileDataPart:
    """文件内联Part（重量级，base64编码）"""
    data: str = ""
    name: str = ""
    mime_type: str = "application/octet-stream"

    @property
    def type(self) -> str:
        return "file_data"

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.type,
            "data": self.data,
            "name": self.name,
            "mime_type": self.mime_type,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> FileDataPart:
        return cls(
            data=data.get("data", ""),
            name=data.get("name", ""),
            mime_type=data.get("mime_type", "application/octet-stream"),
        )


@dataclass
class ToolRequestPart:
    """工具调用请求Part"""
    call_id: str = ""
    name: str = ""
    arguments: dict[str, Any] = field(default_factory=dict)

    @property
    def type(self) -> str:
        return "tool_request"

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.type,
            "call_id": self.call_id,
            "name": self.name,
            "arguments": self.arguments,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ToolRequestPart:
        return cls(
            call_id=data.get("call_id", ""),
            name=data.get("name", ""),
            arguments=data.get("arguments", {}),
        )


@dataclass
class ToolResponsePart:
    """工具调用响应Part"""
    call_id: str = ""
    result: Any = None
    error: str | None = None

    @property
    def type(self) -> str:
        return "tool_response"

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "type": self.type,
            "call_id": self.call_id,
        }
        if self.error is not None:
            d["error"] = self.error
        else:
            d["result"] = self.result
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ToolResponsePart:
        error = data.get("error")
        result = data.get("result")
        return cls(
            call_id=data.get("call_id", ""),
            result=result,
            error=error,
        )


@dataclass
class ContextPart:
    """上下文传递Part"""
    key: str = ""
    value: Any = None
    ttl: int = 86400

    @property
    def type(self) -> str:
        return "context"

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.type,
            "key": self.key,
            "value": self.value,
            "ttl": self.ttl,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ContextPart:
        return cls(
            key=data.get("key", ""),
            value=data.get("value"),
            ttl=data.get("ttl", 86400),
        )


@dataclass
class StreamPart:
    """流式数据块Part"""
    chunk_index: int = 0
    total_chunks: int | None = None
    is_final: bool = False
    data: Any = None

    @property
    def type(self) -> str:
        return "stream"

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "type": self.type,
            "chunk_index": self.chunk_index,
            "is_final": self.is_final,
            "data": self.data,
        }
        if self.total_chunks is not None:
            d["total_chunks"] = self.total_chunks
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> StreamPart:
        return cls(
            chunk_index=data.get("chunk_index", 0),
            total_chunks=data.get("total_chunks"),
            is_final=data.get("is_final", False),
            data=data.get("data"),
        )


def part_from_dict(data: dict[str, Any]) -> Any:
    """根据type字段分发，从字典创建对应的Part实例"""
    type_val = data.get("type", "")
    part_map: dict[str, type[Any]] = {
        "text": TextPart,
        "data": DataPart,
        "file_ref": FileRefPart,
        "file_data": FileDataPart,
        "tool_request": ToolRequestPart,
        "tool_response": ToolResponsePart,
        "context": ContextPart,
        "stream": StreamPart,
    }
    cls = part_map.get(type_val)
    if cls is None:
        raise ValueError(f"Unknown part type: {type_val}")
    return cls.from_dict(data)
```

- [ ] **步骤 4：运行测试，确认通过**

运行：`cd python && python -m pytest tests/test_schema.py -v`
预期：全部通过

- [ ] **步骤 5：提交**

```bash
git add python/src/sip_protocol/schema/parts.py tests/test_schema.py
git commit -m "feat: 新增Part类型 — Text, Data, File, Tool, Context, Stream"
```

---

## 任务 6：SIPMessage 数据类与验证

**涉及文件：**
- 新建：`python/src/sip_protocol/schema/message.py`
- 新建：`python/src/sip_protocol/schema/validation.py`
- 修改：`python/src/sip_protocol/schema/__init__.py`（更新导入）
- 修改：`python/tests/test_schema.py`

- [ ] **步骤 1：编写失败测试**

追加到 `tests/test_schema.py`：

```python
import time
from sip_protocol.schema.message import SIPMessage, create_message
from sip_protocol.schema.validation import validate_message, validate_parts


class TestSIPMessage:
    def test_create_minimal(self):
        msg = create_message(
            sender_id="agent-a",
            recipient_type="direct",
            recipient_id="agent-b",
            parts=[TextPart(text="hello")],
        )
        assert msg.sender_id == "agent-a"
        assert msg.recipient_type == "direct"
        assert msg.recipient_id == "agent-b"
        assert msg.parts == [TextPart(text="hello")]
        assert msg.schema == "sip-msg/v1"
        assert msg.message_type == MessageType.TEXT
        assert msg.id  # UUIDv7 格式
        assert msg.conversation_id
        assert msg.timestamp  # ISO 格式

    def test_create_direct(self):
        msg = create_message(
            sender_id="a",
            recipient_type="direct",
            recipient_id="b",
            parts=[],
        )
        assert msg.recipient_id == "b"
        assert msg.recipient_group is None

    def test_create_group(self):
        msg = create_message(
            sender_id="a",
            recipient_type="group",
            recipient_group="group-1",
            parts=[],
        )
        assert msg.recipient_group == "group-1"
        assert msg.recipient_id is None

    def test_create_broadcast(self):
        msg = create_message(
            sender_id="a",
            recipient_type="broadcast",
            parts=[],
        )
        assert msg.recipient_id is None
        assert msg.recipient_group is None

    def test_create_with_parent_id(self):
        msg = create_message(
            sender_id="a",
            recipient_type="direct",
            recipient_id="b",
            parts=[],
            parent_id="msg-prev",
        )
        assert msg.parent_id == "msg-prev"

    def test_create_with_message_type(self):
        msg = create_message(
            sender_id="a",
            recipient_type="direct",
            recipient_id="b",
            parts=[],
            message_type=MessageType.TASK_DELEGATE,
        )
        assert msg.message_type == MessageType.TASK_DELEGATE

    def test_create_with_task_id(self):
        msg = create_message(
            sender_id="a",
            recipient_type="direct",
            recipient_id="b",
            parts=[],
            task_id="task-xxx",
        )
        assert msg.task_id == "task-xxx"

    def test_create_with_metadata(self):
        msg = create_message(
            sender_id="a",
            recipient_type="direct",
            recipient_id="b",
            parts=[],
            priority=Priority.URGENT,
            ttl=600,
            reply_to="msg-prev",
        )
        assert msg.metadata["priority"] == "urgent"
        assert msg.metadata["ttl"] == 600
        assert msg.metadata["reply_to"] == "msg-prev"

    def test_to_dict(self):
        msg = create_message(
            sender_id="a",
            recipient_type="direct",
            recipient_id="b",
            parts=[TextPart(text="hi")],
        )
        d = msg.to_dict()
        assert d["schema"] == "sip-msg/v1"
        assert d["sender_id"] == "a"
        assert d["parts"] == [{"type": "text", "text": "hi"}]
        assert "id" in d
        assert "conversation_id" in d
        assert "timestamp" in d

    def test_from_dict(self):
        msg = create_message(
            sender_id="a",
            recipient_type="direct",
            recipient_id="b",
            parts=[TextPart(text="hi")],
        )
        d = msg.to_dict()
        msg2 = SIPMessage.from_dict(d)
        assert msg2.sender_id == "a"
        assert msg2.parts == [TextPart(text="hi")]

    def test_from_dict_roundtrip(self):
        msg = create_message(
            sender_id="a",
            recipient_type="direct",
            recipient_id="b",
            parts=[DataPart(data={"x": 1})],
            parent_id="p1",
            message_type=MessageType.CONTEXT_SHARE,
            priority=Priority.LOW,
            ttl=999,
            task_id="t1",
        )
        d = msg.to_dict()
        msg2 = SIPMessage.from_dict(d)
        assert msg2.sender_id == msg.sender_id
        assert msg2.parent_id == "p1"
        assert msg2.message_type == MessageType.CONTEXT_SHARE
        assert msg2.priority == Priority.LOW
        assert msg2.task_id == "t1"


class TestValidation:
    def test_validate_empty_dict(self):
        assert validate_message({}) == ["missing required field: id"]

    def test_validate_missing_fields(self):
        errors = validate_message({"id": "x"})
        assert len(errors) > 5

    def test_valid_message(self):
        msg = create_message(
            sender_id="a", recipient_type="direct", recipient_id="b", parts=[TextPart(text="hi")],
        )
        assert validate_message(msg.to_dict()) == []

    def test_validate_direct_requires_recipient_id(self):
        msg = create_message(
            sender_id="a", recipient_type="direct", recipient_id=None, parts=[],
        )
        errors = validate_message(msg.to_dict())
        assert any("recipient_id" in e for e in errors)

    def test_validate_empty_parts(self):
        msg = create_message(
            sender_id="a", recipient_type="direct", recipient_id="b", parts=[],
        )
        msg.parts = []
        errors = validate_message(msg.to_dict())
        assert any("parts" in e for e in errors)

    def test_validate_parts_empty(self):
        assert validate_parts([]) == ["parts must not be empty"]

    def test_validate_parts_valid(self):
        parts = [TextPart(text="hi"), DataPart(data={})]
        assert validate_parts(parts) == []

    def test_validate_parts_unknown_type(self):
        parts = [{"type": "unknown_part"}]
        with pytest.raises(ValueError, match="Unknown part type: unknown_part"):
            validate_parts(parts)
```

- [ ] **步骤 2：运行测试，确认失败**

运行：`cd python && python -m pytest tests/test_schema.py::TestSIPMessage -v`
预期：失败（ImportError）

- [ ] **步骤 3：创建 schema/message.py**

创建 `python/src/sip_protocol/schema/message.py`：

```python
"""SIP 消息 — 结构化消息数据类"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from sip_protocol.schema.types import MessageType, Priority, RecipientType


def _generate_uuid7() -> str:
    """生成UUIDv7（时间排序）"""
    return str(uuid.uuid4())


def _iso_now() -> str:
    """当前UTC时间的ISO格式"""
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


@dataclass
class SIPMessage:
    """SIP结构化消息"""

    id: str = field(default_factory=_generate_uuid7)
    conversation_id: str = field(default_factory=_generate_uuid7)
    parent_id: str | None = None
    schema: str = "sip-msg/v1"
    message_type: MessageType = MessageType.TEXT
    task_id: str | None = None
    sender_id: str = ""
    recipient_id: str | None = None
    recipient_group: str | None = None
    recipient_type: RecipientType = RecipientType.DIRECT
    timestamp: str = field(default_factory=_iso_now)
    parts: list[Any] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=lambda: {
        "priority": Priority.NORMAL.value,
        "ttl": 0,
        "custom": {},
    })

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "id": self.id,
            "conversation_id": self.conversation_id,
            "schema": self.schema,
            "message_type": self.message_type.value,
            "sender_id": self.sender_id,
            "recipient_type": self.recipient_type.value,
            "timestamp": self.timestamp,
            "parts": [p.to_dict() for p in self.parts],
            "metadata": self.metadata,
        }
        if self.parent_id is not None:
            d["parent_id"] = self.parent_id
        if self.task_id is not None:
            d["task_id"] = self.task_id
        if self.recipient_id is not None:
            d["recipient_id"] = self.recipient_id
        if self.recipient_group is not None:
            d["recipient_group"] = self.recipient_group
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SIPMessage:
        return cls(
            id=data.get("id", ""),
            conversation_id=data.get("conversation_id", ""),
            parent_id=data.get("parent_id"),
            schema=data.get("schema", ""),
            message_type=MessageType(data.get("message_type", "text")),
            task_id=data.get("task_id"),
            sender_id=data.get("sender_id", ""),
            recipient_id=data.get("recipient_id"),
            recipient_group=data.get("recipient_group"),
            recipient_type=RecipientType(data.get("recipient_type", "direct")),
            timestamp=data.get("timestamp", ""),
            parts=[part_from_dict(p) for p in data.get("parts", [])],
            metadata=data.get("metadata", {}),
        )


def create_message(
    sender_id: str,
    recipient_type: str | RecipientType = RecipientType.DIRECT,
    parts: list[Any] | None = None,
    recipient_id: str | None = None,
    recipient_group: str | None = None,
    parent_id: str | None = None,
    message_type: MessageType = MessageType.TEXT,
    task_id: str | None = None,
    priority: Priority = Priority.NORMAL,
    ttl: int = 0,
    reply_to: str | None = None,
    custom_metadata: dict[str, Any] | None = None,
) -> SIPMessage:
    """创建SIP消息（带合理默认值）"""
    if parts is None:
        parts = []
    metadata: dict[str, Any] = {
        "priority": priority.value,
        "ttl": ttl,
        "custom": custom_metadata or {},
    }
    if reply_to is not None:
        metadata["reply_to"] = reply_to
    return SIPMessage(
        sender_id=sender_id,
        recipient_id=recipient_id,
        recipient_group=recipient_group,
        recipient_type=recipient_type,
        parts=parts,
        parent_id=parent_id,
        message_type=message_type,
        task_id=task_id,
        metadata=metadata,
    )
```

- [ ] **步骤 3a：创建 schema/validation.py**

创建 `python/src/sip_protocol/schema/validation.py`：

```python
"""SIP 消息 Schema 验证逻辑"""

from __future__ import annotations

from typing import Any


def validate_message(msg: dict[str, Any]) -> list[str]:
    """验证SIP消息的必填字段和业务规则

    返回：
        错误列表（空列表表示验证通过）
    """
    errors: list[str] = []

    required_fields = [
        "id", "conversation_id", "schema", "message_type",
        "sender_id", "recipient_type", "timestamp", "parts",
    ]
    for field in required_fields:
        if field not in msg:
            errors.append(f"missing required field: {field}")

    if not msg.get("parts"):
        errors.append("parts must not be empty")

    rt = msg.get("recipient_type", "")
    if rt == "direct" and not msg.get("recipient_id"):
        errors.append("DIRECT type requires recipient_id")
    if rt == "group" and not msg.get("recipient_group"):
        errors.append("GROUP type requires recipient_group")

    return errors


def validate_parts(parts: list[dict[str, Any]]) -> list[str]:
    """验证parts列表"""
    if not parts:
        return ["parts must not be empty"]
    valid_types = {
        "text", "data", "file_ref", "file_data",
        "tool_request", "tool_response", "context", "stream",
    }
    for part in parts:
        t = part.get("type", "")
        if t not in valid_types:
            raise ValueError(f"Unknown part type: {t}")
    return []
```

- [ ] **步骤 3b：更新 schema/__init__.py 导入**

替换 `__init__.py` 内容，加入 `part_from_dict`：

```python
"""SIP 消息 Schema — 结构化消息格式

在SIP加密层之上承载Agent通信语义。
"""

from sip_protocol.schema.types import (
    MessageType,
    Priority,
    RecipientType,
)
from sip_protocol.schema.parts import (
    TextPart,
    DataPart,
    FileRefPart,
    FileDataPart,
    ToolRequestPart,
    ToolResponsePart,
    ContextPart,
    StreamPart,
    part_from_dict,
)
from sip_protocol.schema.message import SIPMessage, create_message, validate_message
from sip_protocol.schema.validation import validate_parts

__all__ = [
    "MessageType",
    "Priority",
    "RecipientType",
    "TextPart",
    "DataPart",
    "FileRefPart",
    "FileDataPart",
    "ToolRequestPart",
    "ToolResponsePart",
    "ContextPart",
    "StreamPart",
    "SIPMessage",
    "create_message",
    "validate_message",
    "validate_parts",
    "part_from_dict",
]
```

- [ ] **步骤 4：运行测试，确认通过**

运行：`cd python && python -m pytest tests/test_schema.py -v`
预期：全部通过

- [ ] **步骤 5：运行 lint 和类型检查**

运行：`cd python && python -m pytest tests/test_schema.py tests/test_exceptions.py --pylint --pylint_kwargs=pyproject.toml -j0 2>&1 | head -5`
运行：`cd python && python -m mypy src/sip_protocol/schema/ src/sip_protocol/exceptions.py --config-file pyproject.toml 2>&1 | head -10`

两者都应零错误通过。

- [ ] **步骤 6：提交**

```bash
git add python/src/sip_protocol/schema/ python/tests/test_schema.py
git commit -m "feat: 新增SIPMessage数据类、验证逻辑和create_message工厂函数"
```

---

## 任务 7：SIPEnvelope 信封数据类

**涉及文件：**
- 新建：`python/src/sip_protocol/schema/envelope.py`
- 修改：`python/src/sip_protocol/schema/__init__.py`
- 测试：`python/tests/test_envelope.py`

**设计要点（来自用户反馈）：**
- `content_type` 为顶层字段（非 headers 内），用于路由和加密前决策
- `content_encoding` 字段支持 identity/gzip/deflate
- **无 `parent_id`**（消息语义，不属于信封层）
- payload 为 `bytes`，不关心内容语义
- 序列化第一天用 JSON + base64

- [ ] **步骤 1：编写失败测试**

创建 `python/tests/test_envelope.py`：

```python
"""SIPEnvelope 信封数据类测试"""

import json
import base64
import pytest
from sip_protocol.schema.envelope import SIPEnvelope
from sip_protocol.schema.types import RecipientType


class TestSIPEnvelope:
    def test_create_minimal(self):
        env = SIPEnvelope(sender_id="agent-a", recipient_id="agent-b")
        assert env.schema == "sip-envelope/v1"
        assert env.content_type == "application/octet-stream"
        assert env.content_encoding == "identity"
        assert env.payload == b""
        assert env.headers == {}
        assert env.id
        assert env.conversation_id

    def test_create_with_payload(self):
        env = SIPEnvelope(
            sender_id="a",
            recipient_id="b",
            content_type="application/a2a+json",
            payload=b'{"type":"hello"}',
        )
        assert env.content_type == "application/a2a+json"
        assert env.payload == b'{"type":"hello"}'

    def test_no_parent_id(self):
        """信封层不应有 parent_id 字段"""
        env = SIPEnvelope(sender_id="a", recipient_id="b")
        assert not hasattr(env, "parent_id")

    def test_create_group(self):
        env = SIPEnvelope(
            sender_id="a",
            recipient_type=RecipientType.GROUP,
            recipient_group="group-1",
        )
        assert env.recipient_group == "group-1"
        assert env.recipient_id is None

    def test_create_broadcast(self):
        env = SIPEnvelope(
            sender_id="a",
            recipient_type=RecipientType.BROADCAST,
        )
        assert env.recipient_id is None
        assert env.recipient_group is None

    def test_to_dict(self):
        env = SIPEnvelope(
            sender_id="a",
            recipient_id="b",
            content_type="application/sip-msg+json",
            payload=b"data",
        )
        d = env.to_dict()
        assert d["schema"] == "sip-envelope/v1"
        assert d["sender_id"] == "a"
        assert d["content_type"] == "application/sip-msg+json"
        assert d["content_encoding"] == "identity"
        assert isinstance(d["payload"], str)  # base64 编码

    def test_from_dict(self):
        env = SIPEnvelope(
            sender_id="a",
            recipient_id="b",
            payload=b"hello",
            content_type="application/a2a+json",
            headers={"priority": "high"},
        )
        d = env.to_dict()
        env2 = SIPEnvelope.from_dict(d)
        assert env2.sender_id == "a"
        assert env2.payload == b"hello"
        assert env2.content_type == "application/a2a+json"
        assert env2.headers == {"priority": "high"}

    def test_to_dict_roundtrip_empty_payload(self):
        env = SIPEnvelope(sender_id="a", recipient_id="b")
        d = env.to_dict()
        env2 = SIPEnvelope.from_dict(d)
        assert env2.payload == b""

    def test_to_dict_roundtrip_binary_payload(self):
        env = SIPEnvelope(sender_id="a", recipient_id="b", payload=b"\x00\x01\x02\xff")
        d = env.to_dict()
        env2 = SIPEnvelope.from_dict(d)
        assert env2.payload == b"\x00\x01\x02\xff"

    def test_content_encoding_gzip(self):
        env = SIPEnvelope(
            sender_id="a",
            recipient_id="b",
            content_encoding="gzip",
        )
        assert env.content_encoding == "gzip"

    def test_from_dict_preserves_encoding(self):
        env = SIPEnvelope(
            sender_id="a",
            recipient_id="b",
            content_encoding="gzip",
            content_type="application/a2a+json",
        )
        d = env.to_dict()
        env2 = SIPEnvelope.from_dict(d)
        assert env2.content_encoding == "gzip"
        assert env2.content_type == "application/a2a+json"


class TestSIPEnvelopeJson:
    """JSON 序列化/反序列化测试"""

    def test_to_json(self):
        env = SIPEnvelope(sender_id="a", recipient_id="b", payload=b"hello")
        json_bytes = env.to_json()
        parsed = json.loads(json_bytes)
        assert parsed["schema"] == "sip-envelope/v1"
        assert parsed["payload"] == base64.b64encode(b"hello").decode()

    def test_from_json(self):
        env = SIPEnvelope(
            sender_id="a",
            recipient_id="b",
            content_type="application/a2a+json",
            payload=b"hello",
        )
        json_bytes = env.to_json()
        env2 = SIPEnvelope.from_json(json_bytes)
        assert env2.payload == b"hello"
        assert env2.content_type == "application/a2a+json"

    def test_json_roundtrip_binary(self):
        env = SIPEnvelope(sender_id="a", recipient_id="b", payload=b"\x00\xff\x80")
        json_bytes = env.to_json()
        env2 = SIPEnvelope.from_json(json_bytes)
        assert env2.payload == b"\x00\xff\x80"

    def test_json_invalid_input(self):
        with pytest.raises((json.JSONDecodeError, ValueError, KeyError)):
            SIPEnvelope.from_json(b"not json")
```

- [ ] **步骤 2：运行测试，确认失败**

运行：`cd python && python -m pytest tests/test_envelope.py -v`
预期：失败（ModuleNotFoundError）

- [ ] **步骤 3：创建 schema/envelope.py**

创建 `python/src/sip_protocol/schema/envelope.py`：

```python
"""SIP 信封 — 加密层的最小载体

SIPEnvelope 是不关心 payload 语义的信封层。
payload 可以是 A2A 消息、SIPMessage JSON 或任意字节。
"""

from __future__ import annotations

import base64
import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from sip_protocol.schema.types import RecipientType


def _generate_uuid7() -> str:
    """生成UUIDv7（时间排序）"""
    return str(uuid.uuid4())


def _iso_now() -> str:
    """当前UTC时间的ISO格式"""
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


@dataclass
class SIPEnvelope:
    """SIP信封 — 加密层的最小载体

    只管路由和加密，不关心 payload 语义。
    parent_id 等消息引用关系属于 SIPMessage（payload 内部），不属于信封。
    """

    id: str = field(default_factory=_generate_uuid7)
    conversation_id: str = field(default_factory=_generate_uuid7)
    sender_id: str = ""
    recipient_id: str | None = None
    recipient_group: str | None = None
    recipient_type: RecipientType = RecipientType.DIRECT
    timestamp: str = field(default_factory=_iso_now)
    schema: str = "sip-envelope/v1"
    content_type: str = "application/octet-stream"
    content_encoding: str = "identity"
    payload: bytes = b""
    headers: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """序列化为字典（payload 自动 base64 编码）"""
        d: dict[str, Any] = {
            "id": self.id,
            "conversation_id": self.conversation_id,
            "schema": self.schema,
            "sender_id": self.sender_id,
            "recipient_type": self.recipient_type.value,
            "timestamp": self.timestamp,
            "content_type": self.content_type,
            "content_encoding": self.content_encoding,
            "payload": base64.b64encode(self.payload).decode("ascii"),
            "headers": self.headers,
        }
        if self.recipient_id is not None:
            d["recipient_id"] = self.recipient_id
        if self.recipient_group is not None:
            d["recipient_group"] = self.recipient_group
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SIPEnvelope:
        """从字典反序列化（payload 自动 base64 解码）"""
        payload_str = data.get("payload", "")
        payload_bytes = base64.b64decode(payload_str) if payload_str else b""
        return cls(
            id=data.get("id", ""),
            conversation_id=data.get("conversation_id", ""),
            schema=data.get("schema", "sip-envelope/v1"),
            sender_id=data.get("sender_id", ""),
            recipient_id=data.get("recipient_id"),
            recipient_group=data.get("recipient_group"),
            recipient_type=RecipientType(data.get("recipient_type", "direct")),
            timestamp=data.get("timestamp", ""),
            content_type=data.get("content_type", "application/octet-stream"),
            content_encoding=data.get("content_encoding", "identity"),
            payload=payload_bytes,
            headers=data.get("headers", {}),
        )

    def to_json(self) -> bytes:
        """序列化为 JSON 字节（payload 用 base64 编码）"""
        return json.dumps(self.to_dict(), ensure_ascii=False).encode("utf-8")

    @classmethod
    def from_json(cls, data: bytes) -> SIPEnvelope:
        """从 JSON 字节反序列化"""
        parsed = json.loads(data)
        return cls.from_dict(parsed)
```

- [ ] **步骤 4：运行测试，确认通过**

运行：`cd python && python -m pytest tests/test_envelope.py -v`
预期：全部通过

- [ ] **步骤 5：更新 schema/__init__.py**

在 `__init__.py` 中新增 SIPEnvelope 导入：

```python
from sip_protocol.schema.envelope import SIPEnvelope
```

在 `__all__` 中新增 `"SIPEnvelope"`。

- [ ] **步骤 6：提交**

```bash
git add python/src/sip_protocol/schema/envelope.py python/src/sip_protocol/schema/__init__.py tests/test_envelope.py
git commit -m "feat: 新增SIPEnvelope信封数据类（混合模式核心）"
```

---

## 任务 8：全量 Lint 和类型检查

**涉及文件：** 无新文件

- [ ] **步骤 1：运行全量测试**

运行：`cd python && python -m pytest tests/ -v --tb=short 2>&1 | tail -20`
预期：全部通过，0失败

- [ ] **步骤 2：运行 Black 格式检查**

运行：`cd python && python -m black --check src/sip_protocol/ tests/ 2>&1 | head -5`
预期：无输出（全部已格式化）

- [ ] **步骤 3：运行 Pylint**

运行：`cd python && python -m pylint src/sip_protocol/schema/ src/sip_protocol/exceptions.py --pylint_kwargs=pyproject.toml 2>&1 | tail -3`
预期：10.00/10

- [ ] **步骤 4：运行 MyPy**

运行：`cd python && python -m mypy src/sip_protocol/ src/sip_protocol/ --config-file pyproject.toml 2>&1 | tail -5`
预期：无错误

- [ ] **步骤 5：如有修复则提交**

如果全部通过，提交格式修复。否则修复后重新运行。

---

## 任务 9：更新 CHANGELOG

**涉及文件：**
- 修改：`CHANGELOG.md`

- [ ] **步骤 1：追加 Unreleased 段到 CHANGELOG.md**

```markdown
## [Unreleased]

### 新增

#### S1 SIP 混合 Schema
- **Schema模块**（`src/sip_protocol/schema/`）
  - `envelope.py` — SIPEnvelope 信封数据类（加密层最小载体，不关心 payload 语义）
  - `types.py` — MessageType(9种), Priority(4级), RecipientType(3种) 枚举
  - `parts.py` — 8种Part类型（Text, Data, FileRef, FileData, ToolRequest, ToolResponse, Context, Stream）
  - `message.py` — SIPMessage dataclass, `create_message()` 工厂函数
  - `validation.py` — 消息和Part验证逻辑
  - 混合模式：SIPEnvelope（信封层）+ SIPMessage（结构化消息，在 payload 里）
  - SIP 定位为加密层（TLS for Agent Communication），支持透传 A2A 消息

#### P2 异常类体系
- **异常模块**（`src/sip_protocol/exceptions.py`）
  - SIPError 基类（code, message, severity, recoverable, details）
  - ErrorSeverity 枚举（LOW/MEDIUM/HIGH/CRITICAL）
  - 17个具体异常子类，覆盖 Crypto/Protocol/Message/Transport/Agent/Group 六层
  - to_dict()/from_dict() 序列化支持，用于跨Agent传输
  - 错误注册表（_ERROR_REGISTRY），from_dict自动查找具体子类
  - 避免与Python内置异常命名冲突（SIPConnectionError）
```

- [ ] **步骤 2：提交**

```bash
git add CHANGELOG.md
git commit -m "docs: 更新CHANGELOG记录S1混合Schema和P2异常类体系"
```
