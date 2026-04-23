# SIP 异常类体系设计文档

> 版本: v1.0
> 日期: 2026-04-22
> 状态: 已批准
> 关联: P2 (sip-protocol-report.md Section 8.3.3 差距7)

## 1. 问题陈述

当前SIP协议的异常处理存在两个问题：
1. 所有错误都是通用的 `ValueError`/`Exception`，不区分Agent通信场景
2. 异常无法跨Agent传输（没有结构化序列化能力）

需要建立一套分层、可序列化、与SIP协议栈对齐的异常体系。

## 2. 设计原则

1. **分层对齐** — 异常层次与SIP协议栈（Crypto → Protocol → Message → Transport → Agent）对应
2. **三要素** — 每个异常包含 `code`（机器可读）、`message`（人类可读）、`recoverable`（是否可恢复）
3. **可序列化** — 所有异常支持 `.to_dict()` → JSON，用于跨Agent传输
4. **不隐藏内置异常** — 命名避免与Python内置异常冲突

## 3. 异常层次结构

```
SIPError (基类)
├── CryptoError
│   ├── EncryptionError
│   ├── DecryptionError
│   └── KeyDerivationError
├── ProtocolError
│   ├── HandshakeError
│   ├── RekeyError
│   ├── VersionNegotiationError
│   └── FragmentError
├── MessageError
│   ├── MessageSchemaError
│   └── MessageExpiredError
├── TransportError
│   ├── SIPConnectionError        # 注意：避免与内置ConnectionError冲突
│   └── AdapterError
├── AgentError
│   ├── CapabilityNotFoundError
│   ├── AgentNotAvailableError
│   └── TaskError
│       ├── TaskTimeoutError
│       └── TaskCancelledError
└── GroupError
    ├── MemberNotFoundError
    └── GroupKeyError
```

## 4. 基类定义

```python
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Any


class ErrorSeverity(str, Enum):
    LOW = "low"           # 警告级别，不影响通信
    MEDIUM = "medium"     # 功能降级，通信可继续
    HIGH = "high"         # 严重错误，当前操作失败
    CRITICAL = "critical" # 致命错误，通道不可用


@dataclass
class SIPError(Exception):
    """SIP协议基础异常"""

    code: str                                    # 机器可读错误码
    message: str                                 # 人类可读描述
    severity: ErrorSeverity = ErrorSeverity.MEDIUM
    recoverable: bool = True                     # 是否可恢复
    details: dict[str, Any] = field(default_factory=dict)

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
    def from_dict(cls, data: dict[str, Any]) -> "SIPError":
        """从字典反序列化"""
        # 查找具体的异常子类
        error_cls = _ERROR_REGISTRY.get(data.get("code", ""))
        if error_cls is None:
            error_cls = SIPError
        return error_cls(
            code=data["code"],
            message=data["message"],
            severity=ErrorSeverity(data.get("severity", "medium")),
            recoverable=data.get("recoverable", True),
            details=data.get("details", {}),
        )
```

## 5. 错误码规范

格式：`SIP-<层>-<序号>`

| 层 | 前缀 | 示例 |
|----|------|------|
| Crypto | `CRYPTO` | `SIP-CRYPTO-001` |
| Protocol | `PROTO` | `SIP-PROTO-001` |
| Message | `MSG` | `SIP-MSG-001` |
| Transport | `TRANSPORT` | `SIP-TRANSPORT-001` |
| Agent | `AGENT` | `SIP-AGENT-001` |
| Group | `GROUP` | `SIP-GROUP-001` |

## 6. 具体异常定义

### 6.1 加密层

```python
@dataclass
class CryptoError(SIPError):
    """加密层基础异常"""
    def __init__(self, message: str, **kwargs):
        super().__init__(code="SIP-CRYPTO-000", message=message, **kwargs)


@dataclass
class EncryptionError(CryptoError):
    """加密失败"""
    def __init__(self, message: str = "加密失败", **kwargs):
        super().__init__(message=message, code="SIP-CRYPTO-001", **kwargs)


@dataclass
class DecryptionError(CryptoError):
    """解密失败"""
    def __init__(self, message: str = "解密失败", **kwargs):
        super().__init__(message=message, code="SIP-CRYPTO-002",
                         recoverable=False, **kwargs)


@dataclass
class KeyDerivationError(CryptoError):
    """密钥派生失败"""
    def __init__(self, message: str = "密钥派生失败", **kwargs):
        super().__init__(message=message, code="SIP-CRYPTO-003",
                         recoverable=False, **kwargs)
```

### 6.2 协议层

```python
@dataclass
class ProtocolError(SIPError):
    """协议层基础异常"""
    def __init__(self, message: str, **kwargs):
        super().__init__(code="SIP-PROTO-000", message=message, **kwargs)


@dataclass
class HandshakeError(ProtocolError):
    """握手失败"""
    def __init__(self, message: str = "握手失败", **kwargs):
        super().__init__(message=message, code="SIP-PROTO-001",
                         recoverable=True, **kwargs)


@dataclass
class RekeyError(ProtocolError):
    """密钥轮换失败"""
    def __init__(self, message: str = "密钥轮换失败", **kwargs):
        super().__init__(message=message, code="SIP-PROTO-002",
                         recoverable=True, **kwargs)
```

### 6.3 传输层（避免命名冲突）

```python
@dataclass
class TransportError(SIPError):
    """传输层基础异常"""
    def __init__(self, message: str, **kwargs):
        super().__init__(code="SIP-TRANSPORT-000", message=message, **kwargs)


@dataclass
class SIPConnectionError(TransportError):
    """连接失败（使用SIP前缀避免与内置ConnectionError冲突）"""
    def __init__(self, message: str = "连接失败", **kwargs):
        super().__init__(message=message, code="SIP-TRANSPORT-001",
                         recoverable=True, **kwargs)


@dataclass
class AdapterError(TransportError):
    """适配器错误"""
    def __init__(self, message: str = "适配器错误", **kwargs):
        super().__init__(message=message, code="SIP-TRANSPORT-002", **kwargs)
```

### 6.4 Agent通信特定

```python
@dataclass
class AgentError(SIPError):
    """Agent通信基础异常"""
    def __init__(self, message: str, **kwargs):
        super().__init__(code="SIP-AGENT-000", message=message, **kwargs)


@dataclass
class CapabilityNotFoundError(AgentError):
    """请求的能力不存在"""
    def __init__(self, capability: str = "", **kwargs):
        super().__init__(
            message=f"能力不存在: {capability}" if capability else "能力不存在",
            code="SIP-AGENT-001",
            **kwargs,
        )


@dataclass
class AgentNotAvailableError(AgentError):
    """目标Agent不可用"""
    def __init__(self, agent_id: str = "", **kwargs):
        super().__init__(
            message=f"Agent不可用: {agent_id}" if agent_id else "Agent不可用",
            code="SIP-AGENT-002",
            recoverable=True,
            **kwargs,
        )


@dataclass
class TaskError(AgentError):
    """任务相关错误"""
    def __init__(self, message: str, **kwargs):
        super().__init__(code="SIP-AGENT-003", message=message, **kwargs)


@dataclass
class TaskTimeoutError(TaskError):
    """任务超时"""
    def __init__(self, task_id: str = "", timeout: float = 0, **kwargs):
        msg = f"任务超时: {task_id}" if task_id else "任务超时"
        if timeout:
            msg += f" ({timeout}s)"
        super().__init__(message=msg, code="SIP-AGENT-004",
                         recoverable=True, **kwargs)
```

## 7. 错误注册表

用于 `from_dict` 反序列化时查找具体异常类：

```python
_ERROR_REGISTRY: dict[str, type[SIPError]] = {}

def _register_error(cls: type[SIPError]) -> type[SIPError]:
    """注册异常类到注册表"""
    _ERROR_REGISTRY[cls("").code] = cls  # type: ignore
    return cls
```

所有具体异常类都通过 `@_register_error` 装饰器注册。

## 8. 跨Agent错误传输

Agent收到错误后可以将其包装为SIP消息发回：

```python
def make_error_message(
    sender_id: str,
    error: SIPError,
    parent_id: str | None = None,
) -> dict:
    return {
        "id": generate_uuid7(),
        "conversation_id": "",
        "schema": "sip-msg/v1",
        "message_type": MessageType.ERROR,
        "sender_id": sender_id,
        "recipient_type": RecipientType.DIRECT,
        "timestamp": datetime.now(UTC).isoformat(),
        "parts": [
            {"type": "data", "content_type": "application/sip-error",
             "data": error.to_dict()}
        ],
        "metadata": {"priority": Priority.HIGH},
        **({"parent_id": parent_id} if parent_id else {}),
    }
```

## 9. 模块位置

```
python/src/sip_protocol/
├── exceptions.py            # 所有异常类定义
├── exceptions/__init__.py   # 公共导出
```

由于异常是跨层使用的，放在包根目录而非子模块中。
