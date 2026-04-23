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


# ==================== 错误注册表 ====================
# code -> 异常类，用于 from_dict 反序列化时查找正确的子类
_ERROR_REGISTRY: dict[str, type[SIPError]] = {}


def _register_error(cls: type[SIPError]) -> type[SIPError]:
    """将异常类注册到注册表（内部装饰器）

    使用默认值创建实例以提取默认 code，
    支持带有自定义 __init__ 签名的子类。
    """
    instance = cls()
    _ERROR_REGISTRY[instance.code] = cls
    return cls


# ==================== SIPError 基类 ====================


@_register_error
@dataclass
class SIPError(Exception):
    """SIP协议基础异常

    所有SIP协议异常的父类，提供统一的错误码、严重级别、可恢复性
    与序列化/反序列化能力。
    """

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
        """从字典反序列化为异常实例

        如果 code 已注册，返回对应的子类实例；
        否则返回基类 SIPError 实例。
        """
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


# ==================== 加密层异常 ====================


@_register_error
@dataclass
class CryptoError(SIPError):
    """加密层基础异常"""

    def __init__(self, message: str = "加密层错误", **kwargs: Any) -> None:
        kwargs.setdefault("code", "SIP-CRYPTO-000")
        super().__init__(message=message, **kwargs)


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
        super().__init__(message=message, code="SIP-CRYPTO-002", recoverable=False, **kwargs)


@_register_error
@dataclass
class KeyDerivationError(CryptoError):
    """密钥派生失败"""

    def __init__(self, message: str = "密钥派生失败", **kwargs: Any) -> None:
        super().__init__(message=message, code="SIP-CRYPTO-003", recoverable=False, **kwargs)


# ==================== 协议层异常 ====================


@_register_error
@dataclass
class ProtocolError(SIPError):
    """协议层基础异常"""

    def __init__(self, message: str = "协议层错误", **kwargs: Any) -> None:
        kwargs.setdefault("code", "SIP-PROTO-000")
        super().__init__(message=message, **kwargs)


@_register_error
@dataclass
class HandshakeError(ProtocolError):
    """握手失败"""

    def __init__(self, message: str = "握手失败", **kwargs: Any) -> None:
        super().__init__(message=message, code="SIP-PROTO-001", recoverable=True, **kwargs)


@_register_error
@dataclass
class RekeyError(ProtocolError):
    """密钥轮换失败"""

    def __init__(self, message: str = "密钥轮换失败", **kwargs: Any) -> None:
        super().__init__(message=message, code="SIP-PROTO-002", recoverable=True, **kwargs)


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


# ==================== 消息层异常 ====================


@_register_error
@dataclass
class MessageError(SIPError):
    """消息层基础异常"""

    def __init__(self, message: str = "消息层错误", **kwargs: Any) -> None:
        kwargs.setdefault("code", "SIP-MSG-000")
        super().__init__(message=message, **kwargs)


@_register_error
@dataclass
class MessageSchemaError(MessageError):
    """消息Schema验证失败"""

    def __init__(self, message: str = "消息Schema验证失败", **kwargs: Any) -> None:
        kwargs.setdefault("code", "SIP-MSG-001")
        super().__init__(message=message, **kwargs)


@_register_error
@dataclass
class MessageExpiredError(MessageError):
    """消息已过期"""

    def __init__(self, message: str = "消息已过期", **kwargs: Any) -> None:
        kwargs.setdefault("code", "SIP-MSG-002")
        super().__init__(message=message, **kwargs)


# ==================== 传输层异常 ====================


@_register_error
@dataclass
class TransportError(SIPError):
    """传输层基础异常"""

    def __init__(self, message: str = "传输层错误", **kwargs: Any) -> None:
        kwargs.setdefault("code", "SIP-TRANSPORT-000")
        super().__init__(message=message, **kwargs)


@_register_error
@dataclass
class SIPConnectionError(TransportError):
    """连接失败（SIP前缀避免与内置ConnectionError冲突）"""

    def __init__(self, message: str = "连接失败", **kwargs: Any) -> None:
        kwargs.setdefault("code", "SIP-TRANSPORT-001")
        kwargs.setdefault("recoverable", True)
        super().__init__(message=message, **kwargs)


@_register_error
@dataclass
class AdapterError(TransportError):
    """适配器错误"""

    def __init__(self, message: str = "适配器错误", **kwargs: Any) -> None:
        kwargs.setdefault("code", "SIP-TRANSPORT-002")
        super().__init__(message=message, **kwargs)


# ==================== Agent通信异常 ====================


@_register_error
@dataclass
class AgentError(SIPError):
    """Agent通信基础异常"""

    def __init__(self, message: str = "Agent通信错误", **kwargs: Any) -> None:
        kwargs.setdefault("code", "SIP-AGENT-000")
        super().__init__(message=message, **kwargs)


@_register_error
@dataclass
class CapabilityNotFoundError(AgentError):
    """请求的能力不存在"""

    def __init__(self, capability: str = "", **kwargs: Any) -> None:
        msg = f"能力不存在: {capability}" if capability else "能力不存在"
        kwargs.setdefault("code", "SIP-AGENT-001")
        super().__init__(message=msg, **kwargs)


@_register_error
@dataclass
class AgentNotAvailableError(AgentError):
    """目标Agent不可用"""

    def __init__(self, agent_id: str = "", **kwargs: Any) -> None:
        msg = f"Agent不可用: {agent_id}" if agent_id else "Agent不可用"
        kwargs.setdefault("recoverable", True)
        kwargs.setdefault("code", "SIP-AGENT-002")
        super().__init__(message=msg, **kwargs)


@_register_error
@dataclass
class TaskError(AgentError):
    """任务相关错误"""

    def __init__(self, message: str = "任务错误", **kwargs: Any) -> None:
        kwargs.setdefault("code", "SIP-AGENT-003")
        super().__init__(message=message, **kwargs)


@_register_error
@dataclass
class TaskTimeoutError(TaskError):
    """任务超时"""

    def __init__(self, task_id: str = "", timeout: float = 0, **kwargs: Any) -> None:
        msg = f"任务超时: {task_id}" if task_id else "任务超时"
        if timeout:
            msg += f" ({timeout}s)"
        kwargs.setdefault("recoverable", True)
        kwargs.setdefault("code", "SIP-AGENT-004")
        super().__init__(message=msg, **kwargs)


# ==================== 群组异常 ====================


@_register_error
@dataclass
class GroupError(SIPError):
    """群组基础异常"""

    def __init__(self, message: str = "群组错误", **kwargs: Any) -> None:
        kwargs.setdefault("code", "SIP-GROUP-000")
        super().__init__(message=message, **kwargs)


@_register_error
@dataclass
class MemberNotFoundError(GroupError):
    """群组成员不存在"""

    def __init__(self, member_id: str = "", **kwargs: Any) -> None:
        msg = f"成员不存在: {member_id}" if member_id else "成员不存在"
        kwargs.setdefault("code", "SIP-GROUP-001")
        super().__init__(message=msg, **kwargs)


@_register_error
@dataclass
class GroupKeyError(GroupError):
    """群组密钥错误"""

    def __init__(self, message: str = "群组密钥错误", **kwargs: Any) -> None:
        kwargs.setdefault("code", "SIP-GROUP-002")
        super().__init__(message=message, **kwargs)
