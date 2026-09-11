"""
Agent消息格式模块
定义Agent间通信的标准消息格式

支持三种消息类型：
1. TEXT - 普通文本消息
2. ENCRYPTED - SIP加密消息
3. CONTROL - 控制消息（握手、心跳、断开等）

所有消息使用JSON格式，便于调试和跨平台兼容。
"""

import json
import time
import uuid
from enum import Enum
from typing import Any, Dict, Optional
from dataclasses import dataclass, field, asdict


class MessageType(str, Enum):
    """消息类型枚举"""

    TEXT = "text"
    ENCRYPTED = "encrypted"
    CONTROL = "control"


class MessagePriority(int, Enum):
    """消息优先级"""

    LOW = 0
    NORMAL = 1
    HIGH = 2
    URGENT = 3


class ControlAction(str, Enum):
    """控制消息动作"""

    HELLO = "hello"
    HEARTBEAT = "heartbeat"
    HEARTBEAT_ACK = "heartbeat_ack"
    DISCONNECT = "disconnect"
    ACK = "ack"
    ERROR = "error"
    HANDSHAKE_INIT = "handshake_init"
    HANDSHAKE_COMPLETE = "handshake_complete"
    REKEY_REQUEST = "rekey_request"
    REKEY_RESPONSE = "rekey_response"


@dataclass
class AgentMessage:
    """
    Agent间通信的标准消息格式

    Attributes:
        id: 消息唯一ID (UUID v4)
        version: 协议版本
        type: 消息类型
        sender_id: 发送方Agent ID
        recipient_id: 接收方Agent ID
        timestamp: 消息时间戳 (Unix毫秒)
        payload: 消息内容
        priority: 消息优先级
        metadata: 元数据 (可选)
        correlation_id: 关联消息ID (用于请求-响应模式)
        hop_count: 跳数计数 (用于三方通信追踪)
        max_hops: 最大跳数限制
    """

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    version: str = "SIP-TRANSPORT-1.0"
    type: MessageType = MessageType.TEXT
    sender_id: str = ""
    recipient_id: str = ""
    timestamp: int = field(default_factory=lambda: int(time.time() * 1000))
    payload: Dict[str, Any] = field(default_factory=dict)
    priority: MessagePriority = MessagePriority.NORMAL
    metadata: Dict[str, Any] = field(default_factory=dict)
    correlation_id: Optional[str] = None
    hop_count: int = 0
    max_hops: int = 10

    def to_dict(self) -> Dict[str, Any]:
        """序列化为字典"""
        d = asdict(self)
        d["type"] = self.type.value
        d["priority"] = self.priority.value
        # 清除空字段
        if self.correlation_id is None:
            del d["correlation_id"]
        return d

    def to_json(self) -> str:
        """序列化为JSON字符串"""
        return json.dumps(self.to_dict(), ensure_ascii=False, separators=(",", ":"))

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AgentMessage":
        """从字典反序列化"""
        # 处理枚举类型
        if isinstance(data.get("type"), str):
            data["type"] = MessageType(data["type"])
        if isinstance(data.get("priority"), int):
            data["priority"] = MessagePriority(data["priority"])
        return cls(**data)

    @classmethod
    def from_json(cls, json_str: str) -> "AgentMessage":
        """从JSON字符串反序列化"""
        data = json.loads(json_str)
        return cls.from_dict(data)

    def is_expired(self, ttl_ms: int = 5 * 60 * 1000) -> bool:
        """检查消息是否过期（默认5分钟TTL）"""
        now = int(time.time() * 1000)
        return (now - self.timestamp) > ttl_ms

    def is_max_hops_reached(self) -> bool:
        """检查是否达到最大跳数"""
        return self.hop_count >= self.max_hops

    def increment_hop(self) -> "AgentMessage":
        """增加跳数并返回自身"""
        self.hop_count += 1
        return self

    def create_reply(
        self, payload: Dict[str, Any], msg_type: Optional[MessageType] = None
    ) -> "AgentMessage":
        """创建回复消息"""
        return AgentMessage(
            version=self.version,
            type=msg_type or self.type,
            sender_id=self.recipient_id,
            recipient_id=self.sender_id,
            payload=payload,
            correlation_id=self.id,
            priority=self.priority,
        )


# ──────────────────────────── 工厂函数 ────────────────────────────


def create_text_message(
    sender_id: str,
    recipient_id: str,
    text: str,
    metadata: Optional[Dict[str, Any]] = None,
    priority: MessagePriority = MessagePriority.NORMAL,
) -> AgentMessage:
    """
    创建文本消息

    Args:
        sender_id: 发送方ID
        recipient_id: 接收方ID
        text: 文本内容
        metadata: 元数据
        priority: 优先级

    Returns:
        AgentMessage: 文本消息
    """
    return AgentMessage(
        type=MessageType.TEXT,
        sender_id=sender_id,
        recipient_id=recipient_id,
        payload={"text": text},
        metadata=metadata or {},
        priority=priority,
    )


def create_control_message(
    sender_id: str,
    recipient_id: str,
    action: ControlAction,
    data: Optional[Dict[str, Any]] = None,
    correlation_id: Optional[str] = None,
) -> AgentMessage:
    """
    创建控制消息

    Args:
        sender_id: 发送方ID
        recipient_id: 接收方ID
        action: 控制动作
        data: 附加数据
        correlation_id: 关联ID

    Returns:
        AgentMessage: 控制消息
    """
    payload: Dict[str, Any] = {"action": action.value}
    if data:
        payload["data"] = data
    return AgentMessage(
        type=MessageType.CONTROL,
        sender_id=sender_id,
        recipient_id=recipient_id,
        payload=payload,
        correlation_id=correlation_id,
        priority=MessagePriority.HIGH,
    )


def create_encrypted_message(
    sender_id: str,
    recipient_id: str,
    encrypted_payload: Dict[str, Any],
    metadata: Optional[Dict[str, Any]] = None,
) -> AgentMessage:
    """
    创建加密消息（包装已加密的SIP payload）

    Args:
        sender_id: 发送方ID
        recipient_id: 接收方ID
        encrypted_payload: 已加密的payload（包含iv, payload, auth_tag, replay_tag等）
        metadata: 元数据

    Returns:
        AgentMessage: 加密消息
    """
    return AgentMessage(
        type=MessageType.ENCRYPTED,
        sender_id=sender_id,
        recipient_id=recipient_id,
        payload=encrypted_payload,
        metadata=metadata or {},
    )


def parse_raw_message(raw: str) -> AgentMessage:
    """
    解析原始消息字符串

    Args:
        raw: JSON格式的消息字符串

    Returns:
        AgentMessage: 解析后的消息

    Raises:
        ValueError: 消息格式无效
    """
    try:
        return AgentMessage.from_json(raw)
    except (json.JSONDecodeError, KeyError, ValueError) as e:
        raise ValueError(f"无效的消息格式: {e}") from e
