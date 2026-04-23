"""SIP 消息 — 结构化消息数据类"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from sip_protocol.schema.parts import part_from_dict
from sip_protocol.schema.types import MessageType, Priority, RecipientType


def _generate_uuid7() -> str:
    """生成UUID（暂用uuid4占位，后续替换为uuid7）"""
    return str(uuid.uuid4())


def _iso_now() -> str:
    """返回当前UTC时间的ISO 8601格式字符串"""
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
    metadata: dict[str, Any] = field(
        default_factory=lambda: {"priority": Priority.NORMAL.value, "ttl": 0, "custom": {}}
    )

    def to_dict(self) -> dict[str, Any]:
        """序列化为字典"""
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
        for field_name in ("parent_id", "task_id", "recipient_id", "recipient_group"):
            val = getattr(self, field_name)
            if val is not None:
                d[field_name] = val
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SIPMessage:
        """从字典反序列化"""
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
