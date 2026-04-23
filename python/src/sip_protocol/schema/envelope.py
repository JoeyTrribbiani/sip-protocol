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
