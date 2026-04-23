"""SIP 消息 Schema — 结构化消息格式

在SIP加密层之上承载Agent通信语义。
"""

from sip_protocol.schema.types import (
    MessageType,
    Priority,
    RecipientType,
)

__all__ = [
    "MessageType",
    "Priority",
    "RecipientType",
]
