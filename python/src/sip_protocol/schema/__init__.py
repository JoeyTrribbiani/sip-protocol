"""SIP 消息 Schema — 结构化消息格式

在SIP加密层之上承载Agent通信语义。
"""

from sip_protocol.schema.message import SIPMessage, create_message
from sip_protocol.schema.parts import (
    ContextPart,
    DataPart,
    FileDataPart,
    FileRefPart,
    StreamPart,
    TextPart,
    ToolRequestPart,
    ToolResponsePart,
    part_from_dict,
)
from sip_protocol.schema.types import (
    MessageType,
    Priority,
    RecipientType,
)
from sip_protocol.schema.validation import validate_message, validate_parts

__all__ = [
    # 枚举类型
    "MessageType",
    "Priority",
    "RecipientType",
    # Part 类型
    "TextPart",
    "DataPart",
    "FileRefPart",
    "FileDataPart",
    "ToolRequestPart",
    "ToolResponsePart",
    "ContextPart",
    "StreamPart",
    "part_from_dict",
    # 消息与工厂
    "SIPMessage",
    "create_message",
    # 验证
    "validate_message",
    "validate_parts",
]
