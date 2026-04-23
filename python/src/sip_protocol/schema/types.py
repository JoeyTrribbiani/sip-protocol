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
