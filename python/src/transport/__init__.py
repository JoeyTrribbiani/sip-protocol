"""
SIP传输层模块
提供Agent间加密通信的适配层

包含：
- AgentMessage: Agent间通信的消息格式
- EncryptedChannel: 基于SIP加密库的安全通道
- OpenClawAdapter: OpenClaw平台集成适配器
"""

from .message import (
    AgentMessage,
    MessageType,
    MessagePriority,
    create_text_message,
    create_control_message,
    create_encrypted_message,
    parse_raw_message,
)
from .encrypted_channel import EncryptedChannel, ChannelState
from .openclaw_adapter import OpenClawAdapter

__all__ = [
    # 消息
    "AgentMessage",
    "MessageType",
    "MessagePriority",
    "create_text_message",
    "create_control_message",
    "create_encrypted_message",
    "parse_raw_message",
    # 通道
    "EncryptedChannel",
    "ChannelState",
    # 适配器
    "OpenClawAdapter",
]
