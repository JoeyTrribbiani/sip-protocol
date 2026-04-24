"""
连接恢复模块
支持会话状态的序列化、反序列化和连接恢复
"""

import json
import base64
import time
import hmac
import hashlib
from typing import Dict
from dataclasses import dataclass, asdict

SESSION_TTL = 24 * 60 * 60  # 会话过期时间（24小时）


@dataclass
class SessionResumeState:
    """会话恢复状态"""

    session_id: str
    partner_id: str
    established_at: int
    encryption_key: str
    auth_key: str
    replay_key: str
    message_counter_send: int
    message_counter_receive: int
    last_rekey_sequence: int
    rekey_key_derived: bool


def serialize_session_state(state: SessionResumeState) -> str:
    """
    序列化会话状态为JSON字符串

    Args:
        state: 会话状态对象

    Returns:
        str: Base64编码的JSON字符串
    """
    # 转换为字典
    state_dict = asdict(state)

    # 序列化为JSON
    json_str = json.dumps(state_dict)

    # Base64编码
    serialized = base64.b64encode(json_str.encode()).decode()

    return serialized


def deserialize_session_state(serialized: str) -> SessionResumeState:
    """
    反序列化会话状态

    Args:
        serialized: Base64编码的JSON字符串

    Returns:
        SessionResumeState: 会话状态对象
    """
    # Base64解码
    json_str = base64.b64decode(serialized).decode()

    # 反序列化JSON
    state_dict = json.loads(json_str)

    # 转换为对象
    state = SessionResumeState(**state_dict)

    return state


def create_session_resume_message(
    session_state: SessionResumeState, next_message_counter: int
) -> Dict:
    """
    创建Session_Resume消息

    Args:
        session_state: 会话状态
        next_message_counter: 下一条消息的计数器

    Returns:
        Dict: Session_Resume消息
    """
    # 解码auth_key
    auth_key = (
        base64.b64decode(session_state.auth_key)
        if isinstance(session_state.auth_key, str)
        else session_state.auth_key
    )

    # 构建消息数据
    data = f"{session_state.session_id}:{next_message_counter}".encode()

    # 生成HMAC签名
    signature = hmac.new(auth_key, data, hashlib.sha256).digest()

    # 构建消息
    message = {
        "version": "SIP-1.0",
        "type": "session_resume",
        "timestamp": int(time.time() * 1000),
        "sender_id": session_state.session_id,
        "recipient_id": session_state.partner_id,
        "session_id": session_state.session_id,
        "message_counter": next_message_counter,
        "signature": base64.b64encode(signature).decode(),
    }

    return message


def verify_session_resume(message: Dict, auth_key: bytes) -> bool:
    """
    验证Session_Resume消息签名

    Args:
        message: Session_Resume消息
        auth_key: 当前auth_key

    Returns:
        bool: 是否有效
    """
    # 构建期望的数据
    data = f"{message['sender_id']}:{message['message_counter']}".encode()

    # 计算期望的签名
    expected_sig = hmac.new(auth_key, data, hashlib.sha256).digest()

    # 解码实际的签名
    actual_sig = base64.b64decode(message["signature"])

    # 比较签名
    return hmac.compare_digest(expected_sig, actual_sig)


def create_session_resume_ack_message(
    session_state: SessionResumeState, message_counter: int
) -> Dict:
    """
    创建Session_Resume_Ack消息

    Args:
        session_state: 会话状态
        message_counter: 确认的消息计数器

    Returns:
        Dict: Session_Resume_Ack消息
    """
    # 解码auth_key
    auth_key = (
        base64.b64decode(session_state.auth_key)
        if isinstance(session_state.auth_key, str)
        else session_state.auth_key
    )

    # 构建消息数据
    data = f"{session_state.session_id}:{message_counter}".encode()

    # 生成HMAC签名
    signature = hmac.new(auth_key, data, hashlib.sha256).digest()

    # 构建消息
    message = {
        "version": "SIP-1.0",
        "type": "session_resume_ack",
        "timestamp": int(time.time() * 1000),
        "sender_id": session_state.partner_id,
        "recipient_id": session_state.session_id,
        "session_id": session_state.session_id,
        "message_counter": message_counter,
        "signature": base64.b64encode(signature).decode(),
    }

    return message


def is_session_expired(session_state: SessionResumeState, ttl: int = SESSION_TTL) -> bool:
    """
    检查会话是否过期

    Args:
        session_state: 会话状态
        ttl: 过期时间（秒）

    Returns:
        bool: 是否过期
    """
    current_time = int(time.time())
    return current_time - session_state.established_at > ttl


def validate_message_counter(local_counter: int, remote_counter: int, max_diff: int = 1000) -> bool:
    """
    验证消息计数器是否有效

    Args:
        local_counter: 本地消息计数器
        remote_counter: 远程消息计数器
        max_diff: 允许的最大差异

    Returns:
        bool: 是否有效
    """
    diff = abs(local_counter - remote_counter)
    return diff <= max_diff
