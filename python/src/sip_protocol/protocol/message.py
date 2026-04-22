"""
消息加密模块
实现消息加密和解密（XChaCha20-Poly1305）
"""

import base64
import hmac
import hashlib
import time
from typing import Optional
from ..crypto.xchacha20_poly1305 import (
    encrypt_xchacha20_poly1305,
    decrypt_xchacha20_poly1305,
    generate_nonce,
)

PROTOCOL_VERSION = "SIP-1.0"


def encrypt_message(
    encryption_key: bytes,
    plaintext: str,
    sender_id: str,
    recipient_id: str,
    message_counter: int,
    replay_key: Optional[bytes] = None,
) -> dict:
    """
    加密消息（XChaCha20-Poly1305）

    Args:
        encryption_key: 加密密钥
        plaintext: 明文消息
        sender_id: 发送方ID
        recipient_id: 接收方ID
        message_counter: 消息计数器
        replay_key: 防重放密钥（可选，用于生成replay_tag）

    Returns:
        dict: 加密后的消息
    """
    iv = generate_nonce()
    ciphertext, auth_tag = encrypt_xchacha20_poly1305(encryption_key, plaintext.encode(), iv)

    # 生成replay_tag（如果提供了replay_key）
    replay_tag = None
    if replay_key is not None:
        replay_tag = generate_replay_tag(replay_key, sender_id, message_counter)

    message = {
        "version": PROTOCOL_VERSION,
        "type": "message",  # 修改为文档要求的类型
        "timestamp": int(time.time() * 1000),
        "sender_id": sender_id,
        "recipient_id": recipient_id,  # 添加recipient_id字段
        "message_counter": message_counter,
        "iv": base64.b64encode(iv).decode(),
        "payload": base64.b64encode(ciphertext).decode(),  # 修改为payload（符合文档）
        "auth_tag": base64.b64encode(auth_tag).decode(),
    }

    # 添加replay_tag字段（如果生成了）
    if replay_tag is not None:
        message["replay_tag"] = replay_tag

    return message


def decrypt_message(encryption_key: bytes, message: dict) -> str:
    """
    解密消息（XChaCha20-Poly1305）

    Args:
        encryption_key: 解密密钥
        message: 加密的消息

    Returns:
        str: 明文消息

    Raises:
        Exception: 解密失败时抛出异常
    """
    iv = base64.b64decode(message["iv"])
    ciphertext = base64.b64decode(message["payload"])  # 修改为payload（符合文档）
    auth_tag = base64.b64decode(message["auth_tag"])

    try:
        plaintext = decrypt_xchacha20_poly1305(encryption_key, ciphertext, iv, auth_tag)
        return plaintext.decode()
    except Exception as error:
        raise ValueError(f"解密失败：{error}") from error


def generate_replay_tag(replay_key: bytes, sender_id: str, message_counter: int) -> str:
    """
    生成防重放标签

    Args:
        replay_key: 防重放密钥
        sender_id: 发送方ID
        message_counter: 消息计数器

    Returns:
        str: 防重放标签（十六进制）
    """
    data = f"{sender_id}:{message_counter}".encode()
    tag = hmac.new(replay_key, data, hashlib.sha256).digest()
    return tag.hex()


def verify_replay_tag(
    replay_key: bytes, sender_id: str, message_counter: int, replay_tag: str
) -> bool:
    """
    验证防重放标签

    Args:
        replay_key: 防重放密钥
        sender_id: 发送方ID
        message_counter: 消息计数器
        replay_tag: 消息中的replay_tag字段

    Returns:
        bool: 是否有效
    """
    expected_tag = generate_replay_tag(replay_key, sender_id, message_counter)
    return hmac.compare_digest(expected_tag, replay_tag)
