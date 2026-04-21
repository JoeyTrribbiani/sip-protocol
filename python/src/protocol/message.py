"""
消息加密模块
实现消息加密和解密
"""

import base64
import hmac
import hashlib
import time
from ..crypto.aes_gcm import encrypt_aes_gcm, decrypt_aes_gcm, AES_GCM_NONCE_LENGTH

PROTOCOL_VERSION = "SIP-1.0"


def encrypt_message(
    encryption_key: bytes, plaintext: str, sender_id: str, message_counter: int
) -> dict:
    """
    加密消息

    Args:
        encryption_key: 加密密钥
        plaintext: 明文消息
        sender_id: 发送方ID
        message_counter: 消息计数器

    Returns:
        dict: 加密后的消息
    """
    import os

    iv = os.urandom(AES_GCM_NONCE_LENGTH)
    ciphertext, auth_tag = encrypt_aes_gcm(encryption_key, plaintext.encode(), iv)

    message = {
        "version": PROTOCOL_VERSION,
        "type": "encrypted_message",
        "sender_id": sender_id,
        "message_counter": message_counter,
        "nonce": base64.b64encode(iv).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "auth_tag": base64.b64encode(auth_tag).decode(),
        "timestamp": int(time.time() * 1000),
    }

    return message


def decrypt_message(encryption_key: bytes, message: dict) -> str:
    """
    解密消息

    Args:
        encryption_key: 解密密钥
        message: 加密的消息

    Returns:
        str: 明文消息

    Raises:
        Exception: 解密失败时抛出异常
    """
    iv = base64.b64decode(message["nonce"])
    ciphertext = base64.b64decode(message["ciphertext"])
    auth_tag = base64.b64decode(message["auth_tag"])

    try:
        plaintext = decrypt_aes_gcm(encryption_key, ciphertext, iv, auth_tag)
        return plaintext.decode()
    except Exception as error:
        raise Exception(f"解密失败：{error}")


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
