"""
消息加密模块
实现消息加密和解密（EN → ChaCha20-Poly1305；ZH → SM4-GCM）

suite 语义（SPEC v1.1 §6.1）：加密侧经参数指定；解密侧自描述——
ZH 消息字典携带 suite 字段，缺省视为 EN（向后兼容，旧消息无此字段）。
replay_tag 的 HMAC 摘要随套件分派（SHA256 / SM3）。
"""

import base64
import hmac
import time
from typing import Optional
from ..crypto.suite import SUITE_EN, digestmod, validate_suite
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
    suite: str = SUITE_EN,
) -> dict:
    """
    加密消息（按套件分派：EN → ChaCha20-Poly1305；ZH → SM4-GCM）

    Args:
        encryption_key: 加密密钥（EN 32字节；ZH 16字节）
        plaintext: 明文消息
        sender_id: 发送方ID
        recipient_id: 接收方ID
        message_counter: 消息计数器
        replay_key: 防重放密钥（可选，用于生成replay_tag）
        suite: 密码套件（ZH 时消息字典携带 suite 字段；EN wire 不变）

    Returns:
        dict: 加密后的消息
    """
    validate_suite(suite)
    iv = generate_nonce()
    ciphertext, auth_tag = encrypt_xchacha20_poly1305(
        encryption_key, plaintext.encode(), iv, None, suite
    )

    # 生成replay_tag（如果提供了replay_key）
    replay_tag = None
    if replay_key is not None:
        replay_tag = generate_replay_tag(replay_key, sender_id, message_counter, suite)

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

    # ZH 显式声明套件（解密侧自描述）；EN 不加字段——wire 逐字节不变
    if suite != SUITE_EN:
        message["suite"] = suite

    # 添加replay_tag字段（如果生成了）
    if replay_tag is not None:
        message["replay_tag"] = replay_tag

    return message


def decrypt_message(encryption_key: bytes, message: dict) -> str:
    """
    解密消息（套件自描述：message 的 suite 字段缺省 EN）

    Args:
        encryption_key: 解密密钥
        message: 加密的消息

    Returns:
        str: 明文消息

    Raises:
        Exception: 解密失败时抛出异常
    """
    suite = validate_suite(message.get("suite", SUITE_EN))
    iv = base64.b64decode(message["iv"])
    ciphertext = base64.b64decode(message["payload"])  # 修改为payload（符合文档）
    auth_tag = base64.b64decode(message["auth_tag"])

    try:
        plaintext = decrypt_xchacha20_poly1305(
            encryption_key, ciphertext, iv, auth_tag, None, suite
        )
        return plaintext.decode()
    except Exception as error:
        raise ValueError(f"解密失败：{error}") from error


def generate_replay_tag(
    replay_key: bytes, sender_id: str, message_counter: int, suite: str = SUITE_EN
) -> str:
    """
    生成防重放标签（EN → HMAC-SHA256；ZH → HMAC-SM3）

    Args:
        replay_key: 防重放密钥
        sender_id: 发送方ID
        message_counter: 消息计数器
        suite: 密码套件

    Returns:
        str: 防重放标签（十六进制）
    """
    validate_suite(suite)
    data = f"{sender_id}:{message_counter}".encode()
    tag = hmac.new(replay_key, data, digestmod(suite)).digest()
    return tag.hex()


def verify_replay_tag(
    replay_key: bytes,
    sender_id: str,
    message_counter: int,
    replay_tag: str,
    suite: str = SUITE_EN,
) -> bool:
    """
    验证防重放标签

    Args:
        replay_key: 防重放密钥
        sender_id: 发送方ID
        message_counter: 消息计数器
        replay_tag: 消息中的replay_tag字段
        suite: 密码套件

    Returns:
        bool: 是否有效
    """
    expected_tag = generate_replay_tag(replay_key, sender_id, message_counter, suite)
    return hmac.compare_digest(expected_tag, replay_tag)
