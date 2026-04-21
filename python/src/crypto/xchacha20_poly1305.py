"""
XChaCha20-Poly1305加密模块
实现XChaCha20-Poly1305加密和解密

注意：由于Python cryptography库的限制，本实现使用ChaCha20-Poly1305（12字节nonce）。
如果未来cryptography库支持XChaCha20，可以升级到XChaCha20-Poly1305（24字节nonce）。

JavaScript版本使用@noble/ciphers的XChaCha20-Poly1305（24字节nonce）。
"""

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import os

NONCE_LENGTH = 12  # ChaCha20-Poly1305使用12字节nonce（Python cryptography库限制）


def encrypt_xchacha20_poly1305(key: bytes, plaintext: bytes, nonce: bytes) -> tuple[bytes, bytes]:
    """
    ChaCha20-Poly1305加密（Python回退实现）

    Args:
        key: 加密密钥（32字节）
        plaintext: 明文
        nonce: 初始化向量（12字节）

    Returns:
        Tuple[bytes, bytes]: (密文, 认证标签)
    """
    cipher = ChaCha20Poly1305(key)
    ciphertext = cipher.encrypt(nonce, plaintext, None)
    # ChaCha20-Poly1305: 最后16字节是认证标签
    ciphertext_only = ciphertext[: len(plaintext)]
    auth_tag = ciphertext[len(plaintext) :]
    return ciphertext_only, auth_tag


def decrypt_xchacha20_poly1305(
    key: bytes, ciphertext: bytes, nonce: bytes, auth_tag: bytes
) -> bytes:
    """
    ChaCha20-Poly1305解密（Python回退实现）

    Args:
        key: 解密密钥（32字节）
        ciphertext: 密文
        nonce: 初始化向量（12字节）
        auth_tag: 认证标签（16字节）

    Returns:
        bytes: 明文
    """
    cipher = ChaCha20Poly1305(key)
    # 重组密文和认证标签
    ciphertext_with_tag = ciphertext + auth_tag
    plaintext = cipher.decrypt(nonce, ciphertext_with_tag, None)
    return plaintext


def generate_nonce() -> bytes:
    """
    生成随机nonce

    Returns:
        bytes: 12字节随机nonce
    """
    return os.urandom(NONCE_LENGTH)
