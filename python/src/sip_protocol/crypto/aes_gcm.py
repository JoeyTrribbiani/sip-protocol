"""
AES-GCM加密模块
实现AES-256-GCM加密和解密
"""

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

AES_GCM_NONCE_LENGTH = 12


def encrypt_aes_gcm(key: bytes, plaintext: bytes, iv: bytes) -> tuple[bytes, bytes]:
    """
    AES-GCM加密

    Args:
        key: 加密密钥（32字节）
        plaintext: 明文
        iv: 初始化向量（12字节）

    Returns:
        Tuple[bytes, bytes]: (密文, 认证标签)
    """
    aesgcm = AESGCM(key)
    ciphertext_with_tag = aesgcm.encrypt(iv, plaintext, None)
    # AES-GCM auth_tag是固定的16字节，从最后16字节分离
    auth_tag = ciphertext_with_tag[-16:]
    ciphertext = ciphertext_with_tag[:-16]
    return ciphertext, auth_tag


def decrypt_aes_gcm(key: bytes, ciphertext: bytes, iv: bytes, auth_tag: bytes) -> bytes:
    """
    AES-GCM解密

    Args:
        key: 解密密钥（32字节）
        ciphertext: 密文
        iv: 初始化向量（12字节）
        auth_tag: 认证标签（16字节）

    Returns:
        bytes: 明文
    """
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(iv, ciphertext + auth_tag, None)
    return plaintext
