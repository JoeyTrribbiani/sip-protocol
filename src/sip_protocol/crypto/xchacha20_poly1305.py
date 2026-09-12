"""
XChaCha20-Poly1305加密模块
实现按套件分派的AEAD加密和解密（SPEC v1.1 §3 / ADR-001）：
- EN → ChaCha20-Poly1305（RFC 8439，12字节nonce，历史行为逐位不变）
- ZH → SM4-GCM（RFC 8998 事实标准化形态，12字节nonce/16字节标签，16字节密钥）

注意：由于Python cryptography库的限制，本实现使用ChaCha20-Poly1305（12字节nonce）。
如果未来cryptography库支持XChaCha20，可以升级到XChaCha20-Poly1305（24字节nonce）。

JavaScript版本使用@noble/ciphers的XChaCha20-Poly1305（24字节nonce）。

模块名历史遗留（偏差 D1）：名为 xchacha20_poly1305，实为 ChaCha20-Poly1305；
v1.1 起本模块同时承载 ZH 套件的 SM4-GCM 分派（接口签名不变，缺省 EN）。
"""

import os

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from .sm4_gcm import decrypt_sm4_gcm, encrypt_sm4_gcm
from .suite import SUITE_EN, SUITE_ZH, validate_suite

NONCE_LENGTH = 12  # ChaCha20-Poly1305使用12字节nonce（Python cryptography库限制）；SM4-GCM 同为 12 字节


def encrypt_xchacha20_poly1305(
    key: bytes, plaintext: bytes, nonce: bytes, aad: bytes | None = None,
    suite: str = SUITE_EN,
) -> tuple[bytes, bytes]:
    """
    AEAD加密（按套件分派：EN → ChaCha20-Poly1305；ZH → SM4-GCM）

    Args:
        key: 加密密钥（EN 32字节；ZH 16字节 SM4-128）
        plaintext: 明文
        nonce: 初始化向量（12字节，两套件同长）
        aad: 附加认证数据（可选，认证但不加密——filetransfer tag 链在用）
        suite: 密码套件（缺省 EN，历史行为不变）

    Returns:
        Tuple[bytes, bytes]: (密文, 认证标签)
    """
    validate_suite(suite)
    if suite == SUITE_ZH:
        return encrypt_sm4_gcm(key, plaintext, nonce, aad)
    cipher = ChaCha20Poly1305(key)
    ciphertext = cipher.encrypt(nonce, plaintext, aad)
    # ChaCha20-Poly1305: 最后16字节是认证标签
    ciphertext_only = ciphertext[: len(plaintext)]
    auth_tag = ciphertext[len(plaintext) :]
    return ciphertext_only, auth_tag


def decrypt_xchacha20_poly1305(
    key: bytes, ciphertext: bytes, nonce: bytes, auth_tag: bytes, aad: bytes | None = None,
    suite: str = SUITE_EN,
) -> bytes:
    """
    AEAD解密（按套件分派；认证失败均抛 cryptography InvalidTag）

    Args:
        key: 解密密钥（EN 32字节；ZH 16字节）
        ciphertext: 密文
        nonce: 初始化向量（12字节）
        auth_tag: 认证标签（16字节）
        aad: 附加认证数据（可选，须与加密时一致，否则认证失败）
        suite: 密码套件（缺省 EN，历史行为不变）

    Returns:
        bytes: 明文
    """
    validate_suite(suite)
    if suite == SUITE_ZH:
        return decrypt_sm4_gcm(key, ciphertext, nonce, auth_tag, aad)
    cipher = ChaCha20Poly1305(key)
    # 重组密文和认证标签
    ciphertext_with_tag = ciphertext + auth_tag
    plaintext = cipher.decrypt(nonce, ciphertext_with_tag, aad)
    return plaintext


def generate_nonce() -> bytes:
    """
    生成随机nonce

    Returns:
        bytes: 12字节随机nonce
    """
    return os.urandom(NONCE_LENGTH)
