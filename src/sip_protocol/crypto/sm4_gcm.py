"""SM4-GCM AEAD 模块（GM/T 0002 块密码 + NIST SP 800-38D GCM 构造）

标准化状态如实记述（SPEC §3/§13）：GB/T 体系内 SM4 的 AEAD 形态无单一强制
标准，SM4-GCM 由 RFC 8998（TLS 1.3 商密套件 TLS_SM4_GCM_SM3）事实标准化。
基于 cryptography（OpenSSL 3，42.0.0 起）；密钥 16 字节、nonce 12 字节、
标签 16 字节——与 EN 套件的 ChaCha20-Poly1305 wire 尺寸同构。

认证失败抛 cryptography.exceptions.InvalidTag（与 ChaCha20 路径同型，
filetransfer 解包层已按该异常捕获）。
"""

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

SM4_KEY_LENGTH = 16
NONCE_LENGTH = 12
TAG_LENGTH = 16


def encrypt_sm4_gcm(
    key: bytes, plaintext: bytes, nonce: bytes, aad: bytes | None = None
) -> tuple[bytes, bytes]:
    """SM4-GCM 加密

    Args:
        key: 加密密钥（16 字节，SM4-128）
        plaintext: 明文
        nonce: 初始化向量（12 字节）
        aad: 附加认证数据（可选，认证但不加密）

    Returns:
        Tuple[bytes, bytes]: (密文, 认证标签)
    """
    encryptor = Cipher(algorithms.SM4(key), modes.GCM(nonce)).encryptor()
    if aad is not None:
        encryptor.authenticate_additional_data(aad)
    ciphertext_only = encryptor.update(plaintext) + encryptor.finalize()
    # Cipher/Modes API 的标签不在密文输出中，须从 encryptor.tag 取（finalize 后有效）
    auth_tag = encryptor.tag
    return ciphertext_only, auth_tag


def decrypt_sm4_gcm(
    key: bytes, ciphertext: bytes, nonce: bytes, auth_tag: bytes, aad: bytes | None = None
) -> bytes:
    """SM4-GCM 解密；认证失败抛 InvalidTag

    Args:
        key: 解密密钥（16 字节）
        ciphertext: 密文
        nonce: 初始化向量（12 字节）
        auth_tag: 认证标签（16 字节）
        aad: 附加认证数据（须与加密时一致，否则认证失败）

    Returns:
        bytes: 明文
    """
    decryptor = Cipher(algorithms.SM4(key), modes.GCM(nonce, auth_tag)).decryptor()
    if aad is not None:
        decryptor.authenticate_additional_data(aad)
    return decryptor.update(ciphertext) + decryptor.finalize()
