"""
HKDF密钥派生模块
实现基于SHA256的HKDF密钥派生函数
"""

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


KDF_SALT = b"SIPHandshake"
KDF_INFO = b"session-keys"


def hkdf(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """
    HKDF密钥派生

    Args:
        ikm: 输入密钥材料
        salt: 盐
        info: 上下文信息
        length: 输出密钥长度（字节）

    Returns:
        bytes: 派生的密钥
    """
    kdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    )
    return kdf.derive(ikm)


def derive_keys(shared_secret, psk_hash, nonce_a, nonce_b):
    """
    派生三个独立密钥（用于握手）

    Args:
        shared_secret: DH共享密钥
        psk_hash: PSK哈希
        nonce_a: 发起方Nonce
        nonce_b: 响应方Nonce

    Returns:
        Tuple[bytes, bytes, bytes]: (encryption_key, auth_key, replay_key)
    """
    ikm = shared_secret + psk_hash + nonce_a + nonce_b
    kdf = hkdf(ikm, KDF_SALT, KDF_INFO, 96)
    encryption_key = kdf[:32]
    auth_key = kdf[32:64]
    replay_key = kdf[64:96]
    return encryption_key, auth_key, replay_key
