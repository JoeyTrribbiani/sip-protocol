"""
HKDF密钥派生模块
实现按套件分派的HKDF密钥派生：EN → HKDF-SHA256（RFC 5869），
ZH → HKDF-SM3（同 RFC 5869 构造，SM3 作底层 PRF，RFC 8998 同构）

密钥长度语义（SPEC §5）：EN 三元组 3×32 字节；ZH 为
16(encryption_key，SM4-128) + 32(auth_key) + 32(replay_key)。
"""

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .suite import SUITE_EN, SUITE_ZH, validate_suite

KDF_SALT = b"SIPHandshake"
KDF_INFO = b"session-keys"


def _okm_length(suite: str) -> int:
    """三元组派生总长度：EN 96 字节（3×32）；ZH 80 字节（16+32+32）"""
    return 80 if suite == SUITE_ZH else 96


def hkdf(ikm: bytes, salt: bytes, info: bytes, length: int, suite: str = SUITE_EN) -> bytes:
    """
    HKDF密钥派生（按套件分派）

    Args:
        ikm: 输入密钥材料
        salt: 盐
        info: 上下文信息
        length: 输出密钥长度（字节）
        suite: 密码套件（EN → SHA256，ZH → SM3）

    Returns:
        bytes: 派生的密钥
    """
    validate_suite(suite)
    algorithm = hashes.SM3() if suite == SUITE_ZH else hashes.SHA256()
    kdf = HKDF(
        algorithm=algorithm,
        length=length,
        salt=salt,
        info=info,
    )
    return kdf.derive(ikm)


def derive_keys_triple_dh(shared_1, shared_2, shared_3, psk_hash, nonce_a, nonce_b, suite=SUITE_EN):
    """
    派生三个独立密钥（用于握手，三重DH）

    Args:
        shared_1: DH共享密钥1 (identity_local × remote_ephemeral)
        shared_2: DH共享密钥2 (ephemeral_local × remote_identity)
        shared_3: DH共享密钥3 (ephemeral_local × remote_ephemeral)
        psk_hash: PSK哈希
        nonce_a: 发起方Nonce
        nonce_b: 响应方Nonce
        suite: 密码套件（决定 PRF 与三元组切分，见模块注释）

    Returns:
        Tuple[bytes, bytes, bytes]: (encryption_key, auth_key, replay_key)
    """
    validate_suite(suite)
    ikm = shared_1 + shared_2 + shared_3 + psk_hash + nonce_a + nonce_b
    kdf = hkdf(ikm, KDF_SALT, KDF_INFO, _okm_length(suite), suite)
    if suite == SUITE_ZH:
        return kdf[:16], kdf[16:48], kdf[48:80]
    encryption_key = kdf[:32]
    auth_key = kdf[32:64]
    replay_key = kdf[64:96]
    return encryption_key, auth_key, replay_key


def derive_keys(shared_secret, psk_hash, nonce_a, nonce_b, suite=SUITE_EN):
    """
    派生三个独立密钥（用于握手，单次DH - 保留兼容性）

    Args:
        shared_secret: DH共享密钥
        psk_hash: PSK哈希
        nonce_a: 发起方Nonce
        nonce_b: 响应方Nonce
        suite: 密码套件

    Returns:
        Tuple[bytes, bytes, bytes]: (encryption_key, auth_key, replay_key)
    """
    validate_suite(suite)
    ikm = shared_secret + psk_hash + nonce_a + nonce_b
    kdf = hkdf(ikm, KDF_SALT, KDF_INFO, _okm_length(suite), suite)
    if suite == SUITE_ZH:
        return kdf[:16], kdf[16:48], kdf[48:80]
    encryption_key = kdf[:32]
    auth_key = kdf[32:64]
    replay_key = kdf[64:96]
    return encryption_key, auth_key, replay_key
