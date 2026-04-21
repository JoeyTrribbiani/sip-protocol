"""
PSK哈希模块
实现基于Argon2id的PSK哈希
"""

from argon2 import PasswordHasher, low_level
import os


def hash_psk(psk: bytes, salt: bytes = None) -> tuple[bytes, bytes]:
    """
    哈希PSK（Argon2id）

    Args:
        psk: 预共享密钥（任意长度）
        salt: 盐（可选，如果为None则生成随机盐，16字节）

    Returns:
        Tuple[bytes, bytes]: (psk_hash, salt)

    需要安装: pip install argon2-cffi
    """
    # 如果没有提供盐，生成随机盐
    if salt is None:
        salt = os.urandom(16)

    # 使用低级API直接计算哈希（避免格式化）
    psk_hash = low_level.hash_secret_raw(
        secret=psk,
        salt=salt,
        time_cost=3,
        memory_cost=65536,
        parallelism=4,
        hash_len=32,
        type=low_level.Type.ID
    )

    return psk_hash, salt
