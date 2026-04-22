"""
PSK哈希模块
实现基于Argon2id的PSK哈希
"""

from typing import Optional
from argon2 import low_level

# 固定盐（用于测试）
FIXED_SALT = b"SIPProtocolTestSalt"  # 16字节


def hash_psk(psk: bytes, salt: Optional[bytes] = None) -> tuple[bytes, bytes]:
    """
    哈希PSK（Argon2id）

    Args:
        psk: 预共享密钥（任意长度）
        salt: 盐（可选，如果为None则使用固定盐）

    Returns:
        Tuple[bytes, bytes]: (psk_hash, salt)

    需要安装: pip install argon2-cffi
    """
    # 如果没有提供盐，使用固定盐
    if salt is None:
        salt = FIXED_SALT

    # 使用低级API直接计算哈希（避免格式化）
    psk_hash = low_level.hash_secret_raw(
        secret=psk,
        salt=salt,
        time_cost=3,
        memory_cost=65536,
        parallelism=4,
        hash_len=32,
        type=low_level.Type.ID,
    )

    return psk_hash, salt
