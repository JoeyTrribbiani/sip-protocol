"""SM3 密码杂凑模块（GM/T 0004-2012）

基于 cryptography（OpenSSL C 实现）封装；HMAC-SM3 经标准库 hmac 构造
（RFC 2104，适配器满足 hmac.new 的 digestmod 协议）。
选型依据见 ADR-001：与纯 Python 实现（gmssl）在测试中交叉验证。
"""

import hmac as hmac_module

from cryptography.hazmat.primitives import hashes

SM3_DIGEST_SIZE = 32
SM3_BLOCK_SIZE = 64


class SM3Hash:
    """hashlib 风格的 SM3 适配器（供 hmac.new 作 digestmod；支持增量与拷贝）"""

    digest_size = SM3_DIGEST_SIZE
    block_size = SM3_BLOCK_SIZE
    name = "sm3"

    def __init__(self, data: bytes = b"") -> None:
        self._hash = hashes.Hash(hashes.SM3())
        self._hash.update(data)

    def update(self, data: bytes) -> "SM3Hash":
        self._hash.update(data)
        return self

    def digest(self) -> bytes:
        return self._hash.copy().finalize()

    def hexdigest(self) -> str:
        return self.digest().hex()

    def copy(self) -> "SM3Hash":
        clone = SM3Hash.__new__(SM3Hash)
        clone._hash = self._hash.copy()
        return clone


def sm3_hash(data: bytes) -> bytes:
    """一次性 SM3 杂凑（32 字节）"""
    hashing = hashes.Hash(hashes.SM3())
    hashing.update(data)
    return hashing.finalize()


def hmac_sm3(key: bytes, msg: bytes) -> bytes:
    """HMAC-SM3（RFC 2104 构造）"""
    return hmac_module.new(key, msg, SM3Hash).digest()
