"""
Nonce管理器模块
防止重放攻击
"""

import os
from collections import OrderedDict

NONCE_LENGTH = 24


class NonceManager:
    """
    Nonce管理器
    使用OrderedDict保证FIFO淘汰顺序
    """

    def __init__(self):
        self.used_nonces: OrderedDict[bytes, None] = OrderedDict()

    def generate_nonce(self) -> bytes:
        """
        生成新的Nonce

        Returns:
            bytes: 新的Nonce
        """
        nonce = os.urandom(NONCE_LENGTH)
        while nonce in self.used_nonces:
            nonce = os.urandom(NONCE_LENGTH)
        self.used_nonces[nonce] = None
        return nonce

    def check_and_add(self, nonce: bytes) -> bool:
        """
        检查并添加Nonce

        Args:
            nonce: 要检查的Nonce

        Returns:
            bool: 是否有效（未使用）
        """
        if nonce in self.used_nonces:
            return False
        self.used_nonces[nonce] = None
        if len(self.used_nonces) > 1000:
            self.used_nonces.popitem(last=False)
        return True

    def validate_nonce(self, nonce: bytes) -> bool:
        """
        验证Nonce是否已使用

        Args:
            nonce: 要验证的Nonce

        Returns:
            bool: 是否有效（未使用）
        """
        return nonce not in self.used_nonces
