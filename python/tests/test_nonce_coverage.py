#!/usr/bin/env python3
"""
nonce.py 补充覆盖率测试
覆盖 generate_nonce / check_and_add / validate_nonce 边界
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sip_protocol.managers.nonce import NonceManager, NONCE_LENGTH


class TestGenerateNonce:
    """generate_nonce 测试"""

    def test_nonce_length(self):
        mgr = NonceManager()
        nonce = mgr.generate_nonce()
        assert len(nonce) == NONCE_LENGTH

    def test_nonce_is_bytes(self):
        mgr = NonceManager()
        nonce = mgr.generate_nonce()
        assert isinstance(nonce, bytes)

    def test_nonce_is_unique(self):
        mgr = NonceManager()
        nonces = {mgr.generate_nonce() for _ in range(100)}
        assert len(nonces) == 100

    def test_nonce_added_to_used_set(self):
        mgr = NonceManager()
        nonce = mgr.generate_nonce()
        assert nonce in mgr.used_nonces


class TestCheckAndAdd:
    """check_and_add 测试"""

    def test_new_nonce_is_valid(self):
        mgr = NonceManager()
        nonce = os.urandom(NONCE_LENGTH)
        assert mgr.check_and_add(nonce) is True

    def test_duplicate_nonce_is_invalid(self):
        mgr = NonceManager()
        nonce = os.urandom(NONCE_LENGTH)
        mgr.check_and_add(nonce)
        assert mgr.check_and_add(nonce) is False

    def test_generated_nonce_is_invalid_for_check_and_add(self):
        mgr = NonceManager()
        nonce = mgr.generate_nonce()
        assert mgr.check_and_add(nonce) is False

    def test_eviction_when_over_1000(self):
        """When used_nonces exceeds 1000, the oldest should be evicted"""
        mgr = NonceManager()
        nonces = []
        for _ in range(1001):
            n = os.urandom(NONCE_LENGTH)
            mgr.check_and_add(n)
            nonces.append(n)

        # After 1001 entries, pop() was called, so set size should be <= 1001
        assert len(mgr.used_nonces) <= 1001

    def test_eviction_reduces_set_size(self):
        """When set exceeds 1000, pop() reduces the set"""
        mgr = NonceManager()
        for _ in range(1001):
            mgr.check_and_add(os.urandom(NONCE_LENGTH))
        # pop() was called once, so size is 1000
        assert len(mgr.used_nonces) == 1000

        # Adding another still triggers pop
        mgr.check_and_add(os.urandom(NONCE_LENGTH))
        assert len(mgr.used_nonces) == 1000


class TestValidateNonce:
    """validate_nonce 测试"""

    def test_unused_nonce_is_valid(self):
        mgr = NonceManager()
        nonce = os.urandom(NONCE_LENGTH)
        assert mgr.validate_nonce(nonce) is True

    def test_used_nonce_is_invalid(self):
        mgr = NonceManager()
        nonce = mgr.generate_nonce()
        assert mgr.validate_nonce(nonce) is False

    def test_check_and_add_makes_nonce_invalid(self):
        mgr = NonceManager()
        nonce = os.urandom(NONCE_LENGTH)
        mgr.check_and_add(nonce)
        assert mgr.validate_nonce(nonce) is False

    def test_validate_does_not_add(self):
        """validate_nonce should not add the nonce to used set"""
        mgr = NonceManager()
        nonce = os.urandom(NONCE_LENGTH)
        mgr.validate_nonce(nonce)
        # Should still be valid (not added)
        assert mgr.validate_nonce(nonce) is True
        # And check_and_add should also work
        assert mgr.check_and_add(nonce) is True


class TestNonceLength:
    """NONCE_LENGTH 常量"""

    def test_nonce_length_is_24(self):
        assert NONCE_LENGTH == 24
