"""sm2_ciphertext 模块测试：三格式互转 + C3 校验 + 畸形输入。"""

from __future__ import annotations

import pytest

from sip_protocol.crypto.sm2_ciphertext import (
    C1_LEN,
    C3_LEN,
    FMT_C1C2C3,
    FMT_C1C2C3_04,
    FMT_C1C3C2,
    FMT_C1C3C2_04,
    KNOWN_FORMATS,
    Sm2CiphertextFormatError,
    convert,
    detect_format,
    verify_c3,
)
from sip_protocol.crypto.sm3 import sm3_hash

# --- 固定测试向量（合成，非真实加密） ---------------------------------------

C1 = bytes(range(C1_LEN))                 # 64B 假点坐标
MSG = b"attack at dawn"                   # 16B 明文
KEYSTREAM = bytes((0x5A + i) & 0xFF for i in range(len(MSG)))  # 假 KDF 流
C2 = bytes(a ^ b for a, b in zip(MSG, KEYSTREAM))
C3 = sm3_hash(C1 + MSG)                   # 按 GM/T 0003.5: Hash(x2‖M‖y2)，x‖y 即 c1

CT_C1C2C3 = C1 + C2 + C3
CT_C1C3C2 = C1 + C3 + C2
CT_C1C2C3_04 = b"\x04" + CT_C1C2C3
CT_C1C3C2_04 = b"\x04" + CT_C1C3C2


def _derive(c1: bytes) -> bytes:
    """确定性假 KDF：c1 决定 KEYSTREAM（长度即明文长，由 C2 反推不出来，
    测试里直接返回与 MSG 等长的流）。"""
    assert c1 == C1
    return KEYSTREAM


# --- detect_format ----------------------------------------------------------


class TestDetectFormat:
    def test_prefixed_detected(self):
        assert detect_format(CT_C1C2C3_04) in (FMT_C1C2C3_04, FMT_C1C3C2_04)

    def test_bare_returns_default_order(self):
        assert detect_format(CT_C1C2C3) == FMT_C1C2C3

    def test_too_short_raises(self):
        with pytest.raises(Sm2CiphertextFormatError):
            detect_format(b"\x04" + bytes(10))

    def test_min_length_boundary(self):
        # C1+C3+1B C2 = 最小合法长
        assert detect_format(bytes(C1_LEN + C3_LEN + 1)) == FMT_C1C2C3


# --- convert ----------------------------------------------------------------


class TestConvert:
    @pytest.mark.parametrize("src", KNOWN_FORMATS)
    @pytest.mark.parametrize("dst", KNOWN_FORMATS)
    def test_roundtrip_all_pairs(self, src, dst):
        srcs = {
            FMT_C1C2C3: CT_C1C2C3,
            FMT_C1C3C2: CT_C1C3C2,
            FMT_C1C2C3_04: CT_C1C2C3_04,
            FMT_C1C3C2_04: CT_C1C3C2_04,
        }
        out = convert(srcs[src], src, dst)
        assert out == srcs[dst]

    def test_c3_moves_not_c1(self):
        # 互转只动 C2/C3 相对位置，C1 恒在前
        assert convert(CT_C1C2C3, FMT_C1C2C3, FMT_C1C3C2)[:C1_LEN] == C1
        assert convert(CT_C1C3C2, FMT_C1C3C2, FMT_C1C2C3)[:C1_LEN] == C1

    def test_unknown_format_rejected(self):
        with pytest.raises(Sm2CiphertextFormatError):
            convert(CT_C1C2C3, "C2C1C3", FMT_C1C3C2)
        with pytest.raises(Sm2CiphertextFormatError):
            convert(CT_C1C2C3, FMT_C1C2C3, "raw")

    def test_prefix_claim_mismatch(self):
        # 声明带 04 前缀但首字节不是 04
        with pytest.raises(Sm2CiphertextFormatError):
            convert(CT_C1C2C3, FMT_C1C2C3_04, FMT_C1C3C2)

    def test_strip_prefix_conversion(self):
        assert convert(CT_C1C2C3_04, FMT_C1C2C3_04, FMT_C1C3C2) == CT_C1C3C2
        assert convert(CT_C1C3C2, FMT_C1C3C2, FMT_C1C3C2_04) == CT_C1C3C2_04


# --- verify_c3 ---------------------------------------------------------------


class TestVerifyC3:
    def test_correct_order_passes(self):
        assert verify_c3(CT_C1C2C3, FMT_C1C2C3, _derive) is True
        assert verify_c3(CT_C1C3C2, FMT_C1C3C2, _derive) is True

    def test_wrong_order_fails(self):
        # 顺序错配：拿旧序密文声明新序（正是静默错解的典型场景）
        assert verify_c3(CT_C1C2C3, FMT_C1C3C2, _derive) is False
        assert verify_c3(CT_C1C3C2, FMT_C1C2C3, _derive) is False

    def test_prefixed_variants(self):
        assert verify_c3(CT_C1C2C3_04, FMT_C1C2C3_04, _derive) is True
        assert verify_c3(CT_C1C3C2_04, FMT_C1C3C2_04, _derive) is True
        assert verify_c3(CT_C1C2C3_04, FMT_C1C3C2_04, _derive) is False

    def test_tampered_c2_fails(self):
        bad = bytearray(CT_C1C2C3)
        bad[C1_LEN] ^= 0x01
        assert verify_c3(bytes(bad), FMT_C1C2C3, _derive) is False

    def test_tampered_c3_fails(self):
        bad = bytearray(CT_C1C2C3)
        bad[-1] ^= 0xFF
        assert verify_c3(bytes(bad), FMT_C1C2C3, _derive) is False

    def test_missing_derive_raises(self):
        with pytest.raises(ValueError):
            verify_c3(CT_C1C2C3, FMT_C1C2C3, None)  # type: ignore[arg-type]

    def test_short_keystream_raises(self):
        with pytest.raises(Sm2CiphertextFormatError):
            verify_c3(CT_C1C2C3, FMT_C1C2C3, lambda c1: b"\x00" * 4)

    def test_malformed_length_raises(self):
        with pytest.raises(Sm2CiphertextFormatError):
            verify_c3(b"\x04" + bytes(20), FMT_C1C2C3_04, _derive)
