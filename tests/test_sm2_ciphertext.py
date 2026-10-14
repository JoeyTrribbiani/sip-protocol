"""sm2_ciphertext 模块测试：四格式互转 + C3 校验 + 畸形输入 + gmssl 真实向量交叉验证。"""

from __future__ import annotations

import pytest

from sip_protocol.crypto.sm2 import SM2PrivateKey
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

try:  # gmssl 仅 dev 组依赖（交叉验证），缺失时跳过真实向量用例
    from gmssl import sm2 as gmssl_sm2

    GMSSL_AVAILABLE = True
except ImportError:
    GMSSL_AVAILABLE = False

# --- 固定测试向量（合成，非真实加密） ---------------------------------------

C1 = bytes(range(C1_LEN))  # 64B 假临时公钥点（密文里的 [k]G）
SHARED = bytes(range(0x40, 0x80))  # 64B 假共享点 x2‖y2（= [d]C1，与 C1 是不同的点）
MSG = b"attack at dawn"  # 16B 明文
# KDF(x2‖y2, klen) 单块展开（klen=16 < 32，SM3(z‖ct=1) 截断）
KEYSTREAM = sm3_hash(SHARED + (1).to_bytes(4, "big"))[: len(MSG)]
C2 = bytes(a ^ b for a, b in zip(MSG, KEYSTREAM))
# GM/T 0003.5：C3 = Hash(x2 ‖ M ‖ y2)——消息居中，x2/y2 取自共享点前后半段
C3 = sm3_hash(SHARED[: C1_LEN // 2] + MSG + SHARED[C1_LEN // 2 :])

CT_C1C2C3 = C1 + C2 + C3
CT_C1C3C2 = C1 + C3 + C2
CT_C1C2C3_04 = b"\x04" + CT_C1C2C3
CT_C1C3C2_04 = b"\x04" + CT_C1C3C2


def _derive(c1: bytes) -> bytes:
    """确定性假共享点：c1 是 C1 时返回 SHARED（真实场景为 [d]C1 点乘）。"""
    assert c1 == C1
    return SHARED


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

    def test_empty_input_raises(self):
        with pytest.raises(Sm2CiphertextFormatError):
            detect_format(b"")


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

    def test_short_ciphertext_rejected(self):
        with pytest.raises(Sm2CiphertextFormatError):
            convert(bytes(20), FMT_C1C2C3, FMT_C1C3C2)


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

    def test_bad_derive_output_raises(self):
        # derive 返回的共享点长度不是 64 字节
        with pytest.raises(Sm2CiphertextFormatError):
            verify_c3(CT_C1C2C3, FMT_C1C2C3, lambda c1: b"\x00" * 4)

    def test_malformed_length_raises(self):
        with pytest.raises(Sm2CiphertextFormatError):
            verify_c3(b"\x04" + bytes(20), FMT_C1C2C3_04, _derive)

    def test_unknown_format_rejected(self):
        with pytest.raises(Sm2CiphertextFormatError):
            verify_c3(CT_C1C2C3, "C1C2C3+DER", _derive)


# --- gmssl 真实密文交叉验证（独立实现互认，dev 依赖缺失则跳过） ------------------

# 固定私钥保证向量确定性（d = 0x0102…20 ∈ [1, n)）
_INTEROP_D = bytes(range(1, 33))
_INTEROP_MSG = b"gmssl interop vector"


@pytest.mark.skipif(not GMSSL_AVAILABLE, reason="gmssl dev 依赖缺失")
class TestGmsslInterop:
    """gmssl 真实加密 ↔ 本模块 verify_c3/convert 互认。

    合成向量与实现共享同一套公式假设，交叉验证必须引入独立实现：
    gmssl 的 C3 拼接顺序与 KDF 均按 GM/T 0003.4/.5 独立实现。
    """

    def _gm(self, mode: int):
        priv = SM2PrivateKey.from_private_bytes(_INTEROP_D)
        pub_xy = priv.public_key().public_bytes().hex()[2:]  # gmssl 公钥为 x‖y 无 04 前缀
        gm = gmssl_sm2.CryptSM2(private_key=_INTEROP_D.hex(), public_key="", mode=mode)
        # 绕开 gmssl __init__ 对 04 开头公钥 lstrip("04") 的误剥离缺陷：构造后直接赋值
        gm.public_key = pub_xy
        return gm

    def _derive_from(self, gm):
        def derive(c1: bytes) -> bytes:
            # 共享点 [d]C1 → x2‖y2（64B）；KDF 与 C3 由 verify_c3 按标准重算
            return bytes.fromhex(gm._kg(int(gm.private_key, 16), c1.hex()))

        return derive

    def test_verify_c3_real_ciphertext(self):
        ct_old = self._gm(0).encrypt(_INTEROP_MSG)  # C1C2C3（gmssl mode=0）
        ct_new = self._gm(1).encrypt(_INTEROP_MSG)  # C1C3C2（gmssl mode=1）
        derive = self._derive_from(self._gm(0))
        # 正确声明顺序 → C3 复算一致——KDF、C3 杂凑顺序任一实现错误此处即红
        assert verify_c3(ct_old, FMT_C1C2C3, derive) is True
        assert verify_c3(ct_new, FMT_C1C3C2, derive) is True
        # 错配顺序 → False（gmssl decrypt 不校验 C3，正是其静默错解场景）
        assert verify_c3(ct_old, FMT_C1C3C2, derive) is False
        assert verify_c3(ct_new, FMT_C1C2C3, derive) is False

    def test_convert_cross_order_gmssl_decrypt(self):
        # 我方互转后的密文由 gmssl 反序实例解开——convert 与真实库互通
        conv = convert(self._gm(0).encrypt(_INTEROP_MSG), FMT_C1C2C3, FMT_C1C3C2)
        assert self._gm(1).decrypt(conv) == _INTEROP_MSG
        conv = convert(self._gm(1).encrypt(_INTEROP_MSG), FMT_C1C3C2, FMT_C1C2C3)
        assert self._gm(0).decrypt(conv) == _INTEROP_MSG

    def test_verify_c3_prefixed_real_ciphertext(self):
        ct_new = self._gm(1).encrypt(_INTEROP_MSG)
        derive = self._derive_from(self._gm(1))
        # 叠加 SEC1 0x04 前缀（部分库 wire 形态）后校验仍成立/仍能识错
        assert verify_c3(b"\x04" + ct_new, FMT_C1C3C2_04, derive) is True
        assert verify_c3(b"\x04" + ct_new, FMT_C1C2C3_04, derive) is False
