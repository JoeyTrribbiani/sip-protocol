"""sm2_ciphertext 模块测试：五格式互转（含 ASN.1 DER）+ C3 校验 + GM/T 0003.4/.5
标准解密（标准向量/边界/异常路径 + gmssl 双向交叉）+ 畸形输入。"""

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
    FMT_DER,
    KNOWN_FORMATS,
    Sm2CiphertextFormatError,
    Sm2DecryptError,
    convert,
    decrypt_ciphertext,
    detect_format,
    sm2_decrypt,
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


# --- 测试内独立手搓 DER 编码（零复用实现，交叉验证基准） -----------------------


def _local_tlv(tag: int, value: bytes) -> bytes:
    assert len(value) < 0x80  # 本仓向量均短形长度内
    return bytes([tag, len(value)]) + value


def _local_integer(v: bytes) -> bytes:
    """最小 INTEGER：剥前导零，最高位为 1 补 0x00 保正。"""
    m = v.lstrip(b"\x00") or b"\x00"
    if m[0] & 0x80:
        m = b"\x00" + m
    return _local_tlv(0x02, m)


def _local_der(c1: bytes, c2: bytes, c3: bytes) -> bytes:
    """GM/T 0009 ASN.1 密文 SEQUENCE{x, y, C3, C2} 手搓编码。"""
    return _local_tlv(
        0x30,
        _local_integer(c1[:32])
        + _local_integer(c1[32:])
        + _local_tlv(0x04, c3)
        + _local_tlv(0x04, c2),
    )


CT_DER = _local_der(C1, C2, C3)
# 手搓已知答案向量（常量字节，独立于两套编码器）：INTEGER 1/2 → 坐标左补零 31 字节
DER_KNOWN = bytes.fromhex("302c" + "020101" + "020102" + "0420" + "33" * 32 + "0402abcd")
CT_FROM_KNOWN = (b"\x00" * 31 + b"\x01") + (b"\x00" * 31 + b"\x02") + b"\xab\xcd" + b"\x33" * 32
# 畸形 DER 构造零件（基于手搓编码器的合法零件拼装）
_BODY_X = _local_integer(C1[:32])
_BODY_Y = _local_integer(C1[32:])
_BODY_C3 = _local_tlv(0x04, C3)
_BODY_C2 = _local_tlv(0x04, C2)
_BODY = _BODY_X + _BODY_Y + _BODY_C3 + _BODY_C2


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
            FMT_DER: CT_DER,
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


# --- DER（ASN.1，GM/T 0009 结构）---------------------------------------------


class TestDerFormat:
    def test_known_answer_vector(self):
        # 手搓常量向量：INTEGER 1/2 解码后左补零 31 字节还原 C1 坐标
        assert convert(DER_KNOWN, FMT_DER, FMT_C1C2C3) == CT_FROM_KNOWN

    def test_impl_encoding_matches_handrolled(self):
        # 实现编码与测试内独立手搓编码逐字节一致（双编码器交叉）
        assert convert(CT_C1C2C3, FMT_C1C2C3, FMT_DER) == CT_DER

    def test_detect_der(self):
        assert detect_format(CT_DER) == FMT_DER
        assert detect_format(DER_KNOWN) == FMT_DER

    def test_detect_0x30_prefixed_raw_falls_back(self):
        # 首字节恰为 0x30 的裸密文（DER 解析必败）→ 落回裸格式缺省旧序
        raw30 = b"\x30" + CT_C1C2C3[1:]
        assert detect_format(raw30) == FMT_C1C2C3

    def test_leading_zero_coordinate_strip_and_restore(self):
        # 本仓 C1x 以 0x00 开头——编码剥前导零（31 字节 INTEGER），解码补回
        assert CT_DER[2] == 0x02 and CT_DER[3] == 31
        assert convert(CT_DER, FMT_DER, FMT_C1C2C3)[:C1_LEN] == C1

    def test_high_bit_coordinate_sign_byte(self):
        # 坐标最高位为 1 → INTEGER 补 0x00 保正（33 字节），往返无损
        c1_hb = b"\xff" + bytes(range(1, C1_LEN))
        ct_hb = c1_hb + C2 + C3
        der = convert(ct_hb, FMT_C1C2C3, FMT_DER)
        assert der[2:5] == b"\x02\x21\x00"
        assert convert(der, FMT_DER, FMT_C1C2C3) == ct_hb

    def test_zero_coordinate_roundtrip(self):
        # 全零坐标 → 最小 INTEGER 单字节 0x00，往返无损（结构层，在曲线校验之前）
        c1_zero = b"\x00" * 32 + C1[32:]
        ct_zero = c1_zero + C2 + C3
        der = convert(ct_zero, FMT_C1C2C3, FMT_DER)
        assert der[2:4] == b"\x02\x01"
        assert convert(der, FMT_DER, FMT_C1C3C2) == c1_zero + C3 + C2

    @pytest.mark.parametrize(
        "bad,label",
        [
            (b"", "空输入"),
            (CT_DER[:-1], "末字节截断"),
            (b"\x31" + CT_DER[1:], "外层标签非 SEQUENCE"),
            (CT_DER + b"\x05\x00", "SEQUENCE 后多余字节"),
            (_local_tlv(0x30, _BODY + b"\x05\x00"), "SEQUENCE 内多余元素"),
            (b"\x30\x81\x77" + _BODY, "长形长度非最小"),
            (
                _local_tlv(0x30, _BODY_X + _BODY_Y + _local_tlv(0x04, C3[:31]) + _BODY_C2),
                "C3 长度 31",
            ),
            (_local_tlv(0x30, _BODY_X + _BODY_Y + _BODY_C3 + b"\x04\x00"), "C2 为空"),
            (
                _local_tlv(
                    0x30,
                    b"\x02\x21" + b"\x00" * 32 + b"\x01" + _BODY_Y + _BODY_C3 + _BODY_C2,
                ),
                "C1x 非最小编码（33 字节带多余前导零）",
            ),
            (
                _local_tlv(
                    0x30,
                    b"\x02\x22" + b"\x00" * 33 + b"\x01" + _BODY_Y + _BODY_C3 + _BODY_C2,
                ),
                "C1x 超出曲线坐标范围（34 字节）",
            ),
        ],
    )
    def test_malformed_der_rejected(self, bad, label):
        with pytest.raises(Sm2CiphertextFormatError):
            convert(bad, FMT_DER, FMT_C1C2C3)

    def test_malformed_der_detect_raises_or_falls_back(self):
        # 畸形 DER 走 detect：空输入抛错；其余首字节 0x30 解析失败落回裸格式
        with pytest.raises(Sm2CiphertextFormatError):
            detect_format(b"")
        assert detect_format(CT_DER[:-1]) == FMT_C1C2C3  # 截断后仍够裸格式最小长

    def test_verify_c3_der(self):
        assert verify_c3(CT_DER, FMT_DER, _derive) is True
        # DER 内 C1/C3/C2 位置由结构固定，篡改 C2 末字节 → C3 复算不一致
        bad = bytearray(CT_DER)
        bad[-1] ^= 0xFF
        assert verify_c3(bytes(bad), FMT_DER, _derive) is False

    def test_verify_c3_malformed_der_rejected(self):
        with pytest.raises(Sm2CiphertextFormatError):
            verify_c3(CT_DER[:-1], FMT_DER, _derive)


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


# --- sm2_decrypt / decrypt_ciphertext（GM/T 0003.4/.5 标准解密） ----------------

# 标准向量：GM/T 0003.5-2012 附录 C 加密样例（GB/T 32918.4 同源文本，
# OpenSSL test/sm2_internal_test.c 采用同款）——真实曲线点/真实 KDF/C3，
# 与本实现零共享假设，任何曲线参数/KDF/C3 公式偏差此处即红。
_STD_D = int.from_bytes(
    bytes.fromhex("3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8"),
    "big",
)
_STD_MSG = b"encryption standard"  # 标准样例明文（19B）
_STD_C1 = bytes.fromhex(
    "04EBFC718E8D1798620432268E77FEB6415E2EDE0E073C0F4F640ECD2E149A73"
    "E858F9D81E5430A57B36DAAB8F950A3C64E6EE6A63094D99283AFF767E124DF0"
)
_STD_C2 = bytes.fromhex("21886CA989CA9C7D58087307CA93092D651EFA")
_STD_C3 = bytes.fromhex("59983C18F809E262923C53AEC295D30383B54E39D609D160AFCB1908D0BD8766")
# OpenSSL 期望的 GM/T 0009 DER 密文整字节（SEQUENCE{x, y, C3, C2}）
_STD_DER_OPENSSL = bytes.fromhex(
    "307C0220"
    + _STD_C1[:32].hex()
    + "022100"
    + _STD_C1[32:].hex()
    + "0420"
    + _STD_C3.hex()
    + "0413"
    + _STD_C2.hex()
)


def _kdf_ref(z: bytes, klen: int) -> bytes:
    """KDF 独立复算（GM/T 0003.4 计数器模式，供测试内手搓加密）。"""
    out = bytearray()
    ct = 1
    while len(out) < klen:
        out += sm3_hash(z + ct.to_bytes(4, "big"))
        ct += 1
    return bytes(out[:klen])


def _std_encrypt_fixed_k(d: bytes, k: bytes, msg: bytes) -> tuple[bytes, bytes, bytes]:
    """测试专用确定性"加密"（GM/T 0003.4 公式手搓，k 固定）→ (C1, C2, C3)。

    库内只提供解密原语；加密方仅为构造测试向量，不进产品代码。
    """
    from sip_protocol.crypto.sm2 import SM2PublicKey

    c1 = SM2PrivateKey.from_private_bytes(k).public_key().public_bytes()[1:]
    pub_d = SM2PrivateKey.from_private_bytes(d).public_key()
    shared = SM2PrivateKey.from_private_bytes(k).exchange_point(
        SM2PublicKey.from_public_bytes(pub_d.public_bytes())
    )
    keystream = _kdf_ref(shared, len(msg))
    c2 = bytes(a ^ b for a, b in zip(msg, keystream))
    c3 = sm3_hash(shared[: C1_LEN // 2] + msg + shared[C1_LEN // 2 :])
    return c1, c2, c3


# 本地确定性往返向量：真实曲线点 + 多块 KDF（明文 64B 跨两个 SM3 块）
_RT_D = bytes(range(1, 33))
_RT_K = bytes(range(0x21, 0x41))
_RT_MSG = b"multi-block kdf message padding to sixty-four bytes!!"  # 54B

_RT_C1, _RT_C2, _RT_C3 = _std_encrypt_fixed_k(_RT_D, _RT_K, _RT_MSG)


class TestSm2Decrypt:
    def test_standard_vector_core(self):
        # 标准样例核心路径：d + (C1, C2, C3) → "encryption standard"
        c1_point = (
            int.from_bytes(_STD_C1[:32], "big"),
            int.from_bytes(_STD_C1[32:], "big"),
        )
        assert sm2_decrypt(_STD_D, c1_point, _STD_C2, _STD_C3) == _STD_MSG

    def test_standard_vector_all_wire_formats(self):
        ct_c1c2c3 = _STD_C1 + _STD_C2 + _STD_C3
        ct_prefixed = b"\x04" + ct_c1c2c3
        for fmt, ct in (
            (FMT_C1C2C3, ct_c1c2c3),
            (FMT_C1C3C2, convert(ct_c1c2c3, FMT_C1C2C3, FMT_C1C3C2)),
            (FMT_C1C2C3_04, ct_prefixed),
            (FMT_C1C3C2_04, convert(ct_prefixed, FMT_C1C2C3_04, FMT_C1C3C2_04)),
            (FMT_DER, convert(ct_c1c2c3, FMT_C1C2C3, FMT_DER)),
        ):
            assert decrypt_ciphertext(ct, fmt, _STD_D) == _STD_MSG, fmt

    def test_standard_der_matches_openssl_bytes(self):
        # 本库 DER 编码与 OpenSSL 期望字节逐字一致——跨实现字节级互通证据
        ct_c1c2c3 = _STD_C1 + _STD_C2 + _STD_C3
        assert convert(ct_c1c2c3, FMT_C1C2C3, FMT_DER) == _STD_DER_OPENSSL

    def test_standard_openssl_der_directly_decryptable(self):
        # OpenSSL 字节直喂（不经本库 convert）——外部密文进、明文出
        assert decrypt_ciphertext(_STD_DER_OPENSSL, FMT_DER, _STD_D) == _STD_MSG

    def test_local_roundtrip_multi_block_kdf(self):
        # 自造向量往返：明文 54B 跨两个 KDF 块（计数器 ct=1,2）
        c1_point = (
            int.from_bytes(_RT_C1[:32], "big"),
            int.from_bytes(_RT_C1[32:], "big"),
        )
        assert sm2_decrypt(int.from_bytes(_RT_D, "big"), c1_point, _RT_C2, _RT_C3) == _RT_MSG
        ct = _RT_C1 + _RT_C2 + _RT_C3
        assert decrypt_ciphertext(ct, FMT_C1C2C3, int.from_bytes(_RT_D, "big")) == _RT_MSG

    def test_empty_message_roundtrip(self):
        # klen=0 边界：KDF 输出空、C3 = Hash(x2‖‖y2)（裸格式层不可达，核心直测）
        c1, c2, c3 = _std_encrypt_fixed_k(_RT_D, _RT_K, b"")
        c1_point = (
            int.from_bytes(c1[:32], "big"),
            int.from_bytes(c1[32:], "big"),
        )
        assert c2 == b""
        assert sm2_decrypt(int.from_bytes(_RT_D, "big"), c1_point, c2, c3) == b""

    def test_wrong_privkey_raises_decrypt_error(self):
        c1_point = (
            int.from_bytes(_STD_C1[:32], "big"),
            int.from_bytes(_STD_C1[32:], "big"),
        )
        with pytest.raises(Sm2DecryptError, match="C3 复算不一致"):
            sm2_decrypt(int.from_bytes(bytes(32) + b"\x01", "big"), c1_point, _STD_C2, _STD_C3)

    def test_tampered_c2_raises(self):
        c1_point = (
            int.from_bytes(_STD_C1[:32], "big"),
            int.from_bytes(_STD_C1[32:], "big"),
        )
        bad_c2 = bytes([_STD_C2[0] ^ 0x01]) + _STD_C2[1:]
        with pytest.raises(Sm2DecryptError, match="C3 复算不一致"):
            sm2_decrypt(_STD_D, c1_point, bad_c2, _STD_C3)

    def test_order_swapped_ciphertext_raises(self):
        # 顺序错配（C1C3C2 字节当 C1C2C3 声明）→ C3 复算必不一致，拒绝返回垃圾明文
        ct_swapped = convert(_STD_C1 + _STD_C2 + _STD_C3, FMT_C1C2C3, FMT_C1C3C2)
        with pytest.raises(Sm2DecryptError, match="C3 复算不一致"):
            decrypt_ciphertext(ct_swapped, FMT_C1C2C3, _STD_D)

    def test_c1_not_on_curve_raises_value_error(self):
        x_bad = int.from_bytes(_STD_C1[:32], "big") ^ 1  # 破坏低位 → 不在曲线
        with pytest.raises(ValueError, match="曲线"):
            sm2_decrypt(_STD_D, (x_bad, int.from_bytes(_STD_C1[32:], "big")), _STD_C2, _STD_C3)

    def test_privkey_out_of_range_raises(self):
        c1_point = (
            int.from_bytes(_STD_C1[:32], "big"),
            int.from_bytes(_STD_C1[32:], "big"),
        )
        with pytest.raises(ValueError, match="越界"):
            sm2_decrypt(0, c1_point, _STD_C2, _STD_C3)

    def test_decrypt_ciphertext_bad_format_raises(self):
        with pytest.raises(Sm2CiphertextFormatError):
            decrypt_ciphertext(_STD_C1 + _STD_C2, FMT_C1C2C3, _STD_D)  # 少 C3 段
        with pytest.raises(Sm2CiphertextFormatError):
            decrypt_ciphertext(_STD_DER_OPENSSL[:-2], FMT_DER, _STD_D)  # DER 截断


@pytest.mark.skipif(not GMSSL_AVAILABLE, reason="gmssl dev 依赖缺失")
class TestGmsslDecryptInterop:
    """gmssl 真实加密 ↔ 本库 sm2_decrypt 双向互认（独立实现交叉验证）。"""

    def test_gmssl_ciphertext_decrypts_locally(self):
        priv = SM2PrivateKey.from_private_bytes(_INTEROP_D)
        pub_xy = priv.public_key().public_bytes().hex()[2:]
        for mode, fmt in ((0, FMT_C1C2C3), (1, FMT_C1C3C2)):
            gm = gmssl_sm2.CryptSM2(private_key=_INTEROP_D.hex(), public_key="", mode=mode)
            gm.public_key = pub_xy  # 绕开 gmssl 对 04 前缀公钥的误剥离缺陷
            ct = gm.encrypt(_INTEROP_MSG)
            assert decrypt_ciphertext(ct, fmt, int.from_bytes(_INTEROP_D, "big")) == _INTEROP_MSG

    def test_local_ciphertext_decrypts_in_gmssl(self):
        # 测试内手搓标准加密（固定 k）→ gmssl 反向解开——公式两实现互证
        c1, c2, c3 = _std_encrypt_fixed_k(_INTEROP_D, _RT_K, _INTEROP_MSG)
        gm = gmssl_sm2.CryptSM2(private_key=_INTEROP_D.hex(), public_key="", mode=0)
        assert gm.decrypt(c1 + c2 + c3) == _INTEROP_MSG
