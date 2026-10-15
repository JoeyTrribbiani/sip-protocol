"""SM2 加密密文的线格式互转与校验（GM/T 0003.5 工程互通层）。

背景
----
GM/T 0003.5 只定义了密文各分量（C1 椭圆曲线点 / C2 密文 / C3 杂凑），
没有规定二进制串行顺序。工程实现因此出现常见 wire 格式：

1. ``C1C2C3``（旧序）——早期实现与部分硬件设备的默认输出；
2. ``C1C3C2``（新序）——GM/T 0009 密文结构规范采用；
3. 前两者再叠加 0x04 未压缩点前缀（SEC1 风格，C1 显式带标记）；
4. ASN.1 DER（``DER``）——GM/T 0009 规定的结构化编码
   ``SEQUENCE { INTEGER C1x, INTEGER C1y, OCTET STRING C3, OCTET STRING C2 }``，
   Java BouncyCastle 默认输出。注意 DER 是变长编码：INTEGER 剥前导零、
   最高位为 1 时补 ``0x00`` 保正，坐标须左补零还原为 32 字节。

不同库之间（gmssl ``mode=0`` / ``mode=1``、OpenSSL SM2、各厂商 SDK）
默认格式不一，且部分实现 ``decrypt`` 不校验 C3——密文序错配时
静默返回垃圾明文而非报错。本模块提供：

- :func:`detect_format` —— 长度/首字节/结构启发式判别（DER 整结构解析）；
- :func:`convert` —— 五种格式间无损互转；
- :func:`verify_c3` —— 由共享点重算 KDF 密钥流与 C3（GM/T 0003.4/.5），
  收口静默错解；
- :func:`sm2_decrypt` / :func:`decrypt_ciphertext` —— GM/T 0003.4/.5
  标准解密（KDF-SM3 密钥流 + C3 强制校验，不一致即抛错、绝不返回
  未认证明文），供 CLI ``sip-sm2cvt decrypt`` 与外部互通消费。

约定
-----
- 裸格式 C1 固定 64 字节（x‖y，不含 0x04 前缀——前缀属于线格式的一部分）；
  DER 格式 C1 为两个 INTEGER，各 1~32 字节（剥前导零后），互转时
  按 32 字节左补零对齐；
- C3 固定 32 字节（SM3 输出）；
- C2 长度 = 明文长度，由总长反推（裸格式）或由 OCTET STRING 长度给出（DER）。
"""

from __future__ import annotations

from typing import Callable

from ..exceptions import Sm2CiphertextFormatError, Sm2DecryptError
from .sm2 import SM2PrivateKey, SM2PublicKey
from .sm3 import sm3_hash

__all__ = [
    "C1_LEN",
    "C3_LEN",
    "FMT_C1C2C3",
    "FMT_C1C3C2",
    "FMT_C1C2C3_04",
    "FMT_C1C3C2_04",
    "FMT_DER",
    "KNOWN_FORMATS",
    "Sm2CiphertextFormatError",
    "Sm2DecryptError",
    "detect_format",
    "convert",
    "verify_c3",
    "sm2_decrypt",
    "decrypt_ciphertext",
]

# --- 长度常量 -------------------------------------------------------------

C1_LEN = 64  #: C1 椭圆曲线点（x‖y，不含 0x04 前缀）
C3_LEN = 32  #: C3 = SM3(x2‖M‖y2) 杂凑

# --- 线格式标识 -----------------------------------------------------------

FMT_C1C2C3 = "C1C2C3"  #: 旧序，无前缀
FMT_C1C3C2 = "C1C3C2"  #: 新序（GM/T 0009），无前缀
FMT_C1C2C3_04 = "C1C2C3+04"  #: 旧序，0x04 未压缩点前缀
FMT_C1C3C2_04 = "C1C3C2+04"  #: 新序，0x04 未压缩点前缀
FMT_DER = "DER"  #: ASN.1 DER（GM/T 0009 结构化编码，Java BouncyCastle 默认输出）

KNOWN_FORMATS = (FMT_C1C2C3, FMT_C1C3C2, FMT_C1C2C3_04, FMT_C1C3C2_04, FMT_DER)

# --- DER（ASN.1）标签/长度常量 ---------------------------------------------

_TAG_INTEGER = 0x02  #: DER INTEGER 标签（C1x / C1y）
_TAG_OCTET_STRING = 0x04  #: DER OCTET STRING 标签（C3 / C2）
_TAG_SEQUENCE = 0x30  #: DER SEQUENCE 标签（最外层）
_COORD_LEN = 32  #: C1 单坐标长（x / y 各 32 字节，DER 互转对齐基准）


# --- 内部工具 -------------------------------------------------------------


def _split_raw(ct: bytes, c3_first: bool) -> tuple[bytes, bytes, bytes]:
    """按（无前缀）总长切出 C1 / C2 / C3 三段。"""
    if len(ct) < C1_LEN + C3_LEN + 1:
        raise Sm2CiphertextFormatError(f"密文过短：{len(ct)} 字节（最少 {C1_LEN + C3_LEN + 1}）")
    c1 = ct[:C1_LEN]
    if c3_first:
        c3 = ct[C1_LEN : C1_LEN + C3_LEN]
        c2 = ct[C1_LEN + C3_LEN :]
    else:
        c2 = ct[C1_LEN:-C3_LEN]
        c3 = ct[-C3_LEN:]
    return c1, c2, c3


def _strip_prefix(ct: bytes, fmt: str) -> tuple[bytes, str]:
    """剥掉 0x04 前缀（若格式声明带前缀），返回（裸密文, 无前缀格式）。"""
    if fmt not in KNOWN_FORMATS:
        raise Sm2CiphertextFormatError(f"未知格式标识：{fmt!r}")
    if fmt.endswith("+04"):
        if not ct or ct[0] != 0x04:
            raise Sm2CiphertextFormatError("声明带 0x04 前缀但首字节不是 0x04")
        return ct[1:], fmt[:-3]  # "+04" 3 字符
    return ct, fmt


def _c1c2c3_to_bytes(c1: bytes, c2: bytes, c3: bytes, c3_first: bool) -> bytes:
    """按目标顺序拼接，C3 在前为新序。"""
    return c1 + (c3 + c2 if c3_first else c2 + c3)


# --- DER（ASN.1）编解码 ------------------------------------------------------


def _der_encode_length(length: int) -> bytes:
    """DER 长度编码：短形（< 0x80）单字节，长形 ``0x80|字节数`` 前缀。"""
    if length < 0x80:
        return bytes([length])
    payload = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(payload)]) + payload


def _der_tlv(tag: int, value: bytes) -> bytes:
    """编码一个 TLV 元素（标签 + DER 长度 + 值）。"""
    return bytes([tag]) + _der_encode_length(len(value)) + value


def _der_encode_coordinate(coord: bytes) -> bytes:
    """C1 坐标（定长 32 字节）→ 最小 INTEGER：剥前导零，最高位为 1 补 0x00 保正。"""
    minimal = coord.lstrip(b"\x00") or b"\x00"
    if minimal[0] & 0x80:
        minimal = b"\x00" + minimal
    return _der_tlv(_TAG_INTEGER, minimal)


def _der_encode(c1: bytes, c2: bytes, c3: bytes) -> bytes:
    """(C1, C2, C3) → GM/T 0009 ASN.1 密文 ``SEQUENCE{x, y, C3, C2}``。"""
    body = (
        _der_encode_coordinate(c1[:_COORD_LEN])
        + _der_encode_coordinate(c1[_COORD_LEN:])
        + _der_tlv(_TAG_OCTET_STRING, c3)
        + _der_tlv(_TAG_OCTET_STRING, c2)
    )
    return _der_tlv(_TAG_SEQUENCE, body)


def _der_decode_length(data: bytes, offset: int) -> tuple[int, int]:
    """解析 DER 长度 → (长度, 值起始偏移)；长形须最小（值 ≥ 0x80）。"""
    if offset >= len(data):
        raise Sm2CiphertextFormatError("DER 长度截断")
    first = data[offset]
    if first < 0x80:
        return first, offset + 1
    size = first & 0x7F
    if size == 0 or offset + 1 + size > len(data):
        raise Sm2CiphertextFormatError(f"DER 长度编码非法：0x{first:02x}")
    length = int.from_bytes(data[offset + 1 : offset + 1 + size], "big")
    if length < 0x80:
        raise Sm2CiphertextFormatError("DER 长形编码非最小（值 < 0x80 须用短形）")
    return length, offset + 1 + size


def _der_decode_tlv(data: bytes, offset: int, tag: int, what: str) -> tuple[bytes, int]:
    """按期望标签解析一个 TLV → (值, 下一元素起始偏移)。"""
    if offset >= len(data) or data[offset] != tag:
        raise Sm2CiphertextFormatError(f"DER {what} 标签不符（期望 0x{tag:02x}）")
    length, value_at = _der_decode_length(data, offset + 1)
    end = value_at + length
    if end > len(data):
        raise Sm2CiphertextFormatError(f"DER {what} 长度越界（声明 {length} 字节）")
    return data[value_at:end], end


def _der_decode_coordinate(value: bytes, what: str) -> bytes:
    """C1 坐标 INTEGER 值 → 定长 32 字节：校验范围与最小编码后左补零对齐。"""
    if len(value) > _COORD_LEN + 1:
        raise Sm2CiphertextFormatError(
            f"DER {what} 超出 SM2 曲线坐标范围（{len(value)} 字节 INTEGER）"
        )
    if len(value) > 1 and value[0] == 0 and not value[1] & 0x80:
        raise Sm2CiphertextFormatError(f"DER {what} INTEGER 非最小编码（多余前导 0x00）")
    return int.from_bytes(value, "big").to_bytes(_COORD_LEN, "big")


def _der_decode(ct: bytes) -> tuple[bytes, bytes, bytes]:
    """解析 GM/T 0009 ASN.1 密文 → (C1, C2, C3)；结构/最小性不符即抛错。"""
    body, end = _der_decode_tlv(ct, 0, _TAG_SEQUENCE, "SEQUENCE")
    if end != len(ct):
        raise Sm2CiphertextFormatError("DER SEQUENCE 后有多余字节")
    x, off = _der_decode_tlv(body, 0, _TAG_INTEGER, "C1x")
    y, off = _der_decode_tlv(body, off, _TAG_INTEGER, "C1y")
    c3, off = _der_decode_tlv(body, off, _TAG_OCTET_STRING, "C3")
    c2, off = _der_decode_tlv(body, off, _TAG_OCTET_STRING, "C2")
    if off != len(body):
        raise Sm2CiphertextFormatError("DER SEQUENCE 内有多余元素")
    if len(c3) != C3_LEN:
        raise Sm2CiphertextFormatError(f"DER C3 长度 {len(c3)} 字节（期望 {C3_LEN}）")
    if not c2:
        raise Sm2CiphertextFormatError("DER C2 为空")
    c1 = _der_decode_coordinate(x, "C1x") + _der_decode_coordinate(y, "C1y")
    return c1, c2, c3


# --- 三元组归一（裸格式与 DER 统一入口） -------------------------------------


def _to_components(ct: bytes, fmt: str) -> tuple[bytes, bytes, bytes]:
    """已声明格式的密文 → (C1, C2, C3) 三元组（DER 走 ASN.1 解析）。"""
    if fmt not in KNOWN_FORMATS:
        raise Sm2CiphertextFormatError(f"未知格式标识：{fmt!r}")
    if fmt == FMT_DER:
        return _der_decode(ct)
    raw, base = _strip_prefix(ct, fmt)
    return _split_raw(raw, c3_first=base == FMT_C1C3C2)


def _from_components(c1: bytes, c2: bytes, c3: bytes, fmt: str) -> bytes:
    """(C1, C2, C3) 三元组 → 目标格式密文。"""
    if fmt == FMT_DER:
        return _der_encode(c1, c2, c3)
    out = _c1c2c3_to_bytes(c1, c2, c3, c3_first=fmt.startswith(FMT_C1C3C2))
    return b"\x04" + out if fmt.endswith("+04") else out


def _kdf(z: bytes, klen: int) -> bytes:
    """GM/T 0003.4 密钥派生函数（SM3 计数器模式）：SM3(z ‖ ct) 级联截断到 klen。"""
    out = bytearray()
    ct = 1
    while len(out) < klen:
        out += sm3_hash(z + ct.to_bytes(4, "big"))
        ct += 1
    return bytes(out[:klen])


# --- 公开接口 -------------------------------------------------------------


def detect_format(ct: bytes) -> str:
    """启发式判别密文线格式。

    判别依据（置信度从高到低）：

    1. 首字节 0x30 且整结构按 ASN.1 解析成功 → ``DER``（结构完整自证，
       误报概率可忽略）；解析失败则视为首字节恰为 0x30 的裸密文，继续下探；
    2. 首字节 0x04 且剥前缀后长度 ≥ 最小密文长 → 带 04 前缀；
    3. 无前缀时 C2/C3 顺序无法从长度区分（C3 定长），返回缺省旧序
       ``C1C2C3`` 并由调用方通过 :func:`verify_c3` 复核。

    参数
    ----
    ct:
        完整密文线字节。

    返回
    ----
    五个格式标识之一（裸格式场景无法仅凭字节判序，恒返回旧序，
    调用方应以 verify_c3 的结果为准）。

    异常
    ----
    Sm2CiphertextFormatError
        长度不满足任何合法格式时抛出。
    """
    min_len = C1_LEN + C3_LEN + 1
    if ct and ct[0] == _TAG_SEQUENCE:
        try:
            _der_decode(ct)
            return FMT_DER
        except Sm2CiphertextFormatError:
            pass  # 首字节恰为 0x30 的裸密文——落回裸格式启发式
    if ct and ct[0] == 0x04 and len(ct) - 1 >= min_len:
        # 前缀存在；顺序不可判，缺省报旧序带前缀
        return FMT_C1C2C3_04
    if len(ct) >= min_len:
        return FMT_C1C2C3
    raise Sm2CiphertextFormatError(f"密文长度 {len(ct)} 不满足任何合法格式（最小 {min_len}）")


def convert(ct: bytes, from_fmt: str, to_fmt: str) -> bytes:
    """SM2 密文线格式互转（无损，五格式含 ASN.1 DER）。

    参数
    ----
    ct:
        原始密文线字节。
    from_fmt / to_fmt:
        KNOWN_FORMATS 中的格式标识。

    异常
    ----
    Sm2CiphertextFormatError
        格式标识未知、前缀声明与字节不符、DER 结构非法、或长度不合法。
    """
    if from_fmt not in KNOWN_FORMATS or to_fmt not in KNOWN_FORMATS:
        raise Sm2CiphertextFormatError(
            f"格式标识必须属于 {KNOWN_FORMATS}，收到 from={from_fmt!r} to={to_fmt!r}"
        )
    c1, c2, c3 = _to_components(ct, from_fmt)
    return _from_components(c1, c2, c3, to_fmt)


def verify_c3(
    ct: bytes,
    fmt: str,
    derive: Callable[[bytes], bytes],
    hasher: Callable[[bytes], bytes] = sm3_hash,
) -> bool:
    """重算 C3 校验密文完整性（防下游库静默错解）。

    部分实现（典型如某些 gmssl 版本的 ``CryptSM2.decrypt``）不校验
    C3——顺序错配时照样返回"成功"与垃圾明文。此函数在解密**前**
    独立复核 C3，错配即返回 False，调用方可据此换序重试或报错。

    参数
    ----
    ct:
        完整密文线字节。
    fmt:
        声明的线格式（KNOWN_FORMATS 之一，含 DER）。
    derive:
        共享点派生函数 ``derive(c1) -> x2‖y2``（64 字节）——即以私钥
        对 C1 做标量乘得到的椭圆曲线共享点坐标（[d]C1 = [k]PB）。
        KDF 密钥流与 C3 均由本函数按标准重算，调用方无需关心。
    hasher:
        C3 杂凑函数，缺省 :func:`sip_protocol.crypto.sm3.sm3_hash`。

    返回
    ----
    bool —— C3 重算一致为 True；不一致（顺序错配/被篡改）为 False。

    异常
    ----
    Sm2CiphertextFormatError
        格式/长度非法、DER 结构非法、或 derive 返回的共享点长度不是
        64 字节。
    ValueError
        derive 未提供。
    """
    if derive is None:
        raise ValueError("必须提供 derive（共享点派生函数）")

    c1, c2, c3 = _to_components(ct, fmt)

    shared = derive(c1)
    if len(shared) != C1_LEN:
        raise Sm2CiphertextFormatError(
            f"derive 返回 {len(shared)} 字节（期望 {C1_LEN} 字节共享点 x2‖y2）"
        )
    # C2 = M ⊕ KDF(x2‖y2, klen)（GM/T 0003.4）；M = c2 XOR keystream 还原明文
    keystream = _kdf(shared, len(c2))
    msg = bytes(a ^ b for a, b in zip(c2, keystream))
    # C3 = Hash(x2 ‖ M ‖ y2)（GM/T 0003.5，消息居中；x2‖y2 是共享点，不是 C1）
    half = C1_LEN // 2
    expect = hasher(shared[:half] + msg + shared[half:])
    return expect == c3


def sm2_decrypt(privkey_int: int, c1_point: tuple[int, int], c2: bytes, c3: bytes) -> bytes:
    """GM/T 0003.4/.5 标准 SM2 解密核心：还原明文并强制校验 C3。

    流程（GB/T 32918.4 / GM/T 0003.4 第 9.2 节）：

    1. 共享点 ``[d]C1 = (x2, y2)``——C1 经在曲线/非无穷远点校验，
       私钥标量经 ``[1, n)`` 范围校验（均由 :mod:`crypto.sm2` 承载）；
    2. ``t = KDF(x2‖y2, klen)``（SM3 计数器模式），标准要求 t 全零
       即失败（概率 2^-256，防御性保留；空消息 klen=0 不在此列）；
    3. ``M = C2 ⊕ t``；
    4. 复算 ``C3 = Hash(x2‖M‖y2)``（SM3）与密文内 C3 比对，不一致
       视为解密失败——顺序错配/密文被篡改/私钥不属此密文均落此处，
       **绝不返回未认证明文**。

    参数
    ----
    privkey_int:
        解密方私钥标量 d（``[1, n)`` 内整数）。
    c1_point:
        密文椭圆曲线点 C1（ ``(x1, y1)`` 仿射坐标二元组）。
    c2:
        密文数据分量（长度即明文长度 klen）。
    c3:
        密文杂凑分量（32 字节 SM3）。

    返回
    ----
    bytes —— 认证通过的明文 M。

    异常
    ----
    Sm2DecryptError
        C3 复算不一致（SIP-CRYPTO-005）或 KDF 密钥流全零。
    ValueError
        C1 不在推荐曲线上（或为无穷远点）、私钥标量越界——与
        :mod:`crypto.sm2` 的既有校验同源。
    """
    # SM2PublicKey 构造即在曲线校验；SM2PrivateKey 构造即 [1, n) 校验
    shared = SM2PrivateKey(privkey_int).exchange_point(SM2PublicKey(c1_point))
    keystream = _kdf(shared, len(c2))
    if c2 and not keystream.strip(b"\x00"):
        raise Sm2DecryptError("KDF 密钥流全零——按 GM/T 0003.4 判定解密失败")
    msg = bytes(a ^ b for a, b in zip(c2, keystream))
    # C3 = Hash(x2 ‖ M ‖ y2)（GM/T 0003.5，消息居中；与 verify_c3 同一公式）
    half = C1_LEN // 2
    expect = sm3_hash(shared[:half] + msg + shared[half:])
    if expect != c3:
        raise Sm2DecryptError("C3 复算不一致——顺序错配或密文被篡改，可换另一顺序重试")
    return msg


def decrypt_ciphertext(ct: bytes, fmt: str, privkey_int: int) -> bytes:
    """密文线字节 + 声明格式 + 私钥 → 明文（解析层 + 解密核心一站式）。

    :func:`sm2_decrypt` 的编排入口：先按 ``fmt`` 解出 (C1, C2, C3)
    三元组（五格式含 ASN.1 DER，解析失败抛
    :class:`Sm2CiphertextFormatError`），再走标准解密。CLI
    ``sip-sm2cvt decrypt`` 即本函数的消费面。

    参数
    ----
    ct:
        完整密文线字节。
    fmt:
        声明的线格式（KNOWN_FORMATS 之一）。
    privkey_int:
        解密方私钥标量 d（``[1, n)`` 内整数）。

    返回
    ----
    bytes —— 认证通过的明文 M。

    异常
    ----
    Sm2CiphertextFormatError
        格式/长度非法、DER 结构非法。
    Sm2DecryptError
        C3 复算不一致或 KDF 密钥流全零。
    ValueError
        C1 不在曲线上、私钥标量越界。
    """
    c1, c2, c3 = _to_components(ct, fmt)
    c1_point = (
        int.from_bytes(c1[: C1_LEN // 2], "big"),
        int.from_bytes(c1[C1_LEN // 2 :], "big"),
    )
    return sm2_decrypt(privkey_int, c1_point, c2, c3)
