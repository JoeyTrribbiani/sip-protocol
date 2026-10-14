"""SM2 加密密文的线格式互转与校验（GM/T 0003.5 工程互通层）。

背景
----
GM/T 0003.5 只定义了密文各分量（C1 椭圆曲线点 / C2 密文 / C3 杂凑），
没有规定二进制串行顺序。工程实现因此出现三种常见 wire 格式：

1. ``C1C2C3``（旧序）——早期实现与部分硬件设备的默认输出；
2. ``C1C3C2``（新序）——GM/T 0009 密文结构规范采用；
3. 前两者再叠加 0x04 未压缩点前缀（SEC1 风格，C1 显式带标记）。

不同库之间（gmssl ``mode=0`` / ``mode=1``、OpenSSL SM2、各厂商 SDK）
默认格式不一，且部分实现 ``decrypt`` 不校验 C3——密文序错配时
静默返回垃圾明文而非报错。本模块提供：

- :func:`detect_format` —— 长度与首字节启发式判别；
- :func:`convert` —— 三种格式间无损互转；
- :func:`verify_c3` —— 以 KDF 派生密钥流重算 C3，收口静默错解。

约定
-----
- C1 固定 64 字节（x‖y，不含 0x04 前缀——前缀属于线格式的一部分）；
- C3 固定 32 字节（SM3 输出）；
- C2 长度 = 明文长度，由总长反推。
"""

from __future__ import annotations

from typing import Callable, Optional

from ..exceptions import CryptoError
from .sm3 import sm3_hash

__all__ = [
    "C1_LEN",
    "C3_LEN",
    "FMT_C1C2C3",
    "FMT_C1C3C2",
    "FMT_C1C2C3_04",
    "FMT_C1C3C2_04",
    "KNOWN_FORMATS",
    "Sm2CiphertextFormatError",
    "detect_format",
    "convert",
    "verify_c3",
]

# --- 长度常量 -------------------------------------------------------------

C1_LEN = 64  #: C1 椭圆曲线点（x‖y，不含 0x04 前缀）
C3_LEN = 32  #: C3 = SM3(x2‖M‖y2) 杂凑

# --- 线格式标识 -----------------------------------------------------------

FMT_C1C2C3 = "C1C2C3"        #: 旧序，无前缀
FMT_C1C3C2 = "C1C3C2"        #: 新序（GM/T 0009），无前缀
FMT_C1C2C3_04 = "C1C2C3+04"  #: 旧序，0x04 未压缩点前缀
FMT_C1C3C2_04 = "C1C3C2+04"  #: 新序，0x04 未压缩点前缀

KNOWN_FORMATS = (FMT_C1C2C3, FMT_C1C3C2, FMT_C1C2C3_04, FMT_C1C3C2_04)


class Sm2CiphertextFormatError(CryptoError):
    """SM2 密文线格式非法或与声明不符。"""


# --- 内部工具 -------------------------------------------------------------


def _split_raw(ct: bytes, c3_first: bool) -> tuple[bytes, bytes, bytes]:
    """按（无前缀）总长切出 C1 / C2 / C3 三段。"""
    if len(ct) < C1_LEN + C3_LEN + 1:
        raise Sm2CiphertextFormatError(
            f"密文过短：{len(ct)} 字节（最少 {C1_LEN + C3_LEN + 1}）"
        )
    c1 = ct[:C1_LEN]
    if c3_first:
        c3 = ct[C1_LEN:C1_LEN + C3_LEN]
        c2 = ct[C1_LEN + C3_LEN:]
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


# --- 公开接口 -------------------------------------------------------------


def detect_format(ct: bytes) -> str:
    """启发式判别密文线格式。

    判别依据（置信度从高到低）：

    1. 首字节 0x04 且剥前缀后长度 ≥ 最小密文长 → 带 04 前缀；
    2. 无前缀时 C2/C3 顺序无法从长度区分（C3 定长），返回缺省旧序
       ``C1C2C3`` 并由调用方通过 :func:`verify_c3` 复核。

    参数
    ----
    ct:
        完整密文线字节。

    返回
    ----
    四个格式标识之一（无前缀场景无法仅凭字节判序，恒返回旧序，
    调用方应以 verify_c3 的结果为准）。

    异常
    ----
    Sm2CiphertextFormatError
        长度不满足任何合法格式时抛出。
    """
    min_len = C1_LEN + C3_LEN + 1
    if ct and ct[0] == 0x04 and len(ct) - 1 >= min_len:
        # 前缀存在；顺序不可判，缺省报旧序带前缀
        return FMT_C1C2C3_04
    if len(ct) >= min_len:
        return FMT_C1C2C3
    raise Sm2CiphertextFormatError(
        f"密文长度 {len(ct)} 不满足任何合法格式（最小 {min_len}）"
    )


def convert(ct: bytes, from_fmt: str, to_fmt: str) -> bytes:
    """SM2 密文线格式互转（无损）。

    参数
    ----
    ct:
        原始密文线字节。
    from_fmt / to_fmt:
        KNOWN_FORMATS 中的格式标识。

    异常
    ----
    Sm2CiphertextFormatError
        格式标识未知、前缀声明与字节不符、或长度不合法。
    """
    if from_fmt not in KNOWN_FORMATS or to_fmt not in KNOWN_FORMATS:
        raise Sm2CiphertextFormatError(
            f"格式标识必须属于 {KNOWN_FORMATS}，收到 from={from_fmt!r} to={to_fmt!r}"
        )
    raw, base = _strip_prefix(ct, from_fmt)
    c1, c2, c3 = _split_raw(raw, c3_first=(base == FMT_C1C3C2))
    out = _c1c2c3_to_bytes(c1, c2, c3, c3_first=to_fmt.startswith(FMT_C1C3C2))
    if to_fmt.endswith("+04"):
        return b"\x04" + out
    return out


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
        声明的线格式（KNOWN_FORMATS 之一）。
    derive:
        密钥流派生函数 ``derive(c1) -> keystream(len(c2))``，
        即以 C1 点坐标经 KDF 得到与 C2 等长的异或流。
    hasher:
        C3 杂凑函数，缺省 :func:`sip_protocol.crypto.sm3.sm3_hash`。

    返回
    ----
    bool —— C3 重算一致为 True；不一致（顺序错配/被篡改）为 False。

    异常
    ----
    Sm2CiphertextFormatError
        格式/长度非法、或派生密钥流不足以覆盖 C2。
    ValueError
        derive 未提供。
    """
    if derive is None:
        raise ValueError("必须提供 derive（密钥流派生函数）")

    raw, base = _strip_prefix(ct, fmt)
    c1, c2, c3 = _split_raw(raw, c3_first=(base == FMT_C1C3C2))

    # C3 = Hash(x2 ‖ M ‖ y2)；此处 M = c2 XOR keystream 还原明文
    keystream = derive(c1)
    if len(keystream) < len(c2):
        raise Sm2CiphertextFormatError(
            f"派生密钥流 {len(keystream)} 字节不足以覆盖 C2 {len(c2)} 字节"
        )
    msg = bytes(a ^ b for a, b in zip(c2, keystream))
    # x2‖y2 即 c1 本身（c1 = x‖y 各 32 字节）
    expect = hasher(c1 + msg)
    return expect == c3
