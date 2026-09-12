"""SM2 椭圆曲线密钥交换模块（GM/T 0003.5-2012 推荐曲线 sm2p256v1）

实现范围：密钥对生成 + 原始 ECDH（共享秘密 = [d]P 的 x 坐标，32 字节大端），
作为三重 DH 的 SM2 类比（K1/K2/K3，SPEC §4.3）；不涉及 SM2 签名/加密
（GM/T 0003.2/.5 的签名/加密形态与本协议无关）。

接口与 cryptography 的 X25519 密钥对象鸭子类型对齐（public_key/exchange/
from_public_bytes/private_bytes），使 protocol/ 层按套件透明分派。

安全边界（ADR-001 / SPEC §12/§13 如实记述）：
- 纯 Python 非常量时间（与纯 Python 国密库同等限制）；
- 对端公钥先做在曲线/非无穷远点校验再进 ECDH（防无效曲线攻击）；
- 曲线 cofactor=1，在曲线上的非无穷远点阶必为 n，标量范围 [1, n) 时
  [d]P 必非无穷远；
- 与 gmssl（独立实现）在 tests/test_sm_crypto.py 双向交叉验证。
"""

import os

# GM/T 0003.5-2012 推荐曲线参数（sm2p256v1，256 位素域）
_P = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
_A = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
_B = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
_N = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
_G = (
    0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7,
    0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0,
)

# 线格式：非压缩 SEC1 风格 0x04 ‖ X(32) ‖ Y(32)，共 65 字节
PUBLIC_KEY_LENGTH = 65
PRIVATE_KEY_LENGTH = 32
_COORDINATE_LENGTH = 32


def _on_curve(point: tuple[int, int]) -> bool:
    """点是否在曲线 y² = x³ + ax + b 上（mod p）"""
    x_coord, y_coord = point
    return (y_coord * y_coord - (x_coord**3 + _A * x_coord + _B)) % _P == 0


def _point_add(
    point1: tuple[int, int] | None, point2: tuple[int, int] | None
) -> tuple[int, int] | None:
    """仿射点加；None 表示无穷远点（加法单位元）"""
    if point1 is None:
        return point2
    if point2 is None:
        return point1
    x1, y1 = point1
    x2, y2 = point2
    if x1 == x2:
        if (y1 + y2) % _P == 0:
            return None  # 互逆点相加得无穷远
        # 倍点：λ = (3x² + a) / (2y)
        slope = (3 * x1 * x1 + _A) * pow(2 * y1, -1, _P) % _P
    else:
        slope = (y2 - y1) * pow(x2 - x1, -1, _P) % _P
    x3 = (slope * slope - x1 - x2) % _P
    y3 = (slope * (x1 - x3) - y1) % _P
    return x3, y3


def _scalar_mult(k: int, point: tuple[int, int]) -> tuple[int, int] | None:
    """double-and-add 标量乘（LSB 优先迭代）；k 为正整数"""
    result: tuple[int, int] | None = None
    addend: tuple[int, int] | None = point
    while k:
        if k & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        k >>= 1
    return result


class SM2PublicKey:
    """SM2 公钥（在推荐曲线上的非无穷远点）"""

    def __init__(self, point: tuple[int, int]) -> None:
        if not _on_curve(point):
            raise ValueError("SM2 公钥不在推荐曲线上（或为无穷远点）")
        self.point = point

    @classmethod
    def from_public_bytes(cls, data: bytes) -> "SM2PublicKey":
        """从 65 字节非压缩格式（0x04 ‖ X ‖ Y）解析并校验"""
        if len(data) != PUBLIC_KEY_LENGTH or data[0] != 0x04:
            raise ValueError(
                f"SM2 公钥格式非法: {len(data)} 字节"
                f"（期望 {PUBLIC_KEY_LENGTH} 字节非压缩 0x04 前缀）"
            )
        x_coord = int.from_bytes(data[1 : 1 + _COORDINATE_LENGTH], "big")
        y_coord = int.from_bytes(data[1 + _COORDINATE_LENGTH :], "big")
        return cls((x_coord, y_coord))

    def public_bytes(self) -> bytes:
        """序列化为 65 字节非压缩格式"""
        x_coord, y_coord = self.point
        return b"\x04" + x_coord.to_bytes(
            _COORDINATE_LENGTH, "big"
        ) + y_coord.to_bytes(_COORDINATE_LENGTH, "big")


class SM2PrivateKey:
    """SM2 私钥（[1, n) 内的标量 d）"""

    def __init__(self, scalar: int) -> None:
        if not 1 <= scalar < _N:
            raise ValueError(f"SM2 私钥标量越界: {scalar}（期望 [1, n)）")
        self._scalar = scalar

    @staticmethod
    def generate() -> "SM2PrivateKey":
        """从 os.urandom 生成私钥（拒绝采样保证 [1, n) 均匀性）"""
        while True:
            scalar = int.from_bytes(os.urandom(PRIVATE_KEY_LENGTH), "big")
            if 1 <= scalar < _N:
                return SM2PrivateKey(scalar)

    @classmethod
    def from_private_bytes(cls, data: bytes) -> "SM2PrivateKey":
        """从 32 字节大端标量解析"""
        if len(data) != PRIVATE_KEY_LENGTH:
            raise ValueError(f"SM2 私钥长度非法: {len(data)} 字节（期望 {PRIVATE_KEY_LENGTH}）")
        return cls(int.from_bytes(data, "big"))

    def private_bytes(self) -> bytes:
        """序列化为 32 字节大端标量"""
        return self._scalar.to_bytes(PRIVATE_KEY_LENGTH, "big")

    def public_key(self) -> SM2PublicKey:
        """派生公钥 P = [d]G"""
        return SM2PublicKey(_scalar_mult(self._scalar, _G))

    def exchange(self, peer_public_key: SM2PublicKey) -> bytes:
        """原始 ECDH：共享秘密 = [d]P_peer 的 x 坐标（32 字节大端）"""
        if not isinstance(peer_public_key, SM2PublicKey):
            raise ValueError("SM2 exchange 需要 SM2PublicKey 对端公钥")
        shared = _scalar_mult(self._scalar, peer_public_key.point)
        if shared is None:
            # 防御性分支：cofactor=1 且 d ∈ [1, n) 时理论不可达（见模块注释）
            raise ValueError("SM2 ECDH 得到无穷远点（对端公钥非法）")
        x_coord, _y_coord = shared
        return x_coord.to_bytes(_COORDINATE_LENGTH, "big")
