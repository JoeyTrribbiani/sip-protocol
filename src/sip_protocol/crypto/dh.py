"""DH密钥交换模块
实现按套件分派的密钥交换：EN → X25519（RFC 7748），ZH → SM2（GM/T 0003.5）

接口签名向后兼容：缺省 suite=SUITE_EN 时行为与历史版本一致。
两套件的密钥对象鸭子类型对齐（public_key()/exchange()/序列化辅助），
上层协议代码经本模块的生成/序列化/解析辅助透明分派（SPEC §4.3）。
"""

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519

from .sm2 import SM2PrivateKey, SM2PublicKey
from .suite import PUBLIC_KEY_LENGTH, SUITE_EN, SUITE_ZH, validate_suite


def generate_keypair(suite: str = SUITE_EN):
    """
    生成密钥对（按套件分派）

    Args:
        suite: 密码套件（EN → X25519 密钥对象；ZH → SM2 密钥对象）

    Returns:
        Tuple[private_key, public_key]: 私钥和公钥
    """
    validate_suite(suite)
    if suite == SUITE_ZH:
        private_key = SM2PrivateKey.generate()
        return private_key, private_key.public_key()
    private_key = x25519.X25519PrivateKey.generate()
    return private_key, private_key.public_key()


def dh_exchange(private_key, public_key):
    """
    ECDH密钥交换（套件透明：两套件私钥对象均有 exchange()）

    Args:
        private_key: 本地私钥（X25519PrivateKey 或 SM2PrivateKey）
        public_key: 远程公钥（X25519PublicKey 或 SM2PublicKey）

    Returns:
        bytes: 共享密钥（两套件均为 32 字节）
    """
    shared_secret = private_key.exchange(public_key)
    return shared_secret


def serialize_public_key(public_key) -> bytes:
    """
    公钥序列化为 Raw 线格式（按对象类型分派）

    EN → X25519 Raw 32 字节；ZH → SM2 非压缩点 65 字节
    """
    if isinstance(public_key, SM2PublicKey):
        return public_key.public_bytes()
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )


def serialize_private_key(private_key) -> bytes:
    """
    私钥序列化为 Raw（按对象类型分派）；EN 32 字节 / ZH 32 字节标量

    仅供测试向量导出等场景使用，协议路径不传输私钥。
    """
    if isinstance(private_key, SM2PrivateKey):
        return private_key.private_bytes()
    return private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )


def parse_public_key(raw: bytes, suite: str = SUITE_EN):
    """
    从 Raw 字节解析公钥（按套件分派）

    Args:
        raw: 公钥原始字节（EN 期望 32 字节；ZH 期望 65 字节非压缩点）
        suite: 密码套件

    Returns:
        公钥对象（X25519PublicKey 或 SM2PublicKey）
    """
    validate_suite(suite)
    if len(raw) != PUBLIC_KEY_LENGTH[suite]:
        raise ValueError(
            f"公钥长度与套件 {suite} 不符: {len(raw)} 字节"
            f"（期望 {PUBLIC_KEY_LENGTH[suite]} 字节；跨套件/被剥离 suite 字段的"
            "握手会在此暴露）"
        )
    if suite == SUITE_ZH:
        return SM2PublicKey.from_public_bytes(raw)
    return x25519.X25519PublicKey.from_public_bytes(raw)
