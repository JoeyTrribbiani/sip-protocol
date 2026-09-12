"""密码套件定义与公共分派辅助（SPEC v1.1 §3）

SIP 支持两套密码套件，握手时经 Hello 的可选 suite 字段协商（§4.2）：
- EN（默认，国际套件）：X25519 / ChaCha20-Poly1305 / HKDF-SHA256 / HMAC-SHA256
- ZH（国密套件）：SM2 / SM4-GCM / HKDF-SM3 / HMAC-SM3（ADR-001 选型）

PSK 拉伸（Argon2id）为套件无关组件（ADR-001 决策 5，红线：PSK 路径不动）。
向后兼容：协议消息中 suite 字段缺省视为 EN。
"""

import hashlib

from .sm3 import SM3Hash

SUITE_EN = "EN"
SUITE_ZH = "ZH"
SUPPORTED_SUITES = (SUITE_EN, SUITE_ZH)

# 各套件 DH 公钥的 Raw 线格式字节长度（X25519 32B / SM2 非压缩点 65B）
PUBLIC_KEY_LENGTH = {SUITE_EN: 32, SUITE_ZH: 65}
# 各套件 AEAD 密钥字节长度（ChaCha20 32B / SM4-128 16B）
AEAD_KEY_LENGTH = {SUITE_EN: 32, SUITE_ZH: 16}


def validate_suite(suite: str) -> str:
    """校验套件取值，非法即抛 ValueError（明确报错，不静默回退）"""
    if suite not in SUPPORTED_SUITES:
        raise ValueError(f"未知的密码套件: {suite!r}（支持: {', '.join(SUPPORTED_SUITES)}）")
    return suite


def digestmod(suite: str):
    """返回套件对应的 HMAC 摘要构造器：EN → hashlib.sha256，ZH → SM3Hash"""
    validate_suite(suite)
    if suite == SUITE_ZH:
        return SM3Hash
    return hashlib.sha256
