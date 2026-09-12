"""
SIP Protocol Library
Secure Inter-agent Protocol - Agent间端到端加密通道库（纯加密层）

密码套件：EN（默认，X25519/ChaCha20-Poly1305/HKDF-SHA256）与
ZH（国密 SM2/SM4-GCM/HKDF-SM3），握手时经 suite 字段协商（SPEC v1.1）。
"""

__version__ = "2.2.0"
