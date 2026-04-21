"""
SIP协议主模块
导出所有公共API
"""

# 密码学模块
from src.crypto.dh import generate_keypair, dh_exchange
from src.crypto.argon2 import hash_psk
from src.crypto.hkdf import hkdf, derive_keys, derive_keys_triple_dh
from src.crypto.xchacha20_poly1305 import (
    encrypt_xchacha20_poly1305,
    decrypt_xchacha20_poly1305,
    generate_nonce as generate_crypto_nonce,
    NONCE_LENGTH,
)

# 协议模块
from src.protocol.handshake import (
    initiate_handshake,
    respond_handshake,
    complete_handshake,
    HANDSHAKE_NONCE_LENGTH,
    PROTOCOL_VERSION,
)
from src.protocol.message import (
    encrypt_message,
    decrypt_message,
    generate_replay_tag,
    verify_replay_tag,
)

# 管理器模块
from src.managers.session import SessionState
from src.managers.group import GroupManager
from src.managers.nonce import NonceManager

# 常量
NONCE_LENGTH = NONCE_LENGTH
HANDSHAKE_NONCE_LENGTH = HANDSHAKE_NONCE_LENGTH
PROTOCOL_VERSION = PROTOCOL_VERSION

__all__ = [
    # 密码学
    "generate_keypair",
    "dh_exchange",
    "hash_psk",
    "hkdf",
    "derive_keys",
    "derive_keys_triple_dh",
    "encrypt_xchacha20_poly1305",
    "decrypt_xchacha20_poly1305",
    "generate_crypto_nonce",
    # 协议
    "initiate_handshake",
    "respond_handshake",
    "complete_handshake",
    "encrypt_message",
    "decrypt_message",
    "generate_replay_tag",
    "verify_replay_tag",
    # 管理器
    "SessionState",
    "GroupManager",
    "NonceManager",
    # 常量
    "NONCE_LENGTH",
    "HANDSHAKE_NONCE_LENGTH",
    "PROTOCOL_VERSION",
]
