"""
SIP协议完整实现
统一导出所有模块
"""

# 常量
from .crypto.hkdf import KDF_SALT, KDF_INFO
from .crypto.aes_gcm import AES_GCM_NONCE_LENGTH
from .protocol.handshake import HANDSHAKE_NONCE_LENGTH
from .protocol.group import MESSAGE_KEY_LENGTH, CHAIN_KEY_LENGTH

# Crypto模块
from .crypto.dh import generate_keypair, dh_exchange
from .crypto.hkdf import hkdf, derive_keys
from .crypto.argon2 import hash_psk
from .crypto.aes_gcm import encrypt_aes_gcm, decrypt_aes_gcm

# Protocol模块
from .protocol.handshake import (
    initiate_handshake,
    respond_handshake,
    complete_handshake
)
from .protocol.message import (
    encrypt_message,
    decrypt_message,
    generate_replay_tag,
    verify_replay_tag
)
from .protocol.group import GroupManager

# Managers模块
from .managers.nonce import NonceManager
from .managers.session import SessionState

__all__ = [
    # 常量
    'KDF_SALT',
    'KDF_INFO',
    'HANDSHAKE_NONCE_LENGTH',
    'MESSAGE_KEY_LENGTH',
    'CHAIN_KEY_LENGTH',
    'AES_GCM_NONCE_LENGTH',

    # Crypto模块
    'generate_keypair',
    'dh_exchange',
    'hkdf',
    'derive_keys',
    'hash_psk',
    'encrypt_aes_gcm',
    'decrypt_aes_gcm',

    # Protocol模块
    'initiate_handshake',
    'respond_handshake',
    'complete_handshake',
    'encrypt_message',
    'decrypt_message',
    'generate_replay_tag',
    'verify_replay_tag',

    # Managers模块
    'NonceManager',
    'SessionState',
    'GroupManager'
]
