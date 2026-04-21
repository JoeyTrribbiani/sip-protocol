"""
握手协议模块
实现SIP握手流程
"""

import json
import os
import time
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization
from .crypto.dh import generate_keypair, dh_exchange
from .crypto.argon2 import hash_psk
from .crypto.hkdf import derive_keys

HANDSHAKE_NONCE_LENGTH = 16
PROTOCOL_VERSION = "SIP-1.0"


async def initiate_handshake(psk: bytes):
    """
    发起握手

    Args:
        psk: 预共享密钥

    Returns:
        Tuple[dict, dict]: (handshake_hello, agent_state)
    """
    # 生成密钥对
    private_key, public_key = generate_keypair()

    # 生成Nonce
    nonce = os.urandom(HANDSHAKE_NONCE_LENGTH)

    # 构建Handshake_Hello消息
    handshake_hello = {
        "version": PROTOCOL_VERSION,
        "type": "handshake_hello",
        "ephemeral_public_key": public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        ).hex(),
        "nonce": nonce.hex()
    }

    # 保存Agent状态
    agent_state = {
        "private_key": private_key,
        "psk": psk,
        "nonce": nonce
    }

    return handshake_hello, agent_state


async def respond_handshake(handshake_hello: dict, psk: bytes):
    """
    响应握手

    Args:
        handshake_hello: Handshake_Hello消息
        psk: 预共享密钥

    Returns:
        Tuple[dict, dict, dict]: (handshake_auth, agent_state, session_keys)
    """

    # 解析Handshake_Hello
    ephemeral_public_key = x25519.X25519PublicKey.from_public_bytes(
        bytes.fromhex(handshake_hello["ephemeral_public_key"])
    )
    remote_nonce = bytes.fromhex(handshake_hello["nonce"])

    # 生成密钥对和Nonce
    private_key, public_key = generate_keypair()
    nonce = os.urandom(HANDSHAKE_NONCE_LENGTH)

    # DH密钥交换
    shared_secret = dh_exchange(private_key, ephemeral_public_key)

    # PSK哈希
    psk_hash, _ = await hash_psk(psk)

    # 派生会话密钥
    session_keys = derive_keys(shared_secret, psk_hash, nonce, remote_nonce)

    # 构建Handshake_Auth消息
    handshake_auth = {
        "version": PROTOCOL_VERSION,
        "type": "handshake_auth",
        "ephemeral_public_key": public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        ).hex(),
        "nonce": nonce.hex()
    }

    # 保存Agent状态
    agent_state = {
        "private_key": private_key,
        "psk": psk,
        "nonce": nonce,
        "remote_ephemeral_public_key": ephemeral_public_key
    }

    return handshake_auth, agent_state, session_keys


async def complete_handshake(handshake_auth: dict, agent_state: dict):
    """
    完成握手

    Args:
        handshake_auth: Handshake_Auth消息
        agent_state: Agent状态

    Returns:
        Tuple[dict, dict]: (session_keys, session_state)
    """
    from cryptography.hazmat.primitives import serialization

    # 解析Handshake_Auth
    ephemeral_public_key = serialization.Encoding.Raw.load(
        handshake_auth["ephemeral_public_key"]
    )
    remote_nonce = bytes.fromhex(handshake_auth["nonce"])

    # DH密钥交换
    shared_secret = dh_exchange(agent_state["private_key"], ephemeral_public_key)

    # PSK哈希
    psk_hash, _ = await hash_psk(agent_state["psk"])

    # 派生会话密钥
    encryption_key, auth_key, replay_key = derive_keys(
        shared_secret,
        psk_hash,
        agent_state["nonce"],
        remote_nonce
    )

    # 构建会话状态
    session_state = {
        "version": PROTOCOL_VERSION,
        "encryption_key": encryption_key,
        "auth_key": auth_key,
        "replay_key": replay_key,
        "created_at": time.time()
    }

    return {"encryption_key": encryption_key, "auth_key": auth_key, "replay_key": replay_key}, session_state
