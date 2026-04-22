"""
握手协议模块
实现SIP握手流程（三重DH + HMAC签名）
"""

import json
import os
import time
import hmac
import hashlib
import base64
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization
from ..crypto.dh import generate_keypair, dh_exchange
from ..crypto.argon2 import hash_psk
from ..crypto.hkdf import derive_keys_triple_dh

HANDSHAKE_NONCE_LENGTH = 16
PROTOCOL_VERSION = "SIP-1.0"


def initiate_handshake(psk: bytes, identity_private_key=None, identity_public_key=None):
    """
    发起握手（三重DH + 身份密钥对）

    Args:
        psk: 预共享密钥
        identity_private_key: 身份私钥（可选，用于持久化）
        identity_public_key: 身份公钥（可选，用于持久化）

    Returns:
        Tuple[dict, dict]: (handshake_hello, agent_state)
    """
    # 生成或使用身份密钥对（持久化）
    if identity_private_key is None or identity_public_key is None:
        identity_private_key = x25519.X25519PrivateKey.generate()
        identity_public_key = identity_private_key.public_key()

    # 生成临时密钥对（每次握手不同）
    ephemeral_private_key, ephemeral_public_key = generate_keypair()

    # 生成Nonce
    nonce = os.urandom(HANDSHAKE_NONCE_LENGTH)

    # 序列化公钥
    identity_pub_bytes = identity_public_key.public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    ephemeral_pub_bytes = ephemeral_public_key.public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )

    # 构建Handshake_Hello消息
    handshake_hello = {
        "version": PROTOCOL_VERSION,
        "type": "handshake",
        "step": "hello",
        "timestamp": int(time.time() * 1000),
        "identity_pub": identity_pub_bytes.hex(),
        "ephemeral_pub": ephemeral_pub_bytes.hex(),
        "nonce": nonce.hex(),
    }

    # 保存Agent状态
    agent_state = {
        "identity_private_key": identity_private_key,
        "identity_public_key": identity_public_key,
        "ephemeral_private_key": ephemeral_private_key,
        "ephemeral_public_key": ephemeral_public_key,
        "psk": psk,
        "nonce": nonce,
        "role": "initiator",
    }

    return handshake_hello, agent_state


def respond_handshake(
    handshake_hello: dict, psk: bytes, identity_private_key=None, identity_public_key=None
):
    """
    响应握手（三重DH + HMAC签名）

    Args:
        handshake_hello: Handshake_Hello消息
        psk: 预共享密钥
        identity_private_key: 身份私钥（可选，用于持久化）
        identity_public_key: 身份公钥（可选，用于持久化）

    Returns:
        Tuple[dict, dict, dict]: (handshake_auth, agent_state, session_keys)
    """
    # 验证时间戳（±5分钟）
    current_time = int(time.time() * 1000)
    hello_time = handshake_hello["timestamp"]
    if abs(current_time - hello_time) > 5 * 60 * 1000:
        raise ValueError("时间戳验证失败：消息过期")

    # 解析Handshake_Hello
    remote_identity_pub = x25519.X25519PublicKey.from_public_bytes(
        bytes.fromhex(handshake_hello["identity_pub"])
    )
    remote_ephemeral_pub = x25519.X25519PublicKey.from_public_bytes(
        bytes.fromhex(handshake_hello["ephemeral_pub"])
    )
    remote_nonce = bytes.fromhex(handshake_hello["nonce"])

    # 生成或使用身份密钥对（持久化）
    if identity_private_key is None or identity_public_key is None:
        identity_private_key = x25519.X25519PrivateKey.generate()
        identity_public_key = identity_private_key.public_key()

    # 生成临时密钥对（每次握手不同）
    ephemeral_private_key, ephemeral_public_key = generate_keypair()
    nonce = os.urandom(HANDSHAKE_NONCE_LENGTH)

    # 序列化本地公钥
    identity_pub_bytes = identity_public_key.public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    ephemeral_pub_bytes = ephemeral_public_key.public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )

    # 三重DH密钥交换（响应方视角）
    # shared_1: identity_local × remote_ephemeral
    shared_1 = dh_exchange(identity_private_key, remote_ephemeral_pub)
    # shared_2: ephemeral_local × remote_identity
    shared_2 = dh_exchange(ephemeral_private_key, remote_identity_pub)
    # shared_3: ephemeral_local × remote_ephemeral
    shared_3 = dh_exchange(ephemeral_private_key, remote_ephemeral_pub)

    # PSK哈希
    psk_hash, _ = hash_psk(psk)

    # 派生会话密钥（三重DH）
    # 注意：由于X25519的对称性，shared_1和shared_2在双方视角下是交换的。
    # 为了派生相同的会话密钥，响应方需要交换shared_1和shared_2的顺序，以匹配发起方的视角。
    # 发起方（A）计算：shared_1 (identity_a × eph_b), shared_2 (eph_a × identity_b), shared_3 (eph_a × eph_b)
    # 响应方（B）计算：shared_1 (identity_b × eph_a), shared_2 (eph_b × identity_a), shared_3 (eph_b × eph_a)
    # 由于identity_b × eph_a = eph_a × identity_b，所以shared_1和shared_2在双方是交换的。
    # 响应方需要按照发起方的视角重新排列：shared_1'=shared_2, shared_2'=shared_1, shared_3'=shared_3
    session_keys = derive_keys_triple_dh(
        shared_2, shared_1, shared_3, psk_hash, remote_nonce, nonce
    )
    encryption_key = session_keys[0]
    auth_key = session_keys[1]
    replay_key = session_keys[2]

    # 序列化identity公钥
    identity_pub_bytes = identity_public_key.public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )

    # 生成HMAC签名
    # 注意：auth_data不包含identity_pub，只包含ephemeral_pub、nonce和timestamp
    timestamp = int(time.time() * 1000)
    auth_data = {
        "ephemeral_pub": ephemeral_pub_bytes.hex(),
        "nonce": nonce.hex(),
        "timestamp": timestamp,
    }
    auth_json = json.dumps(auth_data).encode()
    signature = hmac.new(auth_key, auth_json, hashlib.sha256).digest()

    # 构建Handshake_Auth消息
    # 注意：identity_pub在消息的顶层，不在auth_data中
    handshake_auth = {
        "version": PROTOCOL_VERSION,
        "type": "handshake",
        "step": "auth",
        "timestamp": timestamp,  # 复用同一个timestamp变量，确保HMAC验证一致
        "identity_pub": identity_pub_bytes.hex(),  # 身份公钥在顶层
        "auth_data": {
            "ephemeral_pub": ephemeral_pub_bytes.hex(),
            "nonce": nonce.hex(),
        },
        "signature": base64.b64encode(signature).decode(),
    }

    # 保存Agent状态
    agent_state = {
        "identity_private_key": identity_private_key,
        "identity_public_key": identity_public_key,
        "ephemeral_private_key": ephemeral_private_key,
        "ephemeral_public_key": ephemeral_public_key,
        "psk": psk,
        "nonce": nonce,
        "remote_identity_pub": remote_identity_pub,
        "remote_ephemeral_pub": remote_ephemeral_pub,
        "remote_nonce": remote_nonce,
        "role": "responder",
    }

    return (
        handshake_auth,
        agent_state,
        {"encryption_key": encryption_key, "auth_key": auth_key, "replay_key": replay_key},
    )


def complete_handshake(handshake_auth: dict, agent_state: dict):
    """
    完成握手（三重DH + HMAC验证）

    Args:
        handshake_auth: Handshake_Auth消息
        agent_state: Agent状态

    Returns:
        Tuple[dict, dict]: (session_keys, session_state)
    """
    # 验证时间戳（±5分钟）
    current_time = int(time.time() * 1000)
    auth_time = handshake_auth["timestamp"]
    if abs(current_time - auth_time) > 5 * 60 * 1000:
        raise ValueError("时间戳验证失败：消息过期")

    # 解析Handshake_Auth
    # identity_pub在消息的顶层，不在auth_data中
    remote_identity_pub = x25519.X25519PublicKey.from_public_bytes(
        bytes.fromhex(handshake_auth["identity_pub"])
    )
    remote_ephemeral_pub = x25519.X25519PublicKey.from_public_bytes(
        bytes.fromhex(handshake_auth["auth_data"]["ephemeral_pub"])
    )
    remote_nonce = bytes.fromhex(handshake_auth["auth_data"]["nonce"])
    signature = base64.b64decode(handshake_auth["signature"])

    # 三重DH密钥交换（发起方视角）
    # shared_1: identity_local × remote_ephemeral
    shared_1 = dh_exchange(agent_state["identity_private_key"], remote_ephemeral_pub)
    # shared_2: ephemeral_local × remote_identity
    shared_2 = dh_exchange(agent_state["ephemeral_private_key"], remote_identity_pub)
    # shared_3: ephemeral_local × remote_ephemeral
    shared_3 = dh_exchange(agent_state["ephemeral_private_key"], remote_ephemeral_pub)

    # 三重DH密钥交换（发起方视角）
    # shared_1: identity_local × remote_ephemeral
    shared_1 = dh_exchange(agent_state["identity_private_key"], remote_ephemeral_pub)
    # shared_2: ephemeral_local × remote_identity
    shared_2 = dh_exchange(agent_state["ephemeral_private_key"], remote_identity_pub)
    # shared_3: ephemeral_local × remote_ephemeral
    shared_3 = dh_exchange(agent_state["ephemeral_private_key"], remote_ephemeral_pub)

    # PSK哈希
    psk_hash, _ = hash_psk(agent_state["psk"])

    # 派生会话密钥（三重DH）
    session_keys = derive_keys_triple_dh(
        shared_1, shared_2, shared_3, psk_hash, agent_state["nonce"], remote_nonce
    )
    encryption_key = session_keys[0]
    auth_key = session_keys[1]
    replay_key = session_keys[2]

    # 验证HMAC签名
    # 注意：auth_data不包含identity_pub，只包含ephemeral_pub、nonce和timestamp
    auth_data = {
        "ephemeral_pub": handshake_auth["auth_data"]["ephemeral_pub"],
        "nonce": handshake_auth["auth_data"]["nonce"],
        "timestamp": handshake_auth["timestamp"],
    }
    auth_json = json.dumps(auth_data).encode()
    expected_signature = hmac.new(auth_key, auth_json, hashlib.sha256).digest()

    if not hmac.compare_digest(signature, expected_signature):
        raise ValueError("HMAC签名验证失败")

    # 生成Handshake_Complete消息
    complete_auth_data = {"status": "verified"}
    complete_auth_json = json.dumps(complete_auth_data).encode()
    complete_signature = hmac.new(auth_key, complete_auth_json, hashlib.sha256).digest()

    handshake_complete = {
        "version": PROTOCOL_VERSION,
        "type": "handshake",
        "step": "complete",
        "timestamp": int(time.time() * 1000),
        "auth_data": complete_auth_data,
        "signature": base64.b64encode(complete_signature).decode(),
    }

    # 构建会话状态
    session_state = {
        "version": PROTOCOL_VERSION,
        "encryption_key": encryption_key,
        "auth_key": auth_key,
        "replay_key": replay_key,
        "created_at": time.time(),
        "handshake_complete": handshake_complete,
    }

    return (
        {"encryption_key": encryption_key, "auth_key": auth_key, "replay_key": replay_key},
        session_state,
    )
