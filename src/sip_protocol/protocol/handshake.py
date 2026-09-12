"""
握手协议模块
实现SIP握手流程（三重DH + HMAC签名）

v1.1 起支持密码套件协商（SPEC §4.2/§4.5）：suite=ZH 走国密套件
（SM2 / HKDF-SM3 / HMAC-SM3），缺省 EN 行为与历史版本逐位一致。
"""

import json
import os
import time
import hmac
import base64
from ..crypto.dh import (
    dh_exchange,
    generate_keypair,
    parse_public_key,
    serialize_public_key,
)
from ..crypto.argon2 import hash_psk
from ..crypto.hkdf import derive_keys_triple_dh
from ..crypto.suite import SUITE_EN, SUITE_ZH, digestmod, validate_suite
from ..exceptions import SuiteNegotiationError, VersionNegotiationError

HANDSHAKE_NONCE_LENGTH = 16
PROTOCOL_VERSION = "SIP-1.0"


def negotiate_suite(offered: str, local: str) -> str:
    """套件协商（SPEC §4.5）：对端 offered 与本地 local 必须一致

    offered 取自 Hello 的可选 suite 字段（缺省 EN=向后兼容，旧 peer 无此字段）。
    单选语义、无降级回退——与 §11.2 版本拒绝的防降级哲学一致；
    不一致/未知值在任何密码学计算之前抛 SuiteNegotiationError。
    """
    validate_suite(local)
    if offered not in (SUITE_EN, SUITE_ZH):
        raise SuiteNegotiationError(message=f"未知的密码套件: {offered!r}（支持: EN, ZH）")
    if offered != local:
        raise SuiteNegotiationError(
            message=f"密码套件协商失败: 对端要求 {offered}，本地配置 {local}（无降级回退）"
        )
    return local


def initiate_handshake(
    psk: bytes, identity_private_key=None, identity_public_key=None, suite: str = SUITE_EN
):
    """
    发起握手（三重DH + 身份密钥对）

    Args:
        psk: 预共享密钥
        identity_private_key: 身份私钥（可选，用于持久化）
        identity_public_key: 身份公钥（可选，用于持久化）
        suite: 密码套件（EN=国际默认；ZH=国密，Hello 携带 suite 字段）

    Returns:
        Tuple[dict, dict]: (handshake_hello, agent_state)
    """
    validate_suite(suite)

    # 生成或使用身份密钥对（持久化）
    if identity_private_key is None or identity_public_key is None:
        identity_private_key, identity_public_key = generate_keypair(suite)

    # 生成临时密钥对（每次握手不同）
    ephemeral_private_key, ephemeral_public_key = generate_keypair(suite)

    # 生成Nonce
    nonce = os.urandom(HANDSHAKE_NONCE_LENGTH)

    # 序列化公钥（EN → X25519 Raw 32B；ZH → SM2 非压缩点 65B）
    identity_pub_bytes = serialize_public_key(identity_public_key)
    ephemeral_pub_bytes = serialize_public_key(ephemeral_public_key)

    # 构建Handshake_Hello消息（EN 不携带 suite 字段——wire 逐字节不变；ZH 显式声明）
    handshake_hello = {
        "version": PROTOCOL_VERSION,
        "type": "handshake",
        "step": "hello",
        "timestamp": int(time.time() * 1000),
        "identity_pub": identity_pub_bytes.hex(),
        "ephemeral_pub": ephemeral_pub_bytes.hex(),
        "nonce": nonce.hex(),
    }
    if suite == SUITE_ZH:
        handshake_hello["suite"] = SUITE_ZH

    # 保存Agent状态
    agent_state = {
        "identity_private_key": identity_private_key,
        "identity_public_key": identity_public_key,
        "ephemeral_private_key": ephemeral_private_key,
        "ephemeral_public_key": ephemeral_public_key,
        "psk": psk,
        "nonce": nonce,
        "role": "initiator",
        "suite": suite,
    }

    return handshake_hello, agent_state


def respond_handshake(
    handshake_hello: dict,
    psk: bytes,
    identity_private_key=None,
    identity_public_key=None,
    suite: str = SUITE_EN,
):
    """
    响应握手（三重DH + HMAC签名）

    Args:
        handshake_hello: Handshake_Hello消息
        psk: 预共享密钥
        identity_private_key: 身份私钥（可选，用于持久化）
        identity_public_key: 身份公钥（可选，用于持久化）
        suite: 本地密码套件配置（与 Hello 声明不一致即协商失败）

    Returns:
        Tuple[dict, dict, dict]: (handshake_auth, agent_state, session_keys)
    """
    # 版本校验（SPEC §11.2：不认识的版本在任何密码学计算之前拒绝）
    if handshake_hello.get("version") != PROTOCOL_VERSION:
        raise VersionNegotiationError(
            message=f"不支持的协议版本: {handshake_hello.get('version')}（期望 {PROTOCOL_VERSION}）"
        )

    # 套件协商（SPEC §4.5：缺省字段=EN 向后兼容；不一致/未知值在任何密码学计算之前拒绝）
    suite = negotiate_suite(handshake_hello.get("suite", SUITE_EN), suite)

    # 验证时间戳（±5分钟）
    current_time = int(time.time() * 1000)
    hello_time = handshake_hello["timestamp"]
    if abs(current_time - hello_time) > 5 * 60 * 1000:
        raise ValueError("时间戳验证失败：消息过期")

    # 解析Handshake_Hello（长度与套件不符给出协商向明确错误——含 suite 字段被剥离的跨套件握手）
    remote_identity_pub = parse_public_key(bytes.fromhex(handshake_hello["identity_pub"]), suite)
    remote_ephemeral_pub = parse_public_key(bytes.fromhex(handshake_hello["ephemeral_pub"]), suite)
    remote_nonce = bytes.fromhex(handshake_hello["nonce"])

    # 生成或使用身份密钥对（持久化）
    if identity_private_key is None or identity_public_key is None:
        identity_private_key, identity_public_key = generate_keypair(suite)

    # 生成临时密钥对（每次握手不同）
    ephemeral_private_key, ephemeral_public_key = generate_keypair(suite)

    nonce = os.urandom(HANDSHAKE_NONCE_LENGTH)

    # 序列化本地公钥
    identity_pub_bytes = serialize_public_key(identity_public_key)
    ephemeral_pub_bytes = serialize_public_key(ephemeral_public_key)

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
    # 注意：由于DH的对称性，shared_1和shared_2在双方视角下是交换的。
    # 为了派生相同的会话密钥，响应方需要交换shared_1和shared_2的顺序，以匹配发起方的视角。
    # 发起方（A）计算：shared_1 (identity_a × eph_b), shared_2 (eph_a × identity_b), shared_3 (eph_a × eph_b)
    # 响应方（B）计算：shared_1 (identity_b × eph_a), shared_2 (eph_b × identity_a), shared_3 (eph_b × eph_a)
    # 由于identity_b × eph_a = eph_a × identity_b，所以shared_1和shared_2在双方是交换的。
    # 响应方需要按照发起方的视角重新排列：shared_1'=shared_2, shared_2'=shared_1, shared_3'=shared_3
    session_keys = derive_keys_triple_dh(
        shared_2, shared_1, shared_3, psk_hash, remote_nonce, nonce, suite
    )
    encryption_key = session_keys[0]
    auth_key = session_keys[1]
    replay_key = session_keys[2]

    # 生成HMAC签名（EN → HMAC-SHA256；ZH → HMAC-SM3）
    # 注意：auth_data不包含identity_pub，只包含ephemeral_pub、nonce和timestamp
    timestamp = int(time.time() * 1000)
    auth_data = {
        "ephemeral_pub": ephemeral_pub_bytes.hex(),
        "nonce": nonce.hex(),
        "timestamp": timestamp,
    }
    auth_json = json.dumps(auth_data).encode()
    signature = hmac.new(auth_key, auth_json, digestmod(suite)).digest()

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
    # ZH 显式回显套件（发起方校验点；EN 不加字段——wire 逐字节不变）
    if suite == SUITE_ZH:
        handshake_auth["suite"] = SUITE_ZH

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
        "suite": suite,
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
        agent_state: Agent状态（携带发起方本地套件）

    Returns:
        Tuple[dict, dict]: (session_keys, session_state)
    """
    # 版本校验（SPEC §11.2）
    if handshake_auth.get("version") != PROTOCOL_VERSION:
        raise VersionNegotiationError(
            message=f"不支持的协议版本: {handshake_auth.get('version')}（期望 {PROTOCOL_VERSION}）"
        )

    # 套件确认（SPEC §4.5）：Auth 回显的套件须与本地一致（缺省 EN=向后兼容）
    suite = negotiate_suite(handshake_auth.get("suite", SUITE_EN), agent_state["suite"])

    # 验证时间戳（±5分钟）
    current_time = int(time.time() * 1000)
    auth_time = handshake_auth["timestamp"]
    if abs(current_time - auth_time) > 5 * 60 * 1000:
        raise ValueError("时间戳验证失败：消息过期")

    # 解析Handshake_Auth
    # identity_pub在消息的顶层，不在auth_data中
    remote_identity_pub = parse_public_key(bytes.fromhex(handshake_auth["identity_pub"]), suite)
    remote_ephemeral_pub = parse_public_key(
        bytes.fromhex(handshake_auth["auth_data"]["ephemeral_pub"]), suite
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

    # PSK哈希
    psk_hash, _ = hash_psk(agent_state["psk"])

    # 派生会话密钥（三重DH）
    session_keys = derive_keys_triple_dh(
        shared_1, shared_2, shared_3, psk_hash, agent_state["nonce"], remote_nonce, suite
    )
    encryption_key = session_keys[0]
    auth_key = session_keys[1]
    replay_key = session_keys[2]

    # 验证HMAC签名（EN → HMAC-SHA256；ZH → HMAC-SM3）
    # 注意：auth_data不包含identity_pub，只包含ephemeral_pub、nonce和timestamp
    auth_data = {
        "ephemeral_pub": handshake_auth["auth_data"]["ephemeral_pub"],
        "nonce": handshake_auth["auth_data"]["nonce"],
        "timestamp": handshake_auth["timestamp"],
    }
    auth_json = json.dumps(auth_data).encode()
    expected_signature = hmac.new(auth_key, auth_json, digestmod(suite)).digest()

    if not hmac.compare_digest(signature, expected_signature):
        raise ValueError("HMAC签名验证失败")

    # 生成Handshake_Complete消息
    complete_auth_data = {"status": "verified"}
    complete_auth_json = json.dumps(complete_auth_data).encode()
    complete_signature = hmac.new(auth_key, complete_auth_json, digestmod(suite)).digest()

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
        "suite": suite,
    }

    return (
        {"encryption_key": encryption_key, "auth_key": auth_key, "replay_key": replay_key},
        session_state,
    )
