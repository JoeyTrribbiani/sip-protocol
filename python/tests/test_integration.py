#!/usr/bin/env python3
"""
SIP协议端到端集成测试
测试从握手到消息加密到Rekey到连接恢复的完整流程
"""

import sys
import os
import time
import json
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.protocol.handshake import (
    initiate_handshake,
    respond_handshake,
    complete_handshake,
)
from src.protocol.message import encrypt_message, decrypt_message, generate_replay_tag
from src.protocol.rekey import RekeyManager
from src.protocol.resume import (
    serialize_session_state,
    deserialize_session_state,
    is_session_expired,
)
from src.managers.nonce import NonceManager
from src.managers.session import SessionState


def test_full_handshake_flow():
    """测试完整的握手流程"""
    print("\n=== 测试1：完整的握手流程 ===")

    # Agent A发起握手
    psk = b"shared-secret-key-12345678"
    handshake_hello, agent_a_state = initiate_handshake(psk)

    print(f"✅ Agent A发送Handshake_Hello")
    print(f"   - Version: {handshake_hello['version']}")
    print(f"   - Identity Pub: {handshake_hello['identity_pub'][:32]}...")
    print(f"   - Ephemeral Pub: {handshake_hello['ephemeral_pub'][:32]}...")

    # Agent B响应握手
    (
        handshake_auth,
        agent_b_state,
        agent_b_keys,
    ) = respond_handshake(handshake_hello, psk)

    print(f"✅ Agent B发送Handshake_Auth")
    print(f"   - Identity Pub: {handshake_auth['identity_pub'][:32]}...")

    # Agent A完成握手
    agent_a_keys, session_state = complete_handshake(handshake_auth, agent_a_state)

    print(f"✅ Agent A完成握手")
    print(f"   - Session State: {session_state['version']}")

    # 验证双方密钥一致
    assert agent_a_keys["encryption_key"] == agent_b_keys["encryption_key"], "加密密钥不一致！"
    assert agent_a_keys["auth_key"] == agent_b_keys["auth_key"], "认证密钥不一致！"
    assert agent_a_keys["replay_key"] == agent_b_keys["replay_key"], "防重放密钥不一致！"

    print("✅ 双方会话密钥一致")
    print("✅ 测试1通过！")

    # 继续其他测试
    _test_message_encryption_decryption(agent_a_keys["encryption_key"], agent_a_keys["replay_key"])
    _test_rekey_flow(session_state)
    _test_connection_resume(session_state)


def _test_message_encryption_decryption(encryption_key, replay_key):
    """测试消息加密和解密"""
    print("\n=== 测试2：消息加密和解密 ===")

    # Agent A发送消息
    plaintext = "Hello, Agent B! This is a secure message."
    encrypted_msg = encrypt_message(encryption_key, plaintext, "agent-a", "agent-b", 1, replay_key)

    print(f"✅ Agent A加密消息")
    print(f"   - Plaintext: {plaintext}")
    print(f"   - Ciphertext length: {len(encrypted_msg['payload'])} bytes")

    # Agent B解密消息
    decrypted_plaintext = decrypt_message(encryption_key, encrypted_msg)

    print(f"✅ Agent B解密消息")
    print(f"   - Decrypted: {decrypted_plaintext}")

    assert decrypted_plaintext == plaintext, "解密结果与明文不一致！"
    print("✅ 测试2通过！")


def _test_rekey_flow(session_state, is_initiator=True):
    """测试Rekey密钥轮换流程"""
    print("\n=== 测试3：Rekey密钥轮换流程 ===")

    # 创建双方的RekeyManager
    rekey_manager_a = RekeyManager(session_state, is_initiator=True)
    rekey_manager_b = RekeyManager(session_state, is_initiator=False)

    # Agent A发起Rekey
    rekey_request = rekey_manager_a.create_rekey_request(reason="scheduled")

    print(f"✅ Agent A发起Rekey")
    print(f"   - Reason: {rekey_request['request']['reason']}")
    print(f"   - Sequence: {rekey_request['sequence']}")

    # Agent B验证并处理Rekey请求
    is_valid = rekey_manager_b.validate_rekey_request(rekey_request)
    assert is_valid, "Rekey请求验证失败！"

    print("✅ Agent B验证Rekey请求")

    rekey_response = rekey_manager_b.process_rekey_request(rekey_request)

    print(f"✅ Agent B发送Rekey响应")
    print(f"   - Sequence: {rekey_response['sequence']}")

    # Agent A验证并处理Rekey响应
    is_valid = rekey_manager_a.validate_rekey_response(rekey_response)
    assert is_valid, "Rekey响应验证失败！"

    print("✅ Agent A验证Rekey响应")

    new_keys_a = rekey_manager_a.process_rekey_response(rekey_response)
    new_keys_b = rekey_manager_b._temp_new_keys

    print("✅ 双方派生新密钥")

    # 验证新密钥一致
    assert new_keys_a["encryption_key"] == new_keys_b["encryption_key"], "新加密密钥不一致！"
    assert new_keys_a["auth_key"] == new_keys_b["auth_key"], "新认证密钥不一致！"
    assert new_keys_a["replay_key"] == new_keys_b["replay_key"], "新防重放密钥不一致！"

    print("✅ 新密钥一致")

    # 应用新密钥
    rekey_manager_a.apply_new_keys(new_keys_a)
    rekey_manager_b.apply_new_keys(new_keys_b)

    print("✅ 双方应用新密钥")

    # 验证密钥已更新
    assert session_state["encryption_key"] == new_keys_a["encryption_key"], "密钥未更新！"
    print("✅ 测试3通过！")

    return session_state


def _test_connection_resume(session_state):
    """测试连接恢复流程"""
    print("\n=== 测试4：连接恢复流程 ===")

    # 创建会话恢复状态
    from src.protocol.resume import SessionResumeState

    resume_state = SessionResumeState(
        session_id="agent-a",
        partner_id="agent-b",
        established_at=session_state["created_at"],
        encryption_key=(
            session_state["encryption_key"].hex()
            if isinstance(session_state["encryption_key"], bytes)
            else session_state["encryption_key"]
        ),
        auth_key=(
            session_state["auth_key"].hex()
            if isinstance(session_state["auth_key"], bytes)
            else session_state["auth_key"]
        ),
        replay_key=(
            session_state["replay_key"].hex()
            if isinstance(session_state["replay_key"], bytes)
            else session_state["replay_key"]
        ),
        message_counter_send=0,
        message_counter_receive=0,
        last_rekey_sequence=0,
        rekey_key_derived=False,
    )

    # 序列化会话状态
    serialized = serialize_session_state(resume_state)

    print(f"✅ 序列化会话状态")
    print(f"   - Serialized length: {len(serialized)} bytes")

    # 反序列化会话状态
    deserialized_state = deserialize_session_state(serialized)

    print("✅ 反序列化会话状态")

    # 验证状态一致
    assert deserialized_state.session_id == resume_state.session_id, "会话ID不一致！"
    assert deserialized_state.partner_id == resume_state.partner_id, "伙伴ID不一致！"
    assert deserialized_state.established_at == resume_state.established_at, "建立时间不一致！"
    assert deserialized_state.encryption_key == resume_state.encryption_key, "加密密钥不一致！"
    assert deserialized_state.auth_key == resume_state.auth_key, "认证密钥不一致！"
    assert deserialized_state.replay_key == resume_state.replay_key, "防重放密钥不一致！"

    print("✅ 反序列化的状态与原始状态一致")

    # 检查会话是否过期
    is_expired = is_session_expired(resume_state)
    assert not is_expired, "会话不应该过期！"
    print("✅ 会话未过期")

    # 测试过期检查（创建一个过期的会话）
    from src.protocol.resume import SESSION_TTL

    expired_state = SessionResumeState(
        session_id="agent-a",
        partner_id="agent-b",
        established_at=int(time.time()) - SESSION_TTL - 1,  # 过期1秒
        encryption_key=session_state["encryption_key"].hex(),
        auth_key=session_state["auth_key"].hex(),
        replay_key=session_state["replay_key"].hex(),
        message_counter_send=0,
        message_counter_receive=0,
        last_rekey_sequence=0,
        rekey_key_derived=False,
    )
    is_expired = is_session_expired(expired_state)
    assert is_expired, "会话应该已过期！"
    print("✅ 过期会话检测正确")

    print("✅ 测试4通过！")


def test_full_lifecycle():
    """测试完整的生命周期流程"""
    print("\n=== 测试5：完整的生命周期流程 ===")

    # 1. 握手
    print("\n--- 阶段1：握手 ---")
    psk = b"shared-secret-key-12345678"
    handshake_hello, agent_a_state = initiate_handshake(psk)
    (
        handshake_auth,
        agent_b_state,
        agent_b_keys,
    ) = respond_handshake(handshake_hello, psk)
    agent_a_keys, session_state = complete_handshake(handshake_auth, agent_a_state)
    print("✅ 握手完成")

    # 2. 消息加密/解密
    print("\n--- 阶段2：消息加密/解密 ---")
    plaintext = "Hello, Agent B! First message."
    encrypted_msg = encrypt_message(
        agent_a_keys["encryption_key"],
        plaintext,
        "agent-a",
        "agent-b",
        1,
        agent_a_keys["replay_key"],
    )
    decrypted = decrypt_message(agent_b_keys["encryption_key"], encrypted_msg)
    assert decrypted == plaintext
    print("✅ 消息加密/解密成功")

    # 3. Rekey
    print("\n--- 阶段3：Rekey密钥轮换 ---")
    rekey_manager_a = RekeyManager(session_state, is_initiator=True)
    rekey_manager_b = RekeyManager(session_state, is_initiator=False)

    rekey_request = rekey_manager_a.create_rekey_request(reason="scheduled")
    rekey_response = rekey_manager_b.process_rekey_request(rekey_request)
    new_keys_a = rekey_manager_a.process_rekey_response(rekey_response)
    new_keys_b = rekey_manager_b._temp_new_keys

    assert new_keys_a["encryption_key"] == new_keys_b["encryption_key"]
    rekey_manager_a.apply_new_keys(new_keys_a)
    rekey_manager_b.apply_new_keys(new_keys_b)
    print("✅ Rekey密钥轮换成功")

    # 4. 用新密钥发送消息
    print("\n--- 阶段4：使用新密钥发送消息 ---")
    plaintext = "Hello, Agent B! Post-rekey message."
    encrypted_msg = encrypt_message(
        session_state["encryption_key"],
        plaintext,
        "agent-a",
        "agent-b",
        2,
        session_state["replay_key"],
    )
    decrypted = decrypt_message(session_state["encryption_key"], encrypted_msg)
    assert decrypted == plaintext
    print("✅ 新密钥加密/解密成功")

    # 5. 连接恢复
    print("\n--- 阶段5：连接恢复 ---")
    from src.protocol.resume import SessionResumeState

    resume_state = SessionResumeState(
        session_id="agent-a",
        partner_id="agent-b",
        established_at=session_state["created_at"],
        encryption_key=session_state["encryption_key"].hex(),
        auth_key=session_state["auth_key"].hex(),
        replay_key=session_state["replay_key"].hex(),
        message_counter_send=0,
        message_counter_receive=0,
        last_rekey_sequence=0,
        rekey_key_derived=False,
    )

    serialized = serialize_session_state(resume_state)
    deserialized = deserialize_session_state(serialized)

    assert deserialized.session_id == resume_state.session_id
    assert deserialized.encryption_key == resume_state.encryption_key
    print("✅ 连接恢复成功")

    # 6. 恢复后继续发送消息
    print("\n--- 阶段6：恢复后继续发送消息 ---")
    plaintext = "Hello, Agent B! Post-resume message."
    encrypted_msg = encrypt_message(
        session_state["encryption_key"],
        plaintext,
        "agent-a",
        "agent-b",
        3,
        session_state["replay_key"],
    )
    decrypted = decrypt_message(session_state["encryption_key"], encrypted_msg)
    assert decrypted == plaintext
    print("✅ 恢复后消息加密/解密成功")

    print("\n✅ 测试5通过！完整生命周期测试成功！")


def main():
    """运行所有集成测试"""
    print("\n" + "=" * 60)
    print("SIP协议端到端集成测试套件")
    print("=" * 60)

    try:
        # 测试1：完整的握手流程（包含测试2、3、4）
        test_full_handshake_flow()

        # 测试5：完整的生命周期流程
        test_full_lifecycle()

        print("\n" + "=" * 60)
        print("✅ 所有集成测试通过！")
        print("=" * 60 + "\n")

        return 0

    except Exception as e:
        print(f"\n❌ 测试失败：{e}")
        import traceback

        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
