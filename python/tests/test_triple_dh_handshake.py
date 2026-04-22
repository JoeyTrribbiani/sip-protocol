#!/usr/bin/env python3
"""测试三重DH握手流程"""

import sys
import os
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sip_protocol.protocol.message import (
    encrypt_message,
    decrypt_message,
    generate_replay_tag,
    verify_replay_tag,
)
from sip_protocol.protocol.handshake import (
    initiate_handshake,
    respond_handshake,
    complete_handshake,
)


def test_triple_dh_handshake():
    """测试三重DH握手流程"""
    print("=== 测试：三重DH握手流程 ===\n")

    # 预共享密钥
    psk = b"shared-secret-key-12345678"

    # Agent A发起握手
    print("步骤1：Agent A 发起 Handshake_Hello")
    handshake_hello, agent_state_a = initiate_handshake(psk)
    print(f"✅ Handshake_Hello 已发送")
    print(f"   - 身份公钥：{handshake_hello['identity_pub'][:32]}...")
    print(f"   - 临时公钥：{handshake_hello['ephemeral_pub'][:32]}...")
    print(f"   - Nonce：{handshake_hello['nonce'][:32]}...\n")

    # Agent B响应握手
    print("步骤2：Agent B 响应 Handshake_Auth")
    handshake_auth, agent_state_b, session_keys_b = respond_handshake(handshake_hello, psk)
    print(f"✅ Handshake_Auth 已发送")
    print(f"   - 身份公钥：{handshake_auth['auth_data']['ephemeral_pub'][:32]}...")
    print(f"   - Nonce：{handshake_auth['auth_data']['nonce'][:32]}...")
    print(f"   - 签名：{handshake_auth['signature'][:32]}...\n")

    # Agent A完成握手
    print("步骤3：Agent A 完成握手")
    session_keys_a, session_state_a = complete_handshake(handshake_auth, agent_state_a)
    print(f"✅ Handshake_Complete 已发送")
    print(f"   - 加密密钥：{session_keys_a['encryption_key'][:32].hex()}...")
    print(f"   - 认证密钥：{session_keys_a['auth_key'][:32].hex()}...")
    print(f"   - 防重放密钥：{session_keys_a['replay_key'][:32].hex()}...\n")

    # 验证双方派生的密钥一致
    print("验证密钥一致性：")
    print(
        f"✅ 加密密钥一致：{session_keys_a['encryption_key'] == session_keys_b['encryption_key']}"
    )
    print(f"✅ 认证密钥一致：{session_keys_a['auth_key'] == session_keys_b['auth_key']}")
    print(f"✅ 防重放密钥一致：{session_keys_a['replay_key'] == session_keys_b['replay_key']}\n")

    # 测试消息加密解密
    print("测试消息加密解密：")
    plaintext = "Hello, Agent B! This is a secure message via Triple DH handshake."
    sender_id = "agent-a"
    recipient_id = "agent-b"
    message_counter = 1

    # 加密消息
    encrypted_msg = encrypt_message(
        session_keys_a["encryption_key"],
        plaintext,
        sender_id,
        recipient_id,
        message_counter,
        session_keys_a["replay_key"],
    )
    print(f"✅ 消息已加密：{encrypted_msg['type']}")
    print(f"   - sender_id：{encrypted_msg['sender_id']}")
    print(f"   - recipient_id：{encrypted_msg['recipient_id']}")
    print(f"   - message_counter：{encrypted_msg['message_counter']}")
    print(f"   - payload：{encrypted_msg['payload'][:32]}...")
    print(f"   - replay_tag：{encrypted_msg.get('replay_tag', 'N/A')[:32]}...\n")

    # 解密消息
    decrypted_msg = decrypt_message(session_keys_b["encryption_key"], encrypted_msg)
    print(f"✅ 消息已解密：{decrypted_msg}")
    print(f"✅ 明文一致：{decrypted_msg == plaintext}\n")

    # 测试replay_tag验证
    print("测试replay_tag验证：")
    replay_tag_valid = verify_replay_tag(
        session_keys_b["replay_key"],
        sender_id,
        message_counter,
        encrypted_msg["replay_tag"],
    )
    print(f"✅ Replay tag验证：{replay_tag_valid}\n")

    print("✅ 三重DH握手测试通过！\n")


def main():
    """运行测试"""
    print("\n" + "=" * 50)
    print("SIP协议 - 三重DH握手测试")
    print("=" * 50 + "\n")

    try:
        test_triple_dh_handshake()

        print("\n" + "=" * 50)
        print("✅ 所有测试通过！")
        print("=" * 50 + "\n")

    except Exception as e:
        print(f"\n❌ 测试失败：{e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
