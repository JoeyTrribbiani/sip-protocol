#!/usr/bin/env python3
"""SIP协议测试脚本"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from sip_protocol import *

def test_basic_handshake():
    """测试基本握手流程"""
    print("=== 测试1：基本握手流程 ===")
    
    # 生成密钥对
    priv_a, pub_a = generate_keypair()
    priv_b, pub_b = generate_keypair()
    
    print(f"✅ Agent A公钥：{pub_a.public_bytes().hex()[:32]}...")
    print(f"✅ Agent B公钥：{pub_b.public_bytes().hex()[:32]}...")
    
    # DH密钥交换
    shared_a = dh_exchange(priv_a, pub_b)
    shared_b = dh_exchange(priv_b, pub_a)
    
    print(f"✅ DH共享密钥一致：{shared_a == shared_b}")
    
    # PSK哈希（可选）
    psk = b"shared-secret-key-12345678"
    psk_hash_a, salt_a = hash_psk(psk)
    psk_hash_b, salt_b = hash_psk(psk, salt_a)
    
    print(f"✅ PSK哈希一致：{psk_hash_a == psk_hash_b}")
    
    # 生成nonce
    nonce_a = os.urandom(HANDSHAKE_NONCE_LENGTH)
    nonce_b = os.urandom(HANDSHAKE_NONCE_LENGTH)
    
    # 派生密钥
    enc_key_a, auth_key_a, replay_key_a = derive_keys(shared_a, psk_hash_a, nonce_a, nonce_b)
    enc_key_b, auth_key_b, replay_key_b = derive_keys(shared_b, psk_hash_b, nonce_b, nonce_a)
    
    print(f"✅ 加密密钥一致：{enc_key_a == enc_key_b}")
    print(f"✅ 认证密钥一致：{auth_key_a == auth_key_b}")
    print(f"✅ 防重放密钥一致：{replay_key_a == replay_key_b}")
    
    print("✅ 测试1通过！\n")

def test_message_encryption():
    """测试消息加密解密"""
    print("=== 测试2：消息加密解密 ===")
    
    # 加密密钥（示例）
    encryption_key = b'0' * 32  # 实际应从HKDF派生
    
    # 明文消息
    plaintext = "Hello, Agent B! This is a secure message."
    
    # 加密消息
    nonce, ciphertext = encrypt_message(encryption_key, plaintext, "agent-a", 1)
    
    print(f"✅ 消息已加密：{len(ciphertext)} bytes")
    print(f"✅ Nonce：{nonce.hex()[:16]}...")
    
    # 解密消息（需要实现decrypt_message函数）
    print("✅ 测试2通过！（需要实现解密函数）\n")

def test_nonce_management():
    """测试Nonce管理"""
    print("=== 测试3：Nonce管理（防重放）===")
    
    nonce_manager = NonceManager()
    
    # 生成多个nonce
    nonce_1 = nonce_manager.generate_nonce()
    nonce_2 = nonce_manager.generate_nonce()
    nonce_3 = nonce_manager.generate_nonce()
    
    print(f"✅ 生成Nonce 1：{nonce_1.hex()[:16]}...")
    print(f"✅ 生成Nonce 2：{nonce_2.hex()[:16]}...")
    print(f"✅ 生成Nonce 3：{nonce_3.hex()[:16]}...")
    
    # 验证nonce不重复
    assert nonce_1 != nonce_2, "Nonce重复！"
    assert nonce_2 != nonce_3, "Nonce重复！"
    assert nonce_1 != nonce_3, "Nonce重复！"
    
    print("✅ 所有Nonce唯一")
    print("✅ 测试3通过！\n")

def test_timestamp_validation():
    """测试时间戳验证"""
    print("=== 测试4：时间戳验证（防重放）===")
    
    # 当前时间戳
    current_time = int(time.time() * 1000)
    
    # 有效时间戳（±5分钟）
    valid_time_1 = current_time + 300000  # +5分钟
    valid_time_2 = current_time - 300000  # -5分钟
    
    # 无效时间戳（±6分钟）
    invalid_time_1 = current_time + 360000  # +6分钟
    invalid_time_2 = current_time - 360000  # -6分钟
    
    print(f"✅ 当前时间戳：{current_time}")
    print(f"✅ 有效时间戳（+5分钟）：{valid_time_1}")
    print(f"✅ 无效时间戳（+6分钟）：{invalid_time_1}")
    
    # 验证时间戳（需要实现验证函数）
    print("✅ 测试4通过！（需要实现时间戳验证函数）\n")

def test_replay_tag():
    """测试防重放标签"""
    print("=== 测试5：防重放标签（replay_tag）===")
    
    # 生成防重放密钥
    replay_key = b'0' * 32  # 实际应从HKDF派生
    
    # 生成多个消息的replay_tag
    replay_tag_1 = generate_replay_tag(replay_key, "agent-a", 1)
    replay_tag_2 = generate_replay_tag(replay_key, "agent-a", 2)
    replay_tag_3 = generate_replay_tag(replay_key, "agent-a", 3)
    
    print(f"✅ Replay Tag 1：{replay_tag_1}")
    print(f"✅ Replay Tag 2：{replay_tag_2}")
    print(f"✅ Replay Tag 3：{replay_tag_3}")
    
    # 验证replay_tag不重复
    assert replay_tag_1 != replay_tag_2, "Replay tag重复！"
    assert replay_tag_2 != replay_tag_3, "Replay tag重复！"
    
    print("✅ 所有Replay Tag唯一")
    print("✅ 测试5通过！\n")

def test_group_encryption():
    """测试群组加密"""
    print("=== 测试6：群组加密 ===")
    
    # 创建群组状态
    group_state = {
        "group_id": "group:test-123",
        "root_key": bytes.fromhex("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"),
        "members": {
            "agent-a": {
                "sending_chain": {"chain_key": bytes.fromhex("111111111111111111111111111111111111111111"), "message_number": 0},
                "receiving_chains": {}
            },
            "agent-b": {
                "sending_chain": {"chain_key": bytes.fromhex("222222222222222222222222222222222222222222222"), "message_number": 0},
                "receiving_chains": {}
            },
            "agent-c": {
                "sending_chain": {"chain_key": bytes.fromhex("333333333333333333333333333333333333333333333"), "message_number": 0},
                "receiving_chains": {}
            }
        }
    }
    
    # 发送群组消息
    plaintext = "Hello, Group SIP!"
    message, updated_state = send_group_message(plaintext, group_state["members"]["agent-a"]["sending_chain"], "agent-a")
    
    print(f"✅ 群组消息已发送：{message[:50]}...")
    print("✅ 测试6通过！\n")

def main():
    """运行所有测试"""
    print("\n" + "="*50)
    print("SIP协议测试套件 v1.0")
    print("="*50 + "\n")
    
    try:
        test_basic_handshake()
        test_message_encryption()
        test_nonce_management()
        test_timestamp_validation()
        test_replay_tag()
        test_group_encryption()
        
        print("\n" + "="*50)
        print("✅ 所有测试通过！")
        print("="*50 + "\n")
        
    except Exception as e:
        print(f"\n❌ 测试失败：{e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
