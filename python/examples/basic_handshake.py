#!/usr/bin/env python3
"""SIP协议完整握手示例"""
import sys
import os
import json

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sip_protocol import *


def agent_a_init():
    """Agent A初始化"""
    print("=== Agent A初始化 ===")

    # 生成密钥对
    priv_a, pub_a = generate_keypair()
    print(f"Agent A公钥：{pub_a.public_bytes().hex()[:32]}...")

    # 生成PSK（可选）
    psk = b"shared-secret-key-12345678"
    psk_hash_a, salt_a = hash_psk(psk)
    print(f"PSK哈希：{psk_hash_a.hex()[:32]}...")

    # 生成nonce
    nonce_a = os.urandom(HANDSHAKE_NONCE_LENGTH)
    print(f"Nonce A：{nonce_a.hex()}...")

    return priv_a, pub_a, psk_hash_a, salt_a, nonce_a


def agent_b_init():
    """Agent B初始化"""
    print("\n=== Agent B初始化 ===")

    # 生成密钥对
    priv_b, pub_b = generate_keypair()
    print(f"Agent B公钥：{pub_b.public_bytes().hex()[:32]}...")

    # 使用相同的PSK
    psk = b"shared-secret-key-12345678"
    psk_hash_b, salt_b = hash_psk(psk, salt_a)
    print(f"PSK哈希：{psk_hash_b.hex()[:32]}...")

    # 生成nonce
    nonce_b = os.urandom(HANDSHAKE_NONCE_LENGTH)
    print(f"Nonce B：{nonce_b.hex()}...")

    return priv_b, pub_b, psk_hash_b, nonce_b


def handshake_complete():
    """完成握手流程"""
    print("\n=== 握手流程 ===")

    # Agent A初始化
    priv_a, pub_a, psk_hash_a, salt_a, nonce_a = agent_a_init()

    # Agent B初始化
    priv_b, pub_b, psk_hash_b, salt_b, nonce_b = agent_b_init()

    # DH密钥交换（三重DH）
    print("\n=== DH密钥交换（三重DH）===")

    # Agent A计算DH
    dh_ab = dh_exchange(priv_a, pub_b)
    dh_aaa = dh_exchange(priv_a, pub_a)  # 自DH
    print(f"DH AB：{dh_ab.hex()[:32]}...")
    print(f"DH AAA：{dh_aaa.hex()[:32]}...")

    # Agent B计算DH
    dh_ba = dh_exchange(priv_b, pub_a)
    dh_bbb = dh_exchange(priv_b, pub_b)  # 自DH
    print(f"DH BA：{dh_ba.hex()[:32]}...")
    print(f"DH BBB：{dh_bbb.hex()[:32]}...")

    # 派生密钥
    print("\n=== 派生会话密钥 ===")

    # Agent A派生
    ikm_a = dh_ab + dh_aaa + psk_hash_a + nonce_a + nonce_b
    enc_key_a, auth_key_a, replay_key_a = derive_keys_from_ikm(ikm_a)
    print(f"Agent A加密密钥：{enc_key_a.hex()[:32]}...")
    print(f"Agent A认证密钥：{auth_key_a.hex()[:32]}...")
    print(f"Agent A防重放密钥：{replay_key_a.hex()[:32]}...")

    # Agent B派生
    ikm_b = dh_ba + dh_bbb + psk_hash_b + nonce_a + nonce_b
    enc_key_b, auth_key_b, replay_key_b = derive_keys_from_ikm(ikm_b)
    print(f"Agent B加密密钥：{enc_key_b.hex()[:32]}...")
    print(f"Agent B认证密钥：{auth_key_b.hex()[:32]}...")
    print(f"Agent B防重放密钥：{replay_key_b.hex()[:32]}...")

    # 验证密钥一致
    print("\n=== 验证密钥 ===")
    print(f"加密密钥一致：{enc_key_a == enc_key_b}")
    print(f"认证密钥一致：{auth_key_a == auth_key_b}")
    print(f"防重放密钥一致：{replay_key_a == replay_key_b}")

    # 发送第一条消息
    print("\n=== 发送第一条消息 ===")

    plaintext = "Hello, Agent B! This is a secure E2EE message."
    nonce, ciphertext = encrypt_message(enc_key_a, plaintext, "agent-a", 1)
    print(f"明文：{plaintext}")
    print(f"密文：{ciphertext.hex()[:64]}...")
    print(f"Nonce：{nonce.hex()}...")

    # 保存会话状态
    session_state = {
        "version": PROTOCOL_VERSION,
        "agent_id": "agent-a",
        "remote_agent_id": "agent-b",
        "remote_public_key": pub_b.public_bytes().hex(),
        "encryption_key": enc_key_a.hex(),
        "auth_key": auth_key_a.hex(),
        "replay_key": replay_key_a.hex(),
        "message_counter": 1,
        "psk_hash": psk_hash_a.hex(),
        "salt": salt_a.hex(),
        "local_nonce": nonce_a.hex(),
        "remote_nonce": nonce_b.hex(),
    }

    print("\n=== 会话状态 ===")
    print(json.dumps(session_state, indent=2))

    print("\n✅ 握手完成！Agent A和Agent B已建立安全通道！")
    print("✅ 现在可以使用加密通道进行通信！")


def derive_keys_from_ikm(ikm: bytes):
    """从IKM派生密钥（辅助函数）"""
    kdf = HKDF(
        algorithm=hashes.SHA256(),
        length=96,
        salt=KDF_SALT,
        info=KDF_INFO,
    )
    keys = kdf.derive(ikm)
    encryption_key = keys[:32]
    auth_key = keys[32:64]
    replay_key = keys[64:96]
    return encryption_key, auth_key, replay_key


def main():
    """运行握手示例"""
    print("\n" + "=" * 60)
    print("SIP协议完整握手示例 v1.0")
    print("=" * 60 + "\n")

    try:
        handshake_complete()
    except Exception as e:
        print(f"\n❌ 握手失败：{e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
