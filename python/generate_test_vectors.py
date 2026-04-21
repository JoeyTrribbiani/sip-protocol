"""
生成测试向量
根据SIP协议规范生成可验证的十六进制测试向量
"""

import json
import base64
import os
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from argon2 import low_level

# 固定输入（用于生成可验证的测试向量）
FIXED_PRIVATE_A = bytes.fromhex(
    "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
)
FIXED_PRIVATE_B = bytes.fromhex(
    "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"
)
FIXED_PSK = bytes.fromhex(
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
)
FIXED_SALT = bytes.fromhex("SIPProtocolTestSalt" + "00" * 2)
FIXED_NONCE_A = bytes.fromhex("0123456789abcdef0123456789abcdef")
FIXED_NONCE_B = bytes.fromhex("fedcba9876543210fedcba9876543210")
FIXED_MESSAGE = "Hello, World! This is a test message."


def generate_handshake_vectors():
    """生成握手测试向量"""
    print("生成握手测试向量...")

    # 1. 生成密钥对
    private_a = x25519.X25519PrivateKey.from_private_bytes(FIXED_PRIVATE_A)
    public_a = private_a.public_key()
    pub_a_bytes = public_a.public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )

    private_b = x25519.X25519PrivateKey.from_private_bytes(FIXED_PRIVATE_B)
    public_b = private_b.public_key()
    pub_b_bytes = public_b.public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )

    # 2. DH密钥交换
    shared_a = private_a.exchange(public_b)
    shared_b = private_b.exchange(public_a)

    # 3. PSK哈希
    psk_hash, _ = low_level.hash_secret_raw(
        secret=FIXED_PSK,
        salt=FIXED_SALT,
        time_cost=3,
        memory_cost=65536,
        parallelism=4,
        hash_len=32,
        type=low_level.Type.ID,
    )

    # 4. 派生密钥
    combined = shared_a + psk_hash + FIXED_NONCE_A + FIXED_NONCE_B
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=96,
        salt=FIXED_SALT,
        info=b"SIP-handshake",
    )
    derived = hkdf.derive(combined)

    encryption_key = derived[0:32]
    auth_key = derived[32:64]
    replay_key = derived[64:96]

    # 5. 生成测试向量
    vectors = {
        "handshake": {
            "agent_a": {
                "private_key": FIXED_PRIVATE_A.hex(),
                "public_key": pub_a_bytes.hex(),
            },
            "agent_b": {
                "private_key": FIXED_PRIVATE_B.hex(),
                "public_key": pub_b_bytes.hex(),
            },
            "psk": FIXED_PSK.hex(),
            "salt": FIXED_SALT.hex(),
            "nonce_a": FIXED_NONCE_A.hex(),
            "nonce_b": FIXED_NONCE_B.hex(),
            "shared_secret": shared_a.hex(),  # 双方应该相同
            "psk_hash": psk_hash.hex(),
            "encryption_key": encryption_key.hex(),
            "auth_key": auth_key.hex(),
            "replay_key": replay_key.hex(),
        }
    }

    print("✅ 握手测试向量生成完成！")
    return vectors


def generate_message_encryption_vectors():
    """生成消息加密测试向量"""
    print("生成消息加密测试向量...")

    from src.crypto.xchacha20_poly1305 import (
        encrypt_xchacha20_poly1305,
        decrypt_xchacha20_poly1305,
        generate_nonce,
    )
    from src.protocol.message import encrypt_message, decrypt_message

    # 固定密钥
    encryption_key = bytes.fromhex(
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    )
    auth_key = bytes.fromhex(
        "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
    )
    replay_key = bytes.fromhex(
        "1122334455667788112233445566778811223344556677881122334455667788"
    )

    # 加密消息
    encrypted_msg = encrypt_message(
        encryption_key=encryption_key,
        plaintext=FIXED_MESSAGE,
        sender_id="agent-a",
        recipient_id="agent-b",
        message_counter=1,
        replay_key=replay_key,
    )

    # 生成测试向量
    vectors = {
        "message_encryption": {
            "encryption_key": encryption_key.hex(),
            "auth_key": auth_key.hex(),
            "replay_key": replay_key.hex(),
            "plaintext": FIXED_MESSAGE,
            "encrypted_message": encrypted_msg,
        }
    }

    print("✅ 消息加密测试向量生成完成！")
    return vectors


def generate_group_encryption_vectors():
    """生成群组加密测试向量"""
    print("生成群组加密测试向量...")

    from src.protocol.group import GroupManager
    from src.crypto.hkdf import hkdf

    # 固定root key
    root_key = bytes.fromhex(
        "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
    )

    # 创建群组管理器
    group_manager = GroupManager(group_id="test-group", root_key=root_key)

    # 初始化群组链密钥
    members = ["agent-a", "agent-b", "agent-c"]
    chains = group_manager.initialize_group_chains(members, root_key)

    # 发送群组消息
    plaintext = "Hello, Group!"
    encrypted_msg_json, updated_chain = group_manager.send_group_message(
        plaintext, chains["agent-a"]["sending_chain"]
    )

    # 接收群组消息
    encrypted_msg = json.loads(encrypted_msg_json)
    decrypted_plaintext, _ = group_manager.receive_group_message(
        encrypted_msg_json, chains["agent-a"]["receiving_chain"]
    )

    # 生成测试向量
    vectors = {
        "group_encryption": {
            "root_key": root_key.hex(),
            "members": members,
            "group_id": "test-group",
            "plaintext": plaintext,
            "encrypted_message": json.loads(encrypted_msg_json),
            "decrypted_plaintext": decrypted_plaintext,
            "chain_keys": {
                "agent-a": {
                    "sending_chain_key": chains["agent-a"]["sending_chain"][
                        "chain_key"
                    ].hex(),
                    "receiving_chain_key": chains["agent-a"]["receiving_chain"][
                        "chain_key"
                    ].hex(),
                }
            },
        }
    }

    print("✅ 群组加密测试向量生成完成！")
    return vectors


def generate_rekey_vectors():
    """生成Rekey测试向量"""
    print("生成Rekey测试向量...")

    from src.protocol.rekey import RekeyManager

    # 固定会话状态
    session_state = {
        "encryption_key": bytes.fromhex(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        ),
        "auth_key": bytes.fromhex(
            "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
        ),
        "replay_key": bytes.fromhex(
            "1122334455667788112233445566778811223344556677881122334455667788"
        ),
    }

    # 创建Rekey管理器
    rekey_manager_a = RekeyManager(session_state.copy(), is_initiator=True)
    rekey_manager_b = RekeyManager(session_state.copy(), is_initiator=False)

    # 发起Rekey
    rekey_request = rekey_manager_a.create_rekey_request(reason="scheduled")
    rekey_response = rekey_manager_b.process_rekey_request(rekey_request)

    # 生成测试向量
    vectors = {
        "rekey": {
            "initial_encryption_key": session_state["encryption_key"].hex(),
            "initial_auth_key": session_state["auth_key"].hex(),
            "initial_replay_key": session_state["replay_key"].hex(),
            "rekey_request": rekey_request,
            "rekey_response": rekey_response,
        }
    }

    print("✅ Rekey测试向量生成完成！")
    return vectors


def main():
    """生成所有测试向量"""
    print("=" * 60)
    print("SIP协议测试向量生成器")
    print("=" * 60)
    print()

    # 生成所有测试向量
    all_vectors = {}
    all_vectors.update(generate_handshake_vectors())
    all_vectors.update(generate_message_encryption_vectors())
    all_vectors.update(generate_group_encryption_vectors())
    all_vectors.update(generate_rekey_vectors())

    # 保存到文件
    output_file = "docs/test_vectors.json"
    with open(output_file, "w") as f:
        json.dump(all_vectors, f, indent=2)

    print()
    print("=" * 60)
    print(f"✅ 所有测试向量已生成并保存到 {output_file}")
    print("=" * 60)


if __name__ == "__main__":
    main()
