#!/usr/bin/env python3
"""
修正后的群组测试
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sip_protocol.protocol.group import GroupManager


def test_group_basic():
    """基本群组测试"""
    print("\n=== 基本群组测试 ===")

    # 创建群组
    group_id = "test-group"
    root_key = os.urandom(32)
    group_manager = GroupManager(group_id, root_key)

    # 初始化成员
    members = ["alice", "bob", "charlie"]
    chains = group_manager.initialize_group_chains(members, root_key)

    # Alice发送消息
    sender = "alice"
    plaintext = "Hello, everyone!"
    print(f"\n{sender} 发送消息: {plaintext}")

    # Alice使用她的sending_chain发送
    message_json, updated_sending_chain = group_manager.send_group_message(
        plaintext, chains[sender]["sending_chain"], sender
    )
    chains[sender]["sending_chain"] = updated_sending_chain

    print(f"消息JSON: {message_json[:100]}...")

    # Bob和Charlie使用他们的receiving_chain接收
    for member in members:
        if member == sender:
            continue

        try:
            decrypted, updated_receiving_chain = group_manager.receive_group_message(
                message_json, chains[member]["receiving_chain"], sender
            )
            chains[member]["receiving_chain"] = updated_receiving_chain
            print(f"{member} 解密成功: {decrypted}")
            assert decrypted == plaintext, f"{member} 解密失败"
        except Exception as e:
            print(f"{member} 解密失败: {e}")
            raise

    print("\n✅ 基本群组测试通过！")


def test_group_multiple_messages():
    """多消息群组测试"""
    print("\n=== 多消息群组测试 ===")

    # 创建群组
    group_id = "test-group-multi"
    root_key = os.urandom(32)
    group_manager = GroupManager(group_id, root_key)

    # 初始化成员
    members = ["alice", "bob", "charlie"]
    chains = group_manager.initialize_group_chains(members, root_key)

    # 每个成员发送一条消息
    for sender in members:
        plaintext = f"Message from {sender}"
        print(f"\n{sender} 发送: {plaintext}")

        # 发送
        message_json, updated_sending_chain = group_manager.send_group_message(
            plaintext, chains[sender]["sending_chain"], sender
        )
        chains[sender]["sending_chain"] = updated_sending_chain

        # 其他成员接收
        for member in members:
            if member == sender:
                continue

            decrypted, updated_receiving_chain = group_manager.receive_group_message(
                message_json, chains[member]["receiving_chain"], sender
            )
            chains[member]["receiving_chain"] = updated_receiving_chain
            assert decrypted == plaintext, f"{member} 解密 {sender} 的消息失败"
            print(f"  -> {member} 收到: {decrypted}")

    print("\n✅ 多消息群组测试通过！")


if __name__ == "__main__":
    test_group_basic()
    test_group_multiple_messages()
    print("\n" + "=" * 60)
    print("✅ 所有群组测试通过！")
    print("=" * 60)
