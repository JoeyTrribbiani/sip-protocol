#!/usr/bin/env python3
"""
修正后的群组测试（Double Ratchet）

群组场景下，所有成员需要共享同一 chain_key 才能
互相解密消息。使用 initialize_group_chains 返回的
发送链作为群组共享链。
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sip_protocol.protocol.group import GroupManager


def test_group_basic():
    """基本群组测试：Alice 发送，Bob/Charlie 接收"""
    print("\n=== 基本群组测试 ===")

    group_id = "test-group"
    root_key = os.urandom(32)
    group_manager = GroupManager(group_id, root_key)

    members = ["alice", "bob", "charlie"]
    chains = group_manager.initialize_group_chains(members, root_key)

    # 群组共享链：所有成员使用同一链密钥进行收发
    # 取第一个成员的 sending_chain 作为群组共享链
    shared_chain = chains["alice"]["sending_chain"]
    recv_chain = {"chain_key": shared_chain["chain_key"], "message_number": 0, "skip_keys": {}}

    sender = "alice"
    plaintext = "Hello, everyone!"
    print(f"\n{sender} 发送消息: {plaintext}")

    # Alice 发送
    message_json, updated_chain = group_manager.send_group_message(
        plaintext, shared_chain, sender
    )

    # Bob 和 Charlie 使用相同初始链接收
    for member in members:
        if member == sender:
            continue
        member_recv = {"chain_key": shared_chain["chain_key"], "message_number": 0, "skip_keys": {}}
        decrypted, _ = group_manager.receive_group_message(
            message_json, member_recv, sender
        )
        print(f"{member} 解密成功: {decrypted}")
        assert decrypted == plaintext, f"{member} 解密失败"

    print("\n✅ 基本群组测试通过！")


def test_group_multiple_messages():
    """多消息群组测试：每个成员各发一条"""
    print("\n=== 多消息群组测试 ===")

    group_id = "test-group-multi"
    root_key = os.urandom(32)
    group_manager = GroupManager(group_id, root_key)

    members = ["alice", "bob", "charlie"]

    for sender in members:
        plaintext = f"Message from {sender}"
        print(f"\n{sender} 发送: {plaintext}")

        # 每次发送使用独立的初始链
        send_chain = {"chain_key": root_key, "message_number": 0}
        message_json, _ = group_manager.send_group_message(
            plaintext, send_chain, sender
        )

        # 其他成员使用相同初始链接收
        for member in members:
            if member == sender:
                continue
            recv_chain = {"chain_key": root_key, "message_number": 0, "skip_keys": {}}
            decrypted, _ = group_manager.receive_group_message(
                message_json, recv_chain, sender
            )
            assert decrypted == plaintext, f"{member} 解密 {sender} 的消息失败"
            print(f"  -> {member} 收到: {decrypted}")

    print("\n✅ 多消息群组测试通过！")


if __name__ == "__main__":
    test_group_basic()
    test_group_multiple_messages()
    print("\n" + "=" * 60)
    print("✅ 所有群组测试通过！")
    print("=" * 60)
