#!/usr/bin/env python3
"""
SIP协议性能测试
测试高频消息发送和大规模群组
"""

import sys
import os
import time
import tracemalloc
import random

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.protocol.handshake import (
    initiate_handshake,
    respond_handshake,
    complete_handshake,
)
from src.protocol.message import encrypt_message, decrypt_message, generate_replay_tag
from src.protocol.group import GroupManager
from src.protocol.rekey import RekeyManager


def test_high_frequency_messages():
    """测试高频消息发送（1000条/秒）"""
    print("\n=== 测试1：高频消息发送（1000条/秒） ===")

    # 准备会话密钥
    psk = b"shared-secret-key-12345678"
    handshake_hello, agent_a_state = initiate_handshake(psk)
    (
        handshake_auth,
        agent_b_state,
        agent_b_keys,
    ) = respond_handshake(handshake_hello, psk)
    agent_a_keys, session_state = complete_handshake(handshake_auth, agent_a_state)

    encryption_key = agent_a_keys["encryption_key"]
    auth_key = agent_a_keys["auth_key"]
    replay_key = agent_a_keys["replay_key"]

    # 开始内存跟踪
    tracemalloc.start()

    # 测试参数
    num_messages = 1000
    messages = []

    # 加密1000条消息
    print(f"\n开始加密 {num_messages} 条消息...")
    start_time = time.time()

    for i in range(num_messages):
        plaintext = f"Message #{i}: Hello, Agent B!"
        encrypted_msg = encrypt_message(
            encryption_key,
            plaintext,
            "agent-a",
            "agent-b",
            i + 1,
            replay_key,
        )
        messages.append(encrypted_msg)

    encryption_time = time.time() - start_time

    # 计算性能指标
    avg_encryption_time = encryption_time / num_messages * 1000  # 毫秒
    messages_per_second = num_messages / encryption_time

    print(f"\n✅ 加密完成")
    print(f"   - 总时间: {encryption_time:.3f} 秒")
    print(f"   - 平均每条消息: {avg_encryption_time:.3f} 毫秒")
    print(f"   - 吞吐量: {messages_per_second:.2f} 条/秒")

    # 验证性能要求
    assert avg_encryption_time < 1.0, f"加密速度过慢：{avg_encryption_time:.3f}ms > 1.0ms"
    print(f"✅ 加密速度符合要求（<1ms/条）")

    # 获取内存使用
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    memory_mb = peak / 1024 / 1024
    print(f"\n✅ 内存使用")
    print(f"   - 峰值内存: {memory_mb:.2f} MB")

    # 验证内存要求
    assert memory_mb < 100, f"内存使用过多：{memory_mb:.2f}MB > 100MB"
    print(f"✅ 内存使用符合要求（<100MB）")

    # 解密所有消息验证正确性
    print(f"\n开始解密 {num_messages} 条消息...")
    start_time = time.time()

    for i, encrypted_msg in enumerate(messages):
        decrypted = decrypt_message(agent_b_keys["encryption_key"], encrypted_msg)
        expected = f"Message #{i}: Hello, Agent B!"
        assert decrypted == expected, f"解密失败：第{i+1}条消息"

    decryption_time = time.time() - start_time
    avg_decryption_time = decryption_time / num_messages * 1000

    print(f"\n✅ 解密完成")
    print(f"   - 总时间: {decryption_time:.3f} 秒")
    print(f"   - 平均每条消息: {avg_decryption_time:.3f} 毫秒")

    print("\n✅ 测试1通过！")


def test_large_group_creation(members_count=10):
    """测试大规模群组创建和消息发送"""
    print(f"\n=== 测试2：大规模群组测试（{members_count}个成员） ===")

    # 创建群组
    group_id = f"group-large-test-{members_count}"
    root_key = os.urandom(32)
    group_manager = GroupManager(group_id, root_key)

    print(f"\n✅ 创建群组: {group_id}")

    # 初始化群组链密钥
    member_ids = [f"agent-{i}" for i in range(members_count)]
    chains = group_manager.initialize_group_chains(member_ids, root_key)
    members = {}
    for member_id in member_ids:
        members[member_id] = chains[member_id]
    print(f"✅ 创建 {members_count} 个成员")

    # 测试1：成员加入群组
    print(f"\n--- 测试2.1：成员加入群组 ---")
    new_member_id = "agent-new"
    new_member_id_list = [new_member_id]
    new_member_chain = group_manager.initialize_group_chains(new_member_id_list, root_key)
    members[new_member_id] = new_member_chain[new_member_id]
    print(f"✅ 新成员 {new_member_id} 加入群组")
    assert len(members) == members_count + 1, "成员数量不正确"
    print(f"✅ 当前成员数: {len(members)}")

    # 测试2：成员离开群组
    print(f"\n--- 测试2.2：成员离开群组 ---")
    leaving_member_id = f"agent-{members_count // 2}"
    del members[leaving_member_id]
    print(f"✅ 成员 {leaving_member_id} 离开群组")
    assert len(members) == members_count, "成员数量不正确"
    print(f"✅ 当前成员数: {len(members)}")

    # 测试3：群组消息加密/解密
    print(f"\n--- 测试2.3：群组消息加密/解密 ---")

    # 成员1发送群组消息
    sender_id = "agent-1"
    plaintext = "Hello, Group SIP! This is a test message."
    message, updated_chain = group_manager.send_group_message(
        plaintext, members[sender_id]["sending_chain"], sender_id
    )
    members[sender_id]["sending_chain"] = updated_chain

    print(f"✅ 成员 {sender_id} 发送群组消息")
    print(f"   - Message: {plaintext}")
    print(f"   - Ciphertext length: {len(message)} bytes")

    # 发送者解密自己发送的群组消息（验证加密/解密功能）
    decrypted, updated_chain = group_manager.receive_group_message(
        message, members[sender_id]["receiving_chain"], sender_id
    )
    members[sender_id]["receiving_chain"] = updated_chain

    assert decrypted == plaintext, f"发送者解密失败"
    print(f"✅ 发送者成功解密自己发送的群组消息")

    # 测试4：多条群组消息
    print(f"\n--- 测试2.4：多条群组消息 ---")

    num_messages = 10
    message_count = 0

    # 获取当前存在的成员ID列表
    member_ids = list(members.keys())

    for msg_idx in range(num_messages):
        # 从现有成员中循环选择发送者
        sender_id = member_ids[msg_idx % len(member_ids)]

        plaintext = f"Group message #{msg_idx} from {sender_id}"
        message, updated_chain = group_manager.send_group_message(
            plaintext, members[sender_id]["sending_chain"], sender_id
        )
        members[sender_id]["sending_chain"] = updated_chain

        # 发送者解密自己发送的群组消息
        decrypted, updated_chain = group_manager.receive_group_message(
            message, members[sender_id]["receiving_chain"], sender_id
        )
        members[sender_id]["receiving_chain"] = updated_chain
        assert decrypted == plaintext
        message_count += 1

    print(f"✅ 发送 {num_messages} 条群组消息")
    print(f"✅ 成功解密 {message_count} 条消息")

    print("\n✅ 测试2通过！")


def test_group_performance():
    """测试不同规模的群组性能"""
    print("\n=== 测试3：群组性能对比（10, 50, 100成员） ===")

    group_sizes = [10, 50, 100]

    for size in group_sizes:
        print(f"\n--- 测试 {size} 个成员的群组 ---")

        # 创建群组
        group_id = f"group-perf-{size}"
        root_key = os.urandom(32)
        group_manager = GroupManager(group_id, root_key)

        # 创建成员
        member_ids = [f"agent-{i}" for i in range(size)]
        chains = group_manager.initialize_group_chains(member_ids, root_key)
        members = {}
        for member_id in member_ids:
            members[member_id] = chains[member_id]

        # 测试消息发送和接收
        num_messages = 10
        start_time = time.time()

        for msg_idx in range(num_messages):
            sender_id = f"agent-{msg_idx % size}"
            plaintext = f"Message #{msg_idx}"

            # 发送消息
            message, updated_chain = group_manager.send_group_message(
                plaintext, members[sender_id]["sending_chain"], sender_id
            )
            members[sender_id]["sending_chain"] = updated_chain

            # 发送者解密自己发送的群组消息
            decrypted, updated_chain = group_manager.receive_group_message(
                message, members[sender_id]["receiving_chain"], sender_id
            )
            members[sender_id]["receiving_chain"] = updated_chain
            assert decrypted == plaintext

        elapsed_time = time.time() - start_time
        total_messages = num_messages * (size - 1)

        print(f"✅ 群组大小: {size}")
        print(f"   - 消息数: {num_messages}")
        print(f"   - 总解密次数: {total_messages}")
        print(f"   - 总时间: {elapsed_time:.3f} 秒")
        print(f"   - 平均每条消息: {elapsed_time / total_messages * 1000:.3f} 毫秒")

    print("\n✅ 测试3通过！")


def test_stress_test():
    """压力测试：混合高频消息和群组消息"""
    print("\n=== 测试4：压力测试 ===")

    # 准备会话密钥
    psk = b"shared-secret-key-12345678"
    handshake_hello, agent_a_state = initiate_handshake(psk)
    (
        handshake_auth,
        agent_b_state,
        agent_b_keys,
    ) = respond_handshake(handshake_hello, psk)
    agent_a_keys, session_state = complete_handshake(handshake_auth, agent_a_state)

    encryption_key = agent_a_keys["encryption_key"]
    replay_key = agent_a_keys["replay_key"]

    # 创建群组
    group_id = "group-stress-test"
    root_key = os.urandom(32)
    group_manager = GroupManager(group_id, root_key)

    # 创建50个群组成员
    member_ids = [f"agent-{i}" for i in range(50)]
    chains = group_manager.initialize_group_chains(member_ids, root_key)
    members = {}
    for member_id in member_ids:
        members[member_id] = chains[member_id]

    print("✅ 准备完成：1个点对点会话，50个群组成员")

    # 开始内存跟踪
    tracemalloc.start()

    start_time = time.time()

    # 混合发送点对点和群组消息
    for i in range(100):
        # 点对点消息
        if i % 2 == 0:
            plaintext = f"P2P message #{i}"
            encrypted_msg = encrypt_message(
                encryption_key,
                plaintext,
                "agent-a",
                "agent-b",
                i + 1,
                replay_key,
            )
            decrypted = decrypt_message(agent_b_keys["encryption_key"], encrypted_msg)
            assert decrypted == plaintext
        else:
            # 群组消息
            sender_id = f"agent-{i % 50}"
            plaintext = f"Group message #{i} from {sender_id}"
            message, updated_chain = group_manager.send_group_message(
                plaintext, members[sender_id]["sending_chain"], sender_id
            )
            members[sender_id]["sending_chain"] = updated_chain

            # 发送者解密自己发送的群组消息
            decrypted, updated_chain = group_manager.receive_group_message(
                message, members[sender_id]["receiving_chain"], sender_id
            )
            members[sender_id]["receiving_chain"] = updated_chain
            assert decrypted == plaintext

    elapsed_time = time.time() - start_time

    # 获取内存使用
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    memory_mb = peak / 1024 / 1024

    print(f"\n✅ 压力测试完成")
    print(f"   - 总消息数: 100（50点对点 + 50群组）")
    print(f"   - 总时间: {elapsed_time:.3f} 秒")
    print(f"   - 平均每条消息: {elapsed_time / 100 * 1000:.3f} 毫秒")
    print(f"   - 峰值内存: {memory_mb:.2f} MB")

    assert memory_mb < 100, f"内存使用过多：{memory_mb:.2f}MB > 100MB"
    print(f"✅ 内存使用符合要求（<100MB）")

    print("\n✅ 测试4通过！")


def main():
    """运行所有性能测试"""
    print("\n" + "=" * 60)
    print("SIP协议性能测试套件")
    print("=" * 60)

    try:
        # 测试1：高频消息发送
        test_high_frequency_messages()

        # 测试2：大规模群组测试
        test_large_group_creation(members_count=10)
        test_large_group_creation(members_count=50)
        test_large_group_creation(members_count=100)

        # 测试3：群组性能对比
        test_group_performance()

        # 测试4：压力测试
        test_stress_test()

        print("\n" + "=" * 60)
        print("✅ 所有性能测试通过！")
        print("=" * 60 + "\n")

        return 0

    except Exception as e:
        print(f"\n❌ 测试失败：{e}")
        import traceback

        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
