#!/usr/bin/env python3
"""
SIP协议性能测试
测试高频消息加密与点对点压力场景
"""

import sys
import os
import time
import tracemalloc

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sip_protocol.protocol.handshake import (
    initiate_handshake,
    respond_handshake,
    complete_handshake,
)
from sip_protocol.protocol.message import encrypt_message, decrypt_message, generate_replay_tag
from sip_protocol.protocol.rekey import RekeyManager


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


def test_stress_test():
    """压力测试：高频点对点加密/解密混合轮次"""
    print("\n=== 测试2：压力测试 ===")

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

    print("✅ 准备完成：1个点对点会话")

    # 开始内存跟踪
    tracemalloc.start()

    start_time = time.time()

    num_messages = 100
    for i in range(num_messages):
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

    elapsed_time = time.time() - start_time

    # 获取内存使用
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    memory_mb = peak / 1024 / 1024

    print(f"\n✅ 压力测试完成")
    print(f"   - 总消息数: {num_messages}")
    print(f"   - 总时间: {elapsed_time:.3f} 秒")
    print(f"   - 平均每条消息: {elapsed_time / num_messages * 1000:.3f} 毫秒")
    print(f"   - 峰值内存: {memory_mb:.2f} MB")

    assert memory_mb < 100, f"内存使用过多：{memory_mb:.2f}MB > 100MB"
    print(f"✅ 内存使用符合要求（<100MB）")

    print("\n✅ 测试2通过！")


def main():
    """运行所有性能测试"""
    print("\n" + "=" * 60)
    print("SIP协议性能测试套件")
    print("=" * 60)

    try:
        # 测试1：高频消息发送
        test_high_frequency_messages()

        # 测试2：压力测试
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
