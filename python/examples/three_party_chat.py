#!/usr/bin/env python3
"""
三方加密通信示例

演示 Hermes ↔ OpenClaw ↔ Claude Code 之间的加密通信流程：

    Agent A (Hermes) ←→ Agent B (OpenClaw) ←→ Agent C (Claude Code)
         决策型                调度型               执行型

场景：
1. Agent A (Hermes) 与 Agent B (OpenClaw) 建立加密通道
2. Agent B (OpenClaw) 与 Agent C (Claude Code) 建立加密通道
3. Agent A 发送加密消息给 Agent B
4. Agent B 解密后重新加密，转发给 Agent C
5. Agent C 解密并回复

运行方式：
    cd python
    python -m examples.three_party_chat

注意：
    - 使用共享PSK（生产环境应使用独立密钥交换）
    - 仅演示加密通信流程，不涉及实际网络传输
    - 消息转发场景中，中间Agent可以解密消息内容（B2B信任模型）
"""

import sys
import os
import json
import time

# 确保可以从项目根目录导入
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.transport.encrypted_channel import EncryptedChannel, ChannelState, ChannelConfig
from src.transport.openclaw_adapter import OpenClawAdapter, AgentConfig
from src.transport.message import (
    AgentMessage,
    MessageType,
    ControlAction,
    create_text_message,
    create_control_message,
)


def print_separator(title: str) -> None:
    """打印分隔线"""
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}\n")


def print_message(label: str, msg: AgentMessage, show_payload: bool = True) -> None:
    """打印消息摘要"""
    print(f"  [{label}]")
    print(f"    ID: {msg.id[:8]}...")
    print(f"    Type: {msg.type.value}")
    print(f"    From: {msg.sender_id}")
    print(f"    To: {msg.recipient_id}")
    if show_payload and msg.payload:
        payload_str = json.dumps(msg.payload, ensure_ascii=False)
        if len(payload_str) > 120:
            payload_str = payload_str[:120] + "..."
        print(f"    Payload: {payload_str}")
    print()


def main():
    # ──────────────── 配置 ────────────────

    PSK = b"three-party-shared-secret-key-32b"

    # Agent IDs
    HERMES_ID = "agent:hermes::session:abc001"
    OPENCLAW_ID = "agent:openclaw::session:def002"
    CLAUDE_ID = "agent:claude-code::session:ghi003"

    print_separator("三方加密通信示例")
    print("  Agent A (Hermes)      → 决策型")
    print("  Agent B (OpenClaw)    → 调度型")
    print("  Agent C (Claude Code) → 执行型")
    print(f"\n  PSK: {PSK[:16]}... (shared)")

    # ──────────────── Step 1: 创建通道 ────────────────

    print_separator("Step 1: 创建加密通道")

    # Agent A (Hermes) ↔ Agent B (OpenClaw) 的通道
    channel_a = EncryptedChannel(
        agent_id=HERMES_ID,
        psk=PSK,
        config=ChannelConfig(),
    )
    print(f"  ✅ Hermes 通道已创建 (state: {channel_a.state.value})")

    channel_b_ab = EncryptedChannel(
        agent_id=OPENCLAW_ID,
        psk=PSK,
        config=ChannelConfig(),
    )
    print(f"  ✅ OpenClaw (AB通道) 已创建 (state: {channel_b_ab.state.value})")

    # Agent B (OpenClaw) ↔ Agent C (Claude Code) 的通道
    channel_b_bc = EncryptedChannel(
        agent_id=OPENCLAW_ID,
        psk=PSK,
        config=ChannelConfig(),
    )
    print(f"  ✅ OpenClaw (BC通道) 已创建 (state: {channel_b_bc.state.value})")

    channel_c = EncryptedChannel(
        agent_id=CLAUDE_ID,
        psk=PSK,
        config=ChannelConfig(),
    )
    print(f"  ✅ Claude Code 通道已创建 (state: {channel_c.state.value})")

    # ──────────────── Step 2: A ↔ B 握手 ────────────────

    print_separator("Step 2: Hermes ↔ OpenClaw 握手")

    # A → B: Handshake Hello
    hello_ab = channel_a.initiate()
    print(f"  1. Hermes → OpenClaw: Handshake Hello")
    print_message("Hello AB", hello_ab, show_payload=False)

    # B → A: Handshake Auth
    auth_ab = channel_b_ab.respond_to_handshake(hello_ab)
    print(f"  2. OpenClaw → Hermes: Handshake Auth")
    print_message("Auth AB", auth_ab, show_payload=False)

    # A 完成
    channel_a.complete_handshake(auth_ab)
    print(f"  3. Hermes: Handshake Complete")
    print(f"  ✅ AB通道建立完成!")
    print(f"     Hermes state: {channel_a.state.value}")
    print(f"     OpenClaw(AB) state: {channel_b_ab.state.value}")

    # ──────────────── Step 3: B ↔ C 握手 ────────────────

    print_separator("Step 3: OpenClaw ↔ Claude Code 握手")

    # B → C: Handshake Hello
    hello_bc = channel_b_bc.initiate()
    print(f"  1. OpenClaw → Claude Code: Handshake Hello")
    print_message("Hello BC", hello_bc, show_payload=False)

    # C → B: Handshake Auth
    auth_bc = channel_c.respond_to_handshake(hello_bc)
    print(f"  2. Claude Code → OpenClaw: Handshake Auth")
    print_message("Auth BC", auth_bc, show_payload=False)

    # B 完成
    channel_b_bc.complete_handshake(auth_bc)
    print(f"  3. OpenClaw: Handshake Complete")
    print(f"  ✅ BC通道建立完成!")
    print(f"     OpenClaw(BC) state: {channel_b_bc.state.value}")
    print(f"     Claude Code state: {channel_c.state.value}")

    # ──────────────── Step 4: 加密消息通信 ────────────────

    print_separator("Step 4: 加密消息通信")

    # 4.1: A → B: Hermes发送加密消息
    print("  ── Hermes → OpenClaw ──")
    plaintext_ab = "请帮我分析一下这个项目的架构设计"
    encrypted_ab = channel_a.send(plaintext_ab, OPENCLAW_ID)
    print(f"  原文: \"{plaintext_ab}\"")
    print(f"  加密消息ID: {encrypted_ab.id[:8]}...")
    payload_preview = encrypted_ab.payload.get("payload", "")[:40]
    print(f"  加密payload: {payload_preview}...")

    # B 解密
    decrypted_ab = channel_b_ab.receive(encrypted_ab)
    print(f"  OpenClaw 解密: \"{decrypted_ab}\"")
    assert decrypted_ab == plaintext_ab, "解密不匹配!"
    print(f"  ✅ 消息验证通过")

    # 4.2: B → C: OpenClaw转发给Claude Code
    print("\n  ── OpenClaw → Claude Code (转发) ──")
    forward_text = f"[转发自Hermes]: {decrypted_ab}"
    encrypted_bc = channel_b_bc.send(forward_text, CLAUDE_ID)
    print(f"  转发内容: \"{forward_text}\"")
    print(f"  加密消息ID: {encrypted_bc.id[:8]}...")

    # C 解密
    decrypted_bc = channel_c.receive(encrypted_bc)
    print(f"  Claude Code 解密: \"{decrypted_bc}\"")
    assert decrypted_bc == forward_text, "解密不匹配!"
    print(f"  ✅ 消息验证通过")

    # ──────────────── Step 5: 回复消息 ────────────────

    print_separator("Step 5: 回复消息 (Claude Code → OpenClaw → Hermes)")

    # 5.1: C → B: Claude Code回复
    print("  ── Claude Code → OpenClaw ──")
    reply_cb = "架构设计良好，建议增加缓存层和消息队列来提升性能"
    encrypted_cb = channel_c.send(reply_cb, OPENCLAW_ID)
    print(f"  回复原文: \"{reply_cb}\"")
    print(f"  加密消息ID: {encrypted_cb.id[:8]}...")

    # B 解密
    decrypted_cb = channel_b_bc.receive(encrypted_cb)
    print(f"  OpenClaw 解密: \"{decrypted_cb}\"")
    assert decrypted_cb == reply_cb, "解密不匹配!"
    print(f"  ✅ 消息验证通过")

    # 5.2: B → A: OpenClaw转发给Hermes
    print("\n  ── OpenClaw → Hermes (转发) ──")
    forward_ba = f"[转发自Claude Code]: {decrypted_cb}"
    encrypted_ba = channel_b_ab.send(forward_ba, HERMES_ID)
    print(f"  转发内容: \"{forward_ba}\"")

    # A 解密
    decrypted_ba = channel_a.receive(encrypted_ba)
    print(f"  Hermes 解密: \"{decrypted_ba}\"")
    assert decrypted_ba == forward_ba, "解密不匹配!"
    print(f"  ✅ 消息验证通过")

    # ──────────────── Step 6: 使用OpenClawAdapter ────────────────

    print_separator("Step 6: 使用OpenClawAdapter (高级接口)")

    # 创建Adapter
    adapter_a = OpenClawAdapter(
        config=AgentConfig(
            agent_id=HERMES_ID,
            agent_type="decision",
            psk=PSK,
        )
    )
    adapter_b = OpenClawAdapter(
        config=AgentConfig(
            agent_id=OPENCLAW_ID,
            agent_type="orchestrator",
            psk=PSK,
        )
    )

    adapter_a.start()
    adapter_b.start()
    print("  ✅ Adapters已创建并启动")

    # 使用Adapter进行握手
    print("\n  ── Adapter握手 ──")
    hello = adapter_a.initiate_handshake()
    auth = adapter_b.respond_to_handshake(hello)
    adapter_a.complete_handshake(auth)
    print(f"  ✅ Adapter握手完成")
    print(f"     Adapter A connected: {adapter_a.is_connected}")
    print(f"     Adapter B connected: {adapter_b.is_connected}")

    # 使用Adapter发送加密消息
    print("\n  ── Adapter加密通信 ──")
    test_msg = "通过OpenClawAdapter发送的加密消息"
    encrypted = adapter_a.send_encrypted(test_msg, OPENCLAW_ID)
    print(f"  发送: \"{test_msg}\"")

    decrypted = adapter_b.receive_encrypted(encrypted)
    print(f"  接收: \"{decrypted}\"")
    assert decrypted == test_msg, "Adapter解密不匹配!"
    print(f"  ✅ Adapter加密通信验证通过")

    # 显示统计
    print("\n  ── 统计信息 ──")
    stats_a = adapter_a.stats
    stats_b = adapter_b.stats
    print(f"  Adapter A: {json.dumps(stats_a, indent=4, ensure_ascii=False, default=str)}")
    print(f"  Adapter B: {json.dumps(stats_b, indent=4, ensure_ascii=False, default=str)}")

    # ──────────────── Step 7: 多轮通信 ────────────────

    print_separator("Step 7: 多轮加密通信")

    conversations = [
        ("Hermes", "分析一下这个需求的可行性"),
        ("Claude Code", "需求可行，建议分三个阶段实施"),
        ("Hermes", "好的，请给出第一阶段的详细方案"),
        ("Claude Code", "第一阶段方案：搭建基础架构，实现核心功能模块"),
    ]

    for i, (sender, text) in enumerate(conversations):
        print(f"\n  ── 第{i+1}轮: {sender} ──")

        if sender == "Hermes":
            # A → B → C
            enc_msg = channel_a.send(text, OPENCLAW_ID)
            dec = channel_b_ab.receive(enc_msg)
            print(f"  Hermes(加密) → OpenClaw(解密): \"{dec}\"")

            forward = f"[来自{sender}]: {dec}"
            enc_fwd = channel_b_bc.send(forward, CLAUDE_ID)
            dec_final = channel_c.receive(enc_fwd)
            print(f"  OpenClaw(加密转发) → Claude Code(解密): \"{dec_final}\"")
        else:
            # C → B → A
            enc_msg = channel_c.send(text, OPENCLAW_ID)
            dec = channel_b_bc.receive(enc_msg)
            print(f"  Claude Code(加密) → OpenClaw(解密): \"{dec}\"")

            forward = f"[来自{sender}]: {dec}"
            enc_fwd = channel_b_ab.send(forward, HERMES_ID)
            dec_final = channel_a.receive(enc_fwd)
            print(f"  OpenClaw(加密转发) → Hermes(解密): \"{dec_final}\"")

    # ──────────────── 清理 ────────────────

    print_separator("统计摘要")

    print(f"  Channel A (Hermes):")
    print(f"    State: {channel_a.state.value}")
    print(f"    Stats: {json.dumps(channel_a.stats, indent=6, default=str)}")

    print(f"\n  Channel B-AB (OpenClaw):")
    print(f"    State: {channel_b_ab.state.value}")
    print(f"    Stats: {json.dumps(channel_b_ab.stats, indent=6, default=str)}")

    print(f"\n  Channel B-BC (OpenClaw):")
    print(f"    State: {channel_b_bc.state.value}")
    print(f"    Stats: {json.dumps(channel_b_bc.stats, indent=6, default=str)}")

    print(f"\n  Channel C (Claude Code):")
    print(f"    State: {channel_c.state.value}")
    print(f"    Stats: {json.dumps(channel_c.stats, indent=6, default=str)}")

    # 关闭通道
    channel_a.close()
    channel_b_ab.close()
    channel_b_bc.close()
    channel_c.close()
    adapter_a.stop()
    adapter_b.stop()

    print_separator("✅ 三方加密通信示例完成!")
    print("  所有通道已关闭，消息加密/解密/转发验证通过。\n")


if __name__ == "__main__":
    main()
