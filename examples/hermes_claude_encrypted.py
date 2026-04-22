#!/usr/bin/env python3
"""
Hermes ↔ Claude Code 加密通信示例

演示如何通过SIP协议让Hermes和Claude Code之间端到端加密通信。

注意：这需要在OpenClaw环境中运行，且hermes CLI可用。
"""

import asyncio
import sys
import os

# 添加项目路径
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "python"))

from sip_protocol.transport import HermesClaudeAdapter


async def main():
    """主函数"""
    print("🔐 Hermes ↔ Claude Code 加密通信示例\n")

    # 初始化适配器
    adapter = HermesClaudeAdapter(
        hermes_agent_id="hermes",
        claude_agent_id="claude-code",
        psk=b"my-shared-secret-key-123",  # 在实际应用中应该从安全配置中读取
        model="claude-sonnet",
    )

    try:
        # 1. 建立加密通道（简化版本：使用PSK）
        print("📡 建立加密通道...")
        await adapter.handshake()
        print("✅ 加密通道已建立\n")

        # 2. 发送加密消息
        print("📤 发送加密消息到Claude Code...")
        message = "帮我写一个Python函数，计算斐波那契数列的第n项"

        print(f"明文消息: {message}")
        response = await adapter.send(message)
        print(f"Claude Code响应: {response}\n")

        # 3. 发送第二条消息
        print("📤 发送第二条消息...")
        message2 = "解释一下递归和迭代的区别"
        response2 = await adapter.send(message2)
        print(f"Claude Code响应: {response2}\n")

        print("✅ 通信完成！")

    except Exception as e:
        print(f"❌ 错误: {e}")
        import traceback

        traceback.print_exc()

    finally:
        # 4. 关闭适配器
        print("\n🔒 关闭加密通道...")
        await adapter.close()
        print("✅ 已关闭")


if __name__ == "__main__":
    # 检查是否在OpenClaw环境中
    if not any(
        p in os.environ
        for p in ["OPENCLAW_SESSION_KEY", "OPENCLAW_GATEWAY_URL", "OPENCLAW_API_KEY"]
    ):
        print("⚠️  警告: 未检测到OpenClaw环境")
        print("此示例需要在OpenClaw环境中运行")
        print("您可以通过以下方式运行:\n")
        print("  # 在OpenClaw聊天中:")
        print("  cd /path/to/sip-protocol")
        print("  python examples/hermes_claude_encrypted.py\n")
        print("  # 或者通过OpenClaw的exec命令")
        sys.exit(1)

    asyncio.run(main())
