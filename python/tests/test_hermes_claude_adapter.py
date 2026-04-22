"""
HermesClaudeAdapter单元测试

注意：这些测试需要OpenClaw环境和hermes CLI。
如果不在OpenClaw环境中，部分测试会被跳过。
"""

import asyncio
import os
import sys
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

# 添加项目路径
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.transport.hermes_claude_adapter import HermesClaudeAdapter


class TestHermesClaudeAdapter:
    """HermesClaudeAdapter测试"""

    def test_initialization(self):
        """测试初始化"""
        adapter = HermesClaudeAdapter(
            hermes_agent_id="hermes",
            claude_agent_id="claude-code",
            psk=b"test-key",
        )

        assert adapter.hermes_agent_id == "hermes"
        assert adapter.claude_agent_id == "claude-code"
        assert adapter._claude_session_key is None

    @pytest.mark.skipif(
        not any(p in os.environ for p in ["OPENCLAW_SESSION_KEY", "OPENCLAW_GATEWAY_URL"]),
        reason="需要OpenClaw环境",
    )
    def test_is_in_openclaw(self):
        """测试OpenClaw环境检测"""
        adapter = HermesClaudeAdapter(
            hermes_agent_id="hermes",
            claude_agent_id="claude-code",
            psk=b"test-key",
        )

        assert adapter._is_in_openclaw() is True

    def test_is_not_in_openclaw(self):
        """测试非OpenClaw环境检测"""
        # 临时移除环境变量
        old_env = {}
        for key in ["OPENCLAW_SESSION_KEY", "OPENCLAW_GATEWAY_URL", "OPENCLAW_API_KEY"]:
            if key in os.environ:
                old_env[key] = os.environ[key]
                del os.environ[key]

        try:
            adapter = HermesClaudeAdapter(
                hermes_agent_id="hermes",
                claude_agent_id="claude-code",
                psk=b"test-key",
            )

            assert adapter._is_in_openclaw() is False
        finally:
            # 恢复环境变量
            for key, value in old_env.items():
                os.environ[key] = value

    def test_handshake_simplified(self):
        """测试简化版握手（使用PSK）"""
        adapter = HermesClaudeAdapter(
            hermes_agent_id="hermes",
            claude_agent_id="claude-code",
            psk=b"test-key",
        )

        # 简化版握手只是占位符，不抛异常即可
        asyncio.run(adapter.handshake())

    def test_decrypt_response_unencrypted(self):
        """测试解密未加密的响应"""
        adapter = HermesClaudeAdapter(
            hermes_agent_id="hermes",
            claude_agent_id="claude-code",
            psk=b"test-key",
        )

        # 未加密的响应直接返回原文
        response = {"text": "Hello, world!"}
        decrypted = adapter._decrypt_openclaw_response(response)

        assert decrypted == "Hello, world!"

    def test_decrypt_response_encrypted(self):
        """测试解密加密的响应"""
        # 这个测试需要真实的通道建立，暂时跳过
        pytest.skip("需要完整的握手实现")

    @pytest.mark.skipif(
        not any(p in os.environ for p in ["OPENCLAW_SESSION_KEY", "OPENCLAW_GATEWAY_URL"]),
        reason="需要OpenClaw环境",
    )
    async def test_send_receive_roundtrip(self):
        """测试发送接收往返"""
        adapter = HermesClaudeAdapter(
            hermes_agent_id="hermes",
            claude_agent_id="claude-code",
            psk=b"test-key",
        )

        # 建立通道
        await adapter.handshake()

        # 由于这需要真实的OpenClaw环境，我们只测试加密部分
        # 不真正发送
        encrypted_msg = adapter._channel.send("Test message", "claude-code")

        assert encrypted_msg.sender_id == "hermes"
        assert encrypted_msg.recipient_id == "claude-code"
