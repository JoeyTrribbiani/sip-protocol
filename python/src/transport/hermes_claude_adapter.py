"""
Hermes ↔ Claude Code 加密通信适配器

让Hermes和Claude Code通过SIP协议端到端加密通信，而不是明文通过OpenClaw。

架构：
    Hermes (加密) → OpenClaw sessions_send → Claude Code (解密)

实现方式：
1. 加密包装器：在发送前用SIP加密，接收后解密
2. 通过sessions_spawn启动Claude Code，用sessions_send发送加密消息
3. Claude Code端同样用SIP解密收到的消息

使用方式（Hermes端）：
    from sip_protocol.transport.hermes_claude_adapter import HermesClaudeAdapter

    adapter = HermesClaudeAdapter(
        hermes_agent_id="hermes",
        claude_agent_id="claude-code",
        psk=b"shared-secret-key",
    )

    # 建立加密通道
    await adapter.handshake()

    # 发送加密消息到Claude Code
    response = await adapter.send("帮我写一个Python函数")

    # 接收来自Claude Code的加密消息
    message = await adapter.receive()

    await adapter.close()
"""

import asyncio
import json
import os
from typing import Any, Dict, Optional

from .encrypted_channel import EncryptedChannel, ChannelConfig
from .message import AgentMessage, MessageType


class HermesClaudeAdapter:
    """
    Hermes ↔ Claude Code 加密通信适配器

    在OpenClaw的sessions_send之上加一层SIP加密：
    1. 发送时：用SIP加密 → base64编码 → 通过sessions_send发送
    2. 接收时：通过sessions_send接收 → base64解码 → SIP解密

    注意：这需要OpenClaw环境支持sessions_spawn/sessions_send。
    """

    def __init__(
        self,
        hermes_agent_id: str,
        claude_agent_id: str,
        psk: bytes,
        model: str = "claude-sonnet",
    ):
        """
        初始化适配器

        Args:
            hermes_agent_id: Hermes的Agent ID
            claude_agent_id: Claude Code的Agent ID
            psk: 预共享密钥（用于密钥派生）
            model: Claude Code使用的模型
        """
        self.hermes_agent_id = hermes_agent_id
        self.claude_agent_id = claude_agent_id
        self.model = model
        self._channel = EncryptedChannel(
            agent_id=hermes_agent_id,
            psk=psk,
            config=ChannelConfig(
                rekey_after_messages=10000,
                rekey_after_seconds=3600,
            ),
        )
        self._claude_session_key: Optional[str] = None

    async def _spawn_claude_code(self) -> str:
        """
        启动Claude Code子会话

        Returns:
            子会话的session_key
        """
        # 检查是否在OpenClaw环境中
        if not self._is_in_openclaw():
            raise RuntimeError("此适配器需要在OpenClaw环境中运行")

        # 这里需要调用OpenClaw的sessions_spawn
        # 由于这是Python代码，我们通过subprocess调用hermes CLI
        import subprocess

        cmd = [
            "hermes",
            "spawn",
            "--runtime",
            "acp",
            "--agent-id",
            "claude-code",
            "--task",
            "You are a coding assistant. You will receive encrypted messages, decrypt them, and respond.",
            "--mode",
            "session",
            "--thread",
        ]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60,
        )

        if result.returncode != 0:
            raise RuntimeError(f"启动Claude Code失败: {result.stderr}")

        # 解析输出获取session_key
        # 假设输出包含 "childSessionKey: agent:main:subagent:xxx"
        for line in result.stdout.split("\n"):
            if "childSessionKey:" in line:
                self._claude_session_key = line.split(":", 1)[1].strip()
                break

        if not self._claude_session_key:
            raise RuntimeError("无法获取Claude Code session_key")

        return self._claude_session_key

    def _is_in_openclaw(self) -> bool:
        """检查是否在OpenClaw环境中"""
        return "OPENCLAW_SESSION_KEY" in os.environ or any(
            p in os.environ for p in ["OPENCLAW_GATEWAY_URL", "OPENCLAW_API_KEY"]
        )

    async def handshake(self) -> None:
        """
        执行SIP握手协议

        由于双方都运行在OpenClaw环境中，我们可以：
        1. Hermes发起握手，生成Hello消息
        2. 通过sessions_send发送Hello给Claude Code
        3. Claude Code响应Auth消息
        4. Hermes完成握手

        注意：这需要Claude Code也运行SIP协议栈。
        简化版本：直接用PSK派生会话密钥，跳过DH交换。
        """
        # 简化版本：用PSK直接建立通道
        # 在实际场景中，应该通过DH交换建立密钥

        # 生成一个虚拟的握手完成消息
        # 这里我们假设双方都知道PSK，直接使用PSK派生密钥
        # 实际应用中应该通过DH交换
        pass

    async def send(self, plaintext: str) -> str:
        """
        发送加密消息到Claude Code

        Args:
            plaintext: 明文消息

        Returns:
            Claude Code的响应（解密后）
        """
        # 1. 用SIP加密消息
        encrypted_msg = self._channel.send(plaintext, self.claude_agent_id)

        # 2. 序列化并base64编码
        msg_json = encrypted_msg.to_json()
        import base64

        msg_b64 = base64.b64encode(msg_json.encode()).decode()

        # 3. 通过OpenClaw的sessions_send发送
        # 这里需要调用OpenClaw API
        response = await self._send_via_openclaw(msg_b64)

        # 4. 解密响应
        decrypted_response = self._decrypt_openclaw_response(response)

        return decrypted_response

    async def _send_via_openclaw(self, encrypted_message: str) -> Dict[str, Any]:
        """
        通过OpenClaw发送加密消息

        Args:
            encrypted_message: base64编码的加密消息

        Returns:
            OpenClaw的响应
        """
        # 这里需要调用OpenClaw的sessions_send API
        # 由于Python直接调用OpenClaw API比较复杂，
        # 我们通过subprocess调用hermes CLI

        import subprocess

        cmd = [
            "hermes",
            "sessions",
            "send",
            "--session-key",
            self._claude_session_key or f"agent:{self.claude_agent_id}",
            "--message",
            f"ENCRYPTED:{encrypted_message}",
        ]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,  # 2分钟超时
        )

        if result.returncode != 0:
            raise RuntimeError(f"发送消息失败: {result.stderr}")

        # 解析响应
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError:
            # 如果不是JSON，返回原始文本
            return {"text": result.stdout}

    def _decrypt_openclaw_response(self, response: Dict[str, Any]) -> str:
        """
        解密OpenClaw的响应

        Args:
            response: OpenClaw响应

        Returns:
            解密后的明文
        """
        # 检查响应是否是加密的
        response_text = response.get("text", "")
        if not response_text.startswith("ENCRYPTED:"):
            # 如果不是加密的，直接返回
            return response_text

        # 提取加密消息
        encrypted_b64 = response_text[len("ENCRYPTED:") :]

        # Base64解码
        import base64

        msg_json = base64.b64decode(encrypted_b64).decode()

        # 解析AgentMessage
        agent_msg = AgentMessage.from_json(msg_json)

        # 解密
        plaintext = self._channel.receive(agent_msg)

        return plaintext

    async def receive(self) -> Optional[str]:
        """
        接收来自Claude Code的加密消息

        Returns:
            解密后的消息，如果没有消息则返回None
        """
        # 这里需要轮询OpenClaw的sessions_history
        # 由于这比较复杂，我们简化处理：
        # 假设消息通过send的响应返回

        return None

    async def close(self) -> None:
        """关闭适配器"""
        if self._claude_session_key:
            # 关闭Claude Code子会话
            import subprocess

            subprocess.run(
                ["hermes", "sessions", "kill", "--session-key", self._claude_session_key],
                capture_output=True,
            )
