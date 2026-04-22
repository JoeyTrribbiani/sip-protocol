"""
OpenClaw适配器模块
实现SIP加密通道与OpenClaw平台的集成

提供以下能力：
1. 通过subprocess调用OpenClaw CLI
2. 通过Hermes MCP API发送加密消息
3. 封装sessions_spawn/sessions_send等操作
4. 管理Agent生命周期

使用方式：
    adapter = OpenClawAdapter(agent_id="hermes")
    await adapter.start()
    await adapter.send_encrypted(target="openclaw", message="Hello!")
    await adapter.stop()
"""

import json
import os
import subprocess
import asyncio
import time
import shutil
from typing import Any, Callable, Dict, List, Optional, Tuple
from dataclasses import dataclass, field

from .message import (
    AgentMessage,
    MessageType,
    ControlAction,
    create_text_message,
    create_control_message,
    create_encrypted_message,
    parse_raw_message,
)
from .encrypted_channel import EncryptedChannel, ChannelState, ChannelConfig

# ──────────────── 数据类 ────────────────


@dataclass
class AgentConfig:
    """Agent配置"""

    agent_id: str
    agent_type: str  # "decision", "orchestrator", "executor"
    psk: bytes = b""
    openclaw_path: str = "openclaw"
    model: str = "claude-sonnet"
    label: str = ""


@dataclass
class SpawnResult:
    """sessions_spawn结果"""

    session_id: str
    label: str
    success: bool
    error: Optional[str] = None


# ──────────────── OpenClaw适配器 ────────────────


class OpenClawAdapter:
    """
    OpenClaw平台适配器

    将SIP加密通道与OpenClaw的CLI/API集成，
    实现Agent间的安全通信。

    架构：
    ┌─────────────────────────┐
    │   OpenClawAdapter       │
    │  ┌───────────────────┐  │
    │  │  EncryptedChannel │  │  SIP加密层
    │  └───────────────────┘  │
    │  ┌───────────────────┐  │
    │  │  Transport Layer  │  │  subprocess / MCP
    │  └───────────────────┘  │
    └─────────────────────────┘
    """

    def __init__(
        self,
        config: AgentConfig,
        channel_config: Optional[ChannelConfig] = None,
    ):
        """
        初始化OpenClaw适配器

        Args:
            config: Agent配置
            channel_config: 通道配置
        """
        self.config = config
        self.agent_id = config.agent_id
        self.agent_type = config.agent_type

        # 创建加密通道
        self._channel = EncryptedChannel(
            agent_id=config.agent_id,
            psk=config.psk,
            config=channel_config,
        )

        # 注册通道回调
        self._channel.on_error(self._on_channel_error)
        self._channel.on_state_change(self._on_channel_state_change)

        # 消息队列
        self._outbound_queue: List[AgentMessage] = []
        self._inbound_queue: List[AgentMessage] = []

        # 已知Agents
        self._known_agents: Dict[str, Dict[str, Any]] = {}

        # 活跃sessions
        self._sessions: Dict[str, SpawnResult] = {}

        # 统计
        self._stats = {
            "messages_sent": 0,
            "messages_received": 0,
            "sessions_spawned": 0,
            "errors": 0,
            "started_at": None,
        }

        # 回调
        self._on_message_callback: Optional[Callable] = None

    @property
    def channel(self) -> EncryptedChannel:
        """获取底层加密通道"""
        return self._channel

    @property
    def is_connected(self) -> bool:
        """是否已连接"""
        return self._channel.is_established

    @property
    def stats(self) -> Dict[str, Any]:
        """获取统计信息"""
        return {
            **self._stats,
            "channel": self._channel.stats,
            "known_agents": len(self._known_agents),
            "active_sessions": len(self._sessions),
        }

    # ──────────────── 通道回调 ────────────────

    def _on_channel_error(self, error: Exception) -> None:
        """通道错误回调"""
        self._stats["errors"] += 1

    def _on_channel_state_change(self, old_state: ChannelState, new_state: ChannelState) -> None:
        """通道状态变更回调"""
        pass  # 可扩展用于日志/监控

    # ──────────────── 生命周期 ────────────────

    def start(self) -> None:
        """启动适配器"""
        self._stats["started_at"] = time.time()

    def stop(self) -> None:
        """停止适配器"""
        if self._channel.state not in (ChannelState.CLOSED, ChannelState.IDLE):
            self._channel.close()

    # ──────────────── 握手管理 ────────────────

    def initiate_handshake(self) -> AgentMessage:
        """
        发起握手

        Returns:
            AgentMessage: 握手消息（需要发送给对方）
        """
        return self._channel.initiate()

    def respond_to_handshake(self, handshake_msg: AgentMessage) -> AgentMessage:
        """
        响应握手

        Args:
            handshake_msg: 收到的握手消息

        Returns:
            AgentMessage: 响应消息
        """
        response = self._channel.respond_to_handshake(handshake_msg)
        # 注册对方Agent
        self._register_agent(handshake_msg.sender_id)
        return response

    def complete_handshake(self, auth_msg: AgentMessage) -> None:
        """
        完成握手

        Args:
            auth_msg: 认证消息
        """
        self._channel.complete_handshake(auth_msg)
        # 注册对方Agent
        self._register_agent(auth_msg.sender_id)

    # ──────────────── 加密消息收发 ────────────────

    def send_encrypted(self, text: str, recipient_id: Optional[str] = None) -> AgentMessage:
        """
        发送加密消息

        Args:
            text: 明文消息
            recipient_id: 接收方ID

        Returns:
            AgentMessage: 加密后的消息
        """
        msg = self._channel.send(text, recipient_id)
        self._outbound_queue.append(msg)
        self._stats["messages_sent"] += 1
        return msg

    def receive_encrypted(self, msg: AgentMessage) -> str:
        """
        接收并解密消息

        Args:
            msg: 收到的加密消息

        Returns:
            str: 解密后的明文
        """
        plaintext = self._channel.receive(msg)
        self._inbound_queue.append(msg)
        self._stats["messages_received"] += 1
        if self._on_message_callback:
            self._on_message_callback(plaintext, msg)
        return plaintext

    def on_message(self, callback: Callable) -> None:
        """注册消息回调"""
        self._on_message_callback = callback

    # ──────────────── OpenClaw CLI操作 ────────────────

    def _run_openclaw(self, args: List[str], timeout: int = 30) -> Tuple[int, str, str]:
        """
        执行OpenClaw CLI命令

        Args:
            args: 命令参数
            timeout: 超时时间（秒）

        Returns:
            Tuple[int, str, str]: (返回码, stdout, stderr)
        """
        cmd = [self.config.openclaw_path] + args
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            return result.returncode, result.stdout, result.stderr
        except FileNotFoundError:
            raise RuntimeError(f"OpenClaw CLI未找到: {self.config.openclaw_path}")
        except subprocess.TimeoutExpired:
            raise RuntimeError(f"OpenClaw命令超时: {' '.join(args)}")

    def spawn_session(
        self,
        task: str,
        model: Optional[str] = None,
        label: Optional[str] = None,
        timeout: int = 300,
    ) -> SpawnResult:
        """
        通过openclaw sessions spawn创建子Agent会话

        Args:
            task: 任务描述
            model: 模型名称
            label: 会话标签
            timeout: 超时时间

        Returns:
            SpawnResult: spawn结果
        """
        session_label = label or f"{self.agent_id}-session-{int(time.time())}"

        args = [
            "sessions",
            "spawn",
            "--task",
            task,
            "--label",
            session_label,
        ]
        if model:
            args.extend(["--model", model])

        try:
            returncode, stdout, stderr = self._run_openclaw(args, timeout=timeout)

            if returncode == 0:
                session_id = stdout.strip()
                result = SpawnResult(
                    session_id=session_id,
                    label=session_label,
                    success=True,
                )
                self._sessions[session_label] = result
                self._stats["sessions_spawned"] += 1
                return result
            else:
                return SpawnResult(
                    session_id="",
                    label=session_label,
                    success=False,
                    error=stderr.strip() or stdout.strip(),
                )
        except Exception as e:
            return SpawnResult(
                session_id="",
                label=session_label,
                success=False,
                error=str(e),
            )

    def send_to_session(
        self,
        session_label: str,
        message: str,
        encrypted: bool = True,
    ) -> bool:
        """
        向子Agent会话发送消息

        Args:
            session_label: 会话标签
            message: 消息内容
            encrypted: 是否加密

        Returns:
            bool: 是否成功
        """
        if encrypted and self.is_connected:
            # 加密后发送
            encrypted_msg = self.send_encrypted(message)
            payload = encrypted_msg.to_json()
        else:
            payload = message

        args = [
            "sessions",
            "send",
            "--label",
            session_label,
            "--message",
            payload,
        ]

        try:
            returncode, stdout, stderr = self._run_openclaw(args)
            return returncode == 0
        except Exception:
            return False

    # ──────────────── Agent注册 ────────────────

    def _register_agent(self, agent_id: str) -> None:
        """注册已知Agent"""
        if agent_id not in self._known_agents:
            self._known_agents[agent_id] = {
                "id": agent_id,
                "registered_at": time.time(),
                "last_seen": time.time(),
                "messages_count": 0,
            }
        else:
            self._known_agents[agent_id]["last_seen"] = time.time()

    def get_known_agents(self) -> List[str]:
        """获取已知Agent列表"""
        return list(self._known_agents.keys())

    # ──────────────── 消息队列管理 ────────────────

    def get_outbound_messages(self) -> List[AgentMessage]:
        """获取待发送的消息"""
        msgs = self._outbound_queue.copy()
        self._outbound_queue.clear()
        return msgs

    def get_inbound_messages(self) -> List[AgentMessage]:
        """获取已接收的消息"""
        msgs = self._inbound_queue.copy()
        self._inbound_queue.clear()
        return msgs

    # ──────────────── 转发 ────────────────

    def forward_message(
        self,
        msg: AgentMessage,
        next_recipient_id: str,
    ) -> AgentMessage:
        """
        转发消息给下一个Agent（三方通信场景）

        接收一条消息，增加跳数，加密后转发给下一个Agent。

        Args:
            msg: 原始消息
            next_recipient_id: 下一个接收方ID

        Returns:
            AgentMessage: 转发的消息
        """
        if not self.is_connected:
            raise RuntimeError("通道未建立，无法转发消息")

        # 如果是加密消息，先解密再重新加密转发
        if msg.type == MessageType.ENCRYPTED:
            plaintext = self._channel.receive(msg)
            msg.increment_hop()
            forwarded = self._channel.send(plaintext, next_recipient_id)
            # 保留原始元数据
            forwarded.metadata["original_sender"] = msg.sender_id
            forwarded.metadata["forwarded_by"] = self.agent_id
            forwarded.metadata["hop_count"] = msg.hop_count
            return forwarded
        else:
            # 非加密消息直接包装转发
            msg.increment_hop()
            text = msg.payload.get("text", json.dumps(msg.payload))
            return self._channel.send(text, next_recipient_id)
