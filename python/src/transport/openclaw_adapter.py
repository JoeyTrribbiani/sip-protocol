"""
OpenClaw适配器模块
实现SIP加密通道与OpenClaw平台的集成

提供以下能力：
1. 通过subprocess调用OpenClaw CLI
2. 通过HTTP调用OpenClaw Gateway API
3. 通过Hermes MCP API发送加密消息
4. 封装sessions_spawn/sessions_send等操作
5. 管理Agent生命周期
6. 实现TransportAdapter接口

使用方式：
    adapter = OpenClawAdapter(agent_id="hermes")
    await adapter.connect()
    await adapter.send(message)
    await adapter.close()
"""

import asyncio
import json
import os
import subprocess
import time
from typing import Any, Callable, Dict, List, Optional, Tuple
from dataclasses import dataclass

try:
    import aiohttp
except ImportError:
    aiohttp = None  # type: ignore

from .message import AgentMessage, MessageType
from .encrypted_channel import EncryptedChannel, ChannelState, ChannelConfig

# ──────────────── 数据类 ────────────────


@dataclass
class GatewayConfig:
    """Gateway API配置"""

    # Gateway API地址
    gateway_url: str = os.environ.get("OPENCLAW_GATEWAY_URL", "http://localhost:3000/api")
    # API密钥
    api_key: str = os.environ.get("OPENCLAW_API_KEY", "")
    # Gateway token (Bearer认证)
    gateway_token: str = os.environ.get("OPENCLAW_GATEWAY_TOKEN", "")
    # 使用API而非CLI
    use_api: bool = True
    # 请求超时 (秒)
    request_timeout: int = 30
    # 最大重试次数
    max_retries: int = 3
    # 重试间隔 (秒)
    retry_delay: float = 1.0


@dataclass
class AgentConfig:
    """Agent配置"""

    agent_id: str
    agent_type: str  # "decision", "orchestrator", "executor"
    psk: bytes = b""
    openclaw_path: str = "openclaw"
    model: str = "claude-sonnet"
    label: str = ""
    # Gateway配置
    gateway: Optional[GatewayConfig] = None


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

    # ──────────────── 统计辅助方法 ────────────────

    def _increment_stat(self, key: str, value: int = 1) -> None:
        """安全地递增统计值"""
        current = self._stats.get(key, 0)
        if isinstance(current, (int, float)):
            self._stats[key] = current + value
        else:
            self._stats[key] = value

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

    def _on_channel_error(self, _error: Exception) -> None:
        """通道错误回调"""
        self._increment_stat("errors")

    def _on_channel_state_change(self, old_state: ChannelState, new_state: ChannelState) -> None:
        """通道状态变更回调"""

    # ──────────────── 生命周期 ────────────────

    def start(self) -> None:
        """启动适配器"""
        self._stats["started_at"] = int(time.time())

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
        self._increment_stat("messages_sent")
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
        self._increment_stat("messages_received")
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
                check=True,
            )
            return result.returncode, result.stdout, result.stderr
        except FileNotFoundError as e:
            raise RuntimeError(f"OpenClaw CLI未找到: {self.config.openclaw_path}") from e
        except subprocess.TimeoutExpired as e:
            raise RuntimeError(f"OpenClaw命令超时: {' '.join(args)}") from e

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
                self._increment_stat("sessions_spawned")
                return result
            return SpawnResult(
                session_id="",
                label=session_label,
                success=False,
                error=stderr.strip() or stdout.strip(),
            )
        except RuntimeError as e:
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
            returncode, _stdout, _stderr = self._run_openclaw(args)
            return returncode == 0
        except RuntimeError:
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

    # ──────────────── Gateway API操作 ────────────────

    def _handle_gateway_response(
        self,
        response,
        path: str,
        attempt: int,
        max_retries: int,
        _retry_delay: float,
    ) -> Dict[str, Any]:
        """处理Gateway响应"""
        if response.status == 200:
            return dict(response.json())
        if response.status == 401:
            raise RuntimeError("Gateway认证失败：请检查OPENCLAW_API_KEY或OPENCLAW_GATEWAY_TOKEN")
        if response.status == 404:
            raise RuntimeError(f"Gateway API端点不存在: {path}")
        if response.status >= 500:
            # 服务端错误，重试
            text = response.text
            last_error = RuntimeError(f"Gateway服务端错误 ({response.status}): {text}")
            if attempt < max_retries - 1:
                raise last_error  # 重新抛出以触发重试
            raise last_error
        text = response.text
        raise RuntimeError(f"Gateway请求失败 ({response.status}): {text}")

    async def _gateway_request(
        self,
        method: str,
        path: str,
        data: Optional[Dict[str, Any]] = None,
        timeout: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        向OpenClaw Gateway API发送HTTP请求

        Args:
            method: HTTP方法 (GET, POST, PUT, DELETE)
            path: API路径 (如 /messages/send)
            data: 请求体数据
            timeout: 超时时间

        Returns:
            Dict[str, Any]: API响应JSON

        Raises:
            RuntimeError: Gateway不可用或请求失败
        """
        gateway_config = self.config.gateway
        if gateway_config is None:
            raise RuntimeError("Gateway配置未提供")

        if aiohttp is None:
            raise RuntimeError("aiohttp未安装，请运行: pip install aiohttp")

        url = f"{gateway_config.gateway_url.rstrip('/')}{path}"
        headers: Dict[str, str] = {"Content-Type": "application/json"}

        if gateway_config.api_key:
            headers["X-API-Key"] = gateway_config.api_key
        if gateway_config.gateway_token:
            headers["Authorization"] = f"Bearer {gateway_config.gateway_token}"

        request_timeout = timeout or gateway_config.request_timeout
        last_error: Optional[Exception] = None

        for attempt in range(gateway_config.max_retries):
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.request(
                        method=method,
                        url=url,
                        headers=headers,
                        json=data,
                        timeout=aiohttp.ClientTimeout(total=request_timeout),
                    ) as response:
                        try:
                            return self._handle_gateway_response(
                                response,
                                path,
                                attempt,
                                gateway_config.max_retries,
                                gateway_config.retry_delay,
                            )
                        except RuntimeError as e:
                            if "服务端错误" in str(e) and attempt < gateway_config.max_retries - 1:
                                last_error = e
                                await asyncio.sleep(gateway_config.retry_delay * (attempt + 1))
                                continue
                            raise e
            except aiohttp.ClientConnectorError as e:
                last_error = RuntimeError(f"无法连接到Gateway ({gateway_config.gateway_url}): {e}")
                if attempt < gateway_config.max_retries - 1:
                    await asyncio.sleep(gateway_config.retry_delay * (attempt + 1))
                    continue
                raise last_error from e
            except asyncio.TimeoutError as e:
                last_error = RuntimeError(f"Gateway请求超时 ({request_timeout}s): {path}")
                if attempt < gateway_config.max_retries - 1:
                    await asyncio.sleep(gateway_config.retry_delay * (attempt + 1))
                    continue
                raise last_error from e

        raise last_error or RuntimeError("Gateway请求失败")

    async def gateway_send_message(
        self,
        target: str,
        text: str,
        encrypted: bool = True,
    ) -> Dict[str, Any]:
        """
        通过Gateway API发送消息

        Args:
            target: 目标标识 (如 "telegram:12345", "discord:#general")
            text: 消息文本
            encrypted: 是否使用SIP加密

        Returns:
            Dict[str, Any]: API响应
        """
        if encrypted and self.is_connected:
            encrypted_msg = self.send_encrypted(text)
            payload_text = encrypted_msg.to_json()
        else:
            payload_text = text

        return await self._gateway_request(
            method="POST",
            path="/messages/send",
            data={
                "target": target,
                "message": payload_text,
            },
        )

    async def gateway_read_messages(
        self,
        channel: Optional[str] = None,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        """
        通过Gateway API读取消息

        Args:
            channel: 频道标识 (可选)
            limit: 消息数量限制

        Returns:
            List[Dict[str, Any]]: 消息列表
        """
        params: Dict[str, Any] = {"limit": limit}
        if channel:
            params["channel"] = channel

        result = await self._gateway_request(
            method="GET",
            path="/messages/read",
            data=params,
        )
        messages: List[Dict[str, Any]] = result.get("messages", [])  # type: ignore[assignment]

        # 如果通道已建立，尝试解密加密消息
        if self.is_connected:
            for msg_data in messages:
                content = msg_data.get("content", "")
                if msg_data.get("encrypted", False) and content:
                    try:
                        agent_msg = AgentMessage.from_json(content)
                        plaintext = self.receive_encrypted(agent_msg)
                        msg_data["decrypted_content"] = plaintext
                    except (ValueError, KeyError):
                        pass  # 无法解密，保留原始内容

        return messages

    async def gateway_list_channels(
        self,
        platform: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        通过Gateway API列出可用频道

        Args:
            platform: 平台过滤 (telegram, discord, slack等)

        Returns:
            List[Dict[str, Any]]: 频道列表
        """
        params: Dict[str, Any] = {}
        if platform:
            params["platform"] = platform

        result = await self._gateway_request(
            method="GET",
            path="/channels/list",
            data=params,
        )
        return list(result.get("channels", []))  # type: ignore[arg-type]

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
        # 非加密消息直接包装转发
        msg.increment_hop()
        text = msg.payload.get("text", json.dumps(msg.payload))
        return self._channel.send(text, next_recipient_id)
