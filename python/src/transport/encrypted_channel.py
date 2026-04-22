"""
加密消息通道模块
基于SIP加密库实现Agent间的端到端加密通信

核心功能：
1. 建立加密通道（基于SIP握手）
2. 发送加密消息
3. 接收并解密消息
4. 密钥轮换（Rekey）
5. 通道状态管理

使用方式：
    channel = EncryptedChannel(
        agent_id="agent:hermes::session:abc",
        psk=b"shared-secret-key"
    )
    await channel.connect(remote_public_key)
    await channel.send("Hello, encrypted world!")
    msg = await channel.receive()
"""

import os
import time
import json
import hmac
import hashlib
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple
from dataclasses import dataclass, field

from ..protocol.handshake import (
    initiate_handshake,
    respond_handshake,
    complete_handshake,
)
from ..protocol.message import (
    encrypt_message,
    decrypt_message,
    generate_replay_tag,
    verify_replay_tag,
)
from ..protocol.rekey import RekeyManager
from ..managers.session import SessionState
from ..managers.nonce import NonceManager
from ..crypto.dh import generate_keypair, dh_exchange
from ..crypto.argon2 import hash_psk
from ..crypto.hkdf import derive_keys_triple_dh

from .message import (
    AgentMessage,
    MessageType,
    ControlAction,
    create_text_message,
    create_control_message,
    create_encrypted_message,
)


class ChannelState(str, Enum):
    """通道状态"""

    IDLE = "idle"
    HANDSHAKING = "handshaking"
    ESTABLISHED = "established"
    REKEYING = "rekeying"
    CLOSED = "closed"
    ERROR = "error"


@dataclass
class ChannelConfig:
    """通道配置"""

    # 消息计数器达到此值触发rekey
    rekey_after_messages: int = 10000
    # 连接时长达到此值触发rekey (秒)
    rekey_after_seconds: int = 3600
    # 心跳间隔 (秒)
    heartbeat_interval: int = 30
    # 消息TTL (毫秒)
    message_ttl_ms: int = 5 * 60 * 1000
    # 最大重试次数
    max_retries: int = 3
    # 重试间隔 (毫秒)
    retry_delay_ms: int = 500


class EncryptedChannel:
    """
    加密消息通道

    封装SIP握手、消息加密/解密、密钥轮换等操作，
    提供简洁的send/receive接口。

    使用流程：
    1. 创建通道 (EncryptedChannel)
    2. 发起或响应握手 (initiate / respond)
    3. 发送/接收消息 (send / receive)
    4. 关闭通道 (close)
    """

    def __init__(
        self,
        agent_id: str,
        psk: bytes,
        config: Optional[ChannelConfig] = None,
        identity_private_key=None,
        identity_public_key=None,
    ):
        """
        初始化加密通道

        Args:
            agent_id: 本地Agent ID
            psk: 预共享密钥
            config: 通道配置
            identity_private_key: 身份私钥（可选，用于持久化）
            identity_public_key: 身份公钥（可选，用于持久化）
        """
        self.agent_id = agent_id
        self.psk = psk
        self.config = config or ChannelConfig()
        self.state = ChannelState.IDLE
        self.remote_agent_id: Optional[str] = None

        # 密钥管理
        self._identity_private_key = identity_private_key
        self._identity_public_key = identity_public_key
        self._session_keys: Optional[Dict[str, bytes]] = None
        self._session_state: Optional[SessionState] = None
        self._nonce_manager = NonceManager()

        # 消息计数器
        self._send_counter: int = 0
        self._recv_counter: int = 0

        # 握手状态
        self._handshake_state: Optional[Dict[str, Any]] = None

        # 通道统计
        self._stats = {
            "messages_sent": 0,
            "messages_received": 0,
            "bytes_sent": 0,
            "bytes_received": 0,
            "created_at": time.time(),
            "established_at": None,
            "last_rekey_at": None,
            "errors": 0,
        }

        # 回调
        self._on_message: Optional[Callable] = None
        self._on_error: Optional[Callable] = None
        self._on_state_change: Optional[Callable] = None

    # ──────────────── 状态管理 ────────────────

    def _set_state(self, new_state: ChannelState) -> None:
        """更新通道状态"""
        old_state = self.state
        self.state = new_state
        if self._on_state_change:
            self._on_state_change(old_state, new_state)

    @property
    def is_established(self) -> bool:
        """通道是否已建立"""
        return self.state == ChannelState.ESTABLISHED

    @property
    def stats(self) -> Dict[str, Any]:
        """获取通道统计信息"""
        return {**self._stats, "state": self.state.value}

    # ──────────────── 握手 ────────────────

    def initiate(self) -> AgentMessage:
        """
        发起握手

        Returns:
            AgentMessage: 握手Hello消息（需要传输给对方）
        """
        if self.state != ChannelState.IDLE:
            raise RuntimeError(f"无法在 {self.state.value} 状态下发起握手")

        self._set_state(ChannelState.HANDSHAKING)

        try:
            handshake_hello, agent_state = initiate_handshake(
                psk=self.psk,
                identity_private_key=self._identity_private_key,
                identity_public_key=self._identity_public_key,
            )
            self._handshake_state = agent_state
            self._identity_private_key = agent_state["identity_private_key"]
            self._identity_public_key = agent_state["identity_public_key"]

            # 包装为AgentMessage
            return create_control_message(
                sender_id=self.agent_id,
                recipient_id="",  # 尚未知道对方ID
                action=ControlAction.HANDSHAKE_INIT,
                data=handshake_hello,
            )
        except Exception as e:
            self._set_state(ChannelState.ERROR)
            self._stats["errors"] += 1
            if self._on_error:
                self._on_error(e)
            raise

    def respond_to_handshake(self, handshake_msg: AgentMessage) -> AgentMessage:
        """
        响应握手请求

        Args:
            handshake_msg: 收到的握手Hello消息

        Returns:
            AgentMessage: 握手Auth响应消息
        """
        if self.state != ChannelState.IDLE:
            raise RuntimeError(f"无法在 {self.state.value} 状态下响应握手")

        self._set_state(ChannelState.HANDSHAKING)
        self.remote_agent_id = handshake_msg.sender_id

        try:
            handshake_hello = handshake_msg.payload.get("data", handshake_msg.payload)
            handshake_auth, agent_state, session_keys = respond_handshake(
                handshake_hello,
                psk=self.psk,
                identity_private_key=self._identity_private_key,
                identity_public_key=self._identity_public_key,
            )
            self._handshake_state = agent_state
            self._identity_private_key = agent_state["identity_private_key"]
            self._identity_public_key = agent_state["identity_public_key"]
            self._session_keys = session_keys

            # 创建SessionState
            self._session_state = SessionState()
            self._session_state.agent_id = self.agent_id
            self._session_state.remote_agent_id = self.remote_agent_id
            self._session_state.encryption_key = session_keys["encryption_key"]
            self._session_state.auth_key = session_keys["auth_key"]
            self._session_state.replay_key = session_keys["replay_key"]

            # 响应方在respond_handshake后已获得所有密钥，可以视为ESTABLISHED
            self._set_state(ChannelState.ESTABLISHED)
            self._stats["established_at"] = time.time()

            return create_control_message(
                sender_id=self.agent_id,
                recipient_id=self.remote_agent_id,
                action=ControlAction.HANDSHAKE_COMPLETE,
                data=handshake_auth,
                correlation_id=handshake_msg.id,
            )
        except Exception as e:
            self._set_state(ChannelState.ERROR)
            self._stats["errors"] += 1
            if self._on_error:
                self._on_error(e)
            raise

    def complete_handshake(self, auth_msg: AgentMessage) -> None:
        """
        完成握手（发起方调用）

        Args:
            auth_msg: 收到的握手Auth消息
        """
        if self.state != ChannelState.HANDSHAKING:
            raise RuntimeError(f"无法在 {self.state.value} 状态下完成握手")

        try:
            handshake_auth = auth_msg.payload.get("data", auth_msg.payload)
            session_keys, session_state = complete_handshake(handshake_auth, self._handshake_state)
            self._session_keys = session_keys
            self._session_state = SessionState()
            self._session_state.agent_id = self.agent_id
            self._session_state.remote_agent_id = auth_msg.sender_id
            self._session_state.encryption_key = session_keys["encryption_key"]
            self._session_state.auth_key = session_keys["auth_key"]
            self._session_state.replay_key = session_keys["replay_key"]
            self.remote_agent_id = auth_msg.sender_id

            self._set_state(ChannelState.ESTABLISHED)
            self._stats["established_at"] = time.time()
            self._handshake_state = None
        except Exception as e:
            self._set_state(ChannelState.ERROR)
            self._stats["errors"] += 1
            if self._on_error:
                self._on_error(e)
            raise

    # ──────────────── 消息收发 ────────────────

    def send(self, text: str, recipient_id: Optional[str] = None) -> AgentMessage:
        """
        发送加密消息

        Args:
            text: 明文消息
            recipient_id: 接收方ID（可选，默认使用握手时的对方ID）

        Returns:
            AgentMessage: 包含加密payload的消息

        Raises:
            RuntimeError: 通道未建立
        """
        if not self.is_established:
            raise RuntimeError("通道未建立，无法发送消息")

        recipient = recipient_id or self.remote_agent_id
        if not recipient:
            raise ValueError("未指定接收方ID")

        # 检查是否需要rekey
        self._check_rekey_needed()

        # 加密消息
        self._send_counter += 1
        encrypted_payload = encrypt_message(
            encryption_key=self._session_keys["encryption_key"],
            plaintext=text,
            sender_id=self.agent_id,
            recipient_id=recipient,
            message_counter=self._send_counter,
            replay_key=self._session_keys["replay_key"],
        )

        # 包装为AgentMessage
        msg = create_encrypted_message(
            sender_id=self.agent_id,
            recipient_id=recipient,
            encrypted_payload=encrypted_payload,
        )

        # 更新统计
        self._stats["messages_sent"] += 1
        self._stats["bytes_sent"] += len(msg.to_json())

        return msg

    def receive(self, msg: AgentMessage) -> str:
        """
        接收并解密消息

        Args:
            msg: 收到的AgentMessage（type应为ENCRYPTED）

        Returns:
            str: 解密后的明文

        Raises:
            RuntimeError: 通道未建立
            ValueError: 消息验证失败
        """
        if not self.is_established:
            raise RuntimeError("通道未建立，无法接收消息")

        # 处理控制消息
        if msg.type == MessageType.CONTROL:
            return self._handle_control_message(msg)

        # 处理加密消息
        if msg.type != MessageType.ENCRYPTED:
            # 普通文本消息直接返回
            if msg.type == MessageType.TEXT:
                return msg.payload.get("text", "")
            raise ValueError(f"不支持的消息类型: {msg.type}")

        # 检查消息过期
        if msg.is_expired(self.config.message_ttl_ms):
            raise ValueError("消息已过期")

        # 检查跳数
        if msg.is_max_hops_reached():
            raise ValueError("消息达到最大跳数")

        # 获取加密payload
        encrypted_payload = msg.payload
        message_counter = encrypted_payload.get("message_counter", 0)

        # 验证replay_tag
        sender_id = encrypted_payload.get("sender_id", msg.sender_id)
        replay_tag = encrypted_payload.get("replay_tag")
        if replay_tag and self._session_keys:
            if not verify_replay_tag(
                self._session_keys["replay_key"],
                sender_id,
                message_counter,
                replay_tag,
            ):
                raise ValueError("重放攻击检测：replay_tag验证失败")

        # 检查消息计数器（防止重放）
        if message_counter <= self._recv_counter:
            raise ValueError(f"消息计数器异常：收到 {message_counter}，期望 > {self._recv_counter}")

        # 解密消息
        try:
            plaintext = decrypt_message(self._session_keys["encryption_key"], encrypted_payload)
        except Exception as e:
            self._stats["errors"] += 1
            if self._on_error:
                self._on_error(e)
            raise ValueError(f"消息解密失败: {e}") from e

        # 更新计数器和统计
        self._recv_counter = message_counter
        self._stats["messages_received"] += 1
        self._stats["bytes_received"] += len(msg.to_json())

        return plaintext

    def _handle_control_message(self, msg: AgentMessage) -> str:
        """处理控制消息"""
        action = msg.payload.get("action", "")
        if action == ControlAction.HEARTBEAT.value:
            return "[heartbeat]"
        elif action == ControlAction.DISCONNECT.value:
            self.close()
            return "[disconnect]"
        elif action == ControlAction.ERROR.value:
            error_msg = msg.payload.get("data", {}).get("message", "unknown error")
            return f"[error: {error_msg}]"
        else:
            return f"[control: {action}]"

    # ──────────────── 密钥轮换 ────────────────

    def _check_rekey_needed(self) -> None:
        """检查是否需要密钥轮换"""
        if not self._stats["established_at"]:
            return

        # 按消息数量检查
        if self._send_counter >= self.config.rekey_after_messages:
            self._initiate_rekey()
            return

        # 按时间检查
        elapsed = time.time() - self._stats["established_at"]
        if elapsed >= self.config.rekey_after_seconds:
            self._initiate_rekey()

    def _initiate_rekey(self) -> None:
        """发起密钥轮换"""
        self._set_state(ChannelState.REKEYING)
        try:
            session_state_dict = {
                "encryption_key": self._session_keys["encryption_key"],
                "auth_key": self._session_keys["auth_key"],
                "replay_key": self._session_keys["replay_key"],
            }
            manager = RekeyManager(session_state_dict, is_initiator=True)
            rekey_request = manager.create_rekey_request()
            self._handshake_state = {"rekey_manager": manager}
            self._stats["last_rekey_at"] = time.time()
        except Exception as e:
            self._set_state(ChannelState.ERROR)
            self._stats["errors"] += 1
            raise

    # ──────────────── 通道控制 ────────────────

    def close(self) -> None:
        """关闭通道"""
        self._set_state(ChannelState.CLOSED)
        self._session_keys = None
        self._session_state = None
        self._handshake_state = None

    def create_heartbeat(self) -> AgentMessage:
        """创建心跳消息"""
        return create_control_message(
            sender_id=self.agent_id,
            recipient_id=self.remote_agent_id or "",
            action=ControlAction.HEARTBEAT,
        )

    def create_disconnect(self) -> AgentMessage:
        """创建断开连接消息"""
        return create_control_message(
            sender_id=self.agent_id,
            recipient_id=self.remote_agent_id or "",
            action=ControlAction.DISCONNECT,
        )

    # ──────────────── 回调注册 ────────────────

    def on_message(self, callback: Callable) -> None:
        """注册消息回调"""
        self._on_message = callback

    def on_error(self, callback: Callable) -> None:
        """注册错误回调"""
        self._on_error = callback

    def on_state_change(self, callback: Callable) -> None:
        """注册状态变更回调"""
        self._on_state_change = callback
