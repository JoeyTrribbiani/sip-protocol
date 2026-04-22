"""
传输层抽象接口测试
测试TransportAdapter抽象基类和相关数据结构
"""

import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.transport.base import (
    TransportAdapter,
    TransportType,
    TransportState,
    TransportConfig,
    ConnectionResult,
    SendResult,
    ReceiveResult,
    create_transport,
)
from src.transport.message import AgentMessage, MessageType

# ──────────────── 枚举测试 ────────────────


class TestTransportType:
    """传输类型枚举测试"""

    def test_all_transport_types(self):
        assert TransportType.OPENCRAW == "openclaw"
        assert TransportType.WEBSOCKET == "websocket"
        assert TransportType.HTTP == "http"
        assert TransportType.GRPC == "grpc"
        assert TransportType.QUIC == "quic"

    def test_transport_type_is_string(self):
        for tt in TransportType:
            assert isinstance(tt.value, str)


class TestTransportState:
    """传输状态枚举测试"""

    def test_all_states(self):
        assert TransportState.DISCONNECTED == "disconnected"
        assert TransportState.CONNECTING == "connecting"
        assert TransportState.CONNECTED == "connected"
        assert TransportState.RECONNECTING == "reconnecting"
        assert TransportState.ERROR == "error"
        assert TransportState.CLOSED == "closed"


# ──────────────── 数据类测试 ────────────────


class TestTransportConfig:
    """传输配置测试"""

    def test_default_config(self):
        config = TransportConfig()
        assert config.connect_timeout == 30
        assert config.send_timeout == 10
        assert config.receive_timeout == 30
        assert config.heartbeat_interval == 30
        assert config.max_reconnect == 5
        assert config.reconnect_delay == 1.0
        assert config.enable_compression is False
        assert config.enable_tls is False

    def test_custom_config(self):
        config = TransportConfig(
            connect_timeout=60,
            send_timeout=20,
            max_reconnect=10,
            enable_tls=True,
        )
        assert config.connect_timeout == 60
        assert config.send_timeout == 20
        assert config.max_reconnect == 10
        assert config.enable_tls is True


class TestConnectionResult:
    """连接结果测试"""

    def test_success_result(self):
        result = ConnectionResult(
            success=True,
            transport_type=TransportType.WEBSOCKET,
            latency_ms=50,
        )
        assert result.success is True
        assert result.transport_type == TransportType.WEBSOCKET
        assert result.error is None
        assert result.latency_ms == 50
        assert result.retry_count == 0

    def test_failure_result(self):
        result = ConnectionResult(
            success=False,
            transport_type=TransportType.OPENCRAW,
            error="连接被拒绝",
        )
        assert result.success is False
        assert result.error == "连接被拒绝"


class TestSendResult:
    """发送结果测试"""

    def test_success_result(self):
        result = SendResult(
            success=True,
            message_id="msg-123",
            bytes_sent=256,
        )
        assert result.success is True
        assert result.message_id == "msg-123"
        assert result.error is None
        assert result.bytes_sent == 256

    def test_failure_result(self):
        result = SendResult(
            success=False,
            message_id="msg-456",
            error="发送超时",
        )
        assert result.success is False
        assert result.error == "发送超时"


class TestReceiveResult:
    """接收结果测试"""

    def test_success_with_message(self):
        msg = AgentMessage(type=MessageType.TEXT, payload={"text": "hello"})
        result = ReceiveResult(
            success=True,
            message=msg,
            bytes_received=128,
        )
        assert result.success is True
        assert result.message is not None
        assert result.message.payload["text"] == "hello"
        assert result.bytes_received == 128

    def test_failure_result(self):
        result = ReceiveResult(
            success=False,
            error="接收超时",
        )
        assert result.success is False
        assert result.message is None
        assert result.error == "接收超时"


# ──────────────── 抽象基类测试 ────────────────


class ConcreteTransport(TransportAdapter):
    """用于测试的具体传输适配器"""

    def __init__(self):
        self._state = TransportState.DISCONNECTED
        self._connected = False
        self._messages_sent = []
        self._message_callback = None
        self._connect_callback = None
        self._disconnect_callback = None
        self._error_callback = None
        self._state_change_callback = None

    @property
    def transport_type(self) -> TransportType:
        return TransportType.HTTP

    @property
    def state(self) -> TransportState:
        return self._state

    @property
    def is_connected(self) -> bool:
        return self._connected

    @property
    def remote_endpoint(self):
        return "http://localhost:8080" if self._connected else None

    @property
    def stats(self):
        return {"messages_sent": len(self._messages_sent)}

    async def connect(self, endpoint: str = "", timeout=None):
        self._state = TransportState.CONNECTED
        self._connected = True
        if self._connect_callback:
            self._connect_callback()
        return ConnectionResult(
            success=True,
            transport_type=self.transport_type,
            latency_ms=10,
        )

    async def close(self):
        self._state = TransportState.CLOSED
        self._connected = False
        if self._disconnect_callback:
            self._disconnect_callback(None)

    async def send(self, message, timeout=None):
        if not self._connected:
            return SendResult(success=False, message_id=message.id, error="未连接")
        self._messages_sent.append(message)
        return SendResult(
            success=True,
            message_id=message.id,
            bytes_sent=len(message.to_json()),
        )

    async def receive(self, timeout=None):
        if not self._messages_sent:
            return ReceiveResult(success=False, error="无消息")
        msg = self._messages_sent.pop(0)
        return ReceiveResult(success=True, message=msg, bytes_received=100)

    async def send_receive(self, message, timeout=None):
        send_result = await self.send(message)
        if not send_result.success:
            return ReceiveResult(success=False, error=send_result.error)
        return await self.receive(timeout)

    def on_message(self, callback):
        self._message_callback = callback

    def on_connect(self, callback):
        self._connect_callback = callback

    def on_disconnect(self, callback):
        self._disconnect_callback = callback

    def on_error(self, callback):
        self._error_callback = callback

    def on_state_change(self, callback):
        self._state_change_callback = callback


class TestTransportAdapterABC:
    """传输适配器抽象基类测试"""

    def test_cannot_instantiate_abstract(self):
        with pytest.raises(TypeError):
            TransportAdapter()

    def test_concrete_implementation(self):
        adapter = ConcreteTransport()
        assert adapter.transport_type == TransportType.HTTP
        assert adapter.state == TransportState.DISCONNECTED
        assert adapter.is_connected is False
        assert adapter.remote_endpoint is None

    @pytest.mark.asyncio
    async def test_connect_and_close(self):
        adapter = ConcreteTransport()
        result = await adapter.connect("http://localhost:8080")
        assert result.success is True
        assert adapter.is_connected is True
        assert adapter.state == TransportState.CONNECTED

        await adapter.close()
        assert adapter.is_connected is False
        assert adapter.state == TransportState.CLOSED

    @pytest.mark.asyncio
    async def test_send_and_receive(self):
        adapter = ConcreteTransport()
        await adapter.connect()

        msg = AgentMessage(
            type=MessageType.TEXT,
            sender_id="agent-a",
            payload={"text": "hello"},
        )

        send_result = await adapter.send(msg)
        assert send_result.success is True
        assert send_result.message_id == msg.id

        recv_result = await adapter.receive()
        assert recv_result.success is True
        assert recv_result.message is not None

    @pytest.mark.asyncio
    async def test_send_receive_combined(self):
        adapter = ConcreteTransport()
        await adapter.connect()

        msg = AgentMessage(
            type=MessageType.TEXT,
            sender_id="agent-a",
            payload={"text": "hello"},
        )

        result = await adapter.send_receive(msg)
        assert result.success is True
        assert result.message is not None

    @pytest.mark.asyncio
    async def test_send_when_disconnected(self):
        adapter = ConcreteTransport()
        msg = AgentMessage(payload={"text": "test"})
        result = await adapter.send(msg)
        assert result.success is False
        assert result.error == "未连接"

    @pytest.mark.asyncio
    async def test_receive_when_no_messages(self):
        adapter = ConcreteTransport()
        result = await adapter.receive(timeout=0.1)
        assert result.success is False

    def test_callback_registration(self):
        adapter = ConcreteTransport()
        callbacks = []
        adapter.on_message(lambda m: callbacks.append(("msg", m)))
        adapter.on_connect(lambda: callbacks.append("connect"))
        adapter.on_disconnect(lambda e: callbacks.append(("disconnect", e)))
        adapter.on_error(lambda e: callbacks.append(("error", e)))
        adapter.on_state_change(lambda o, n: callbacks.append(("state", o, n)))
        # 回调已注册（无直接断言，只确认不报错）

    @pytest.mark.asyncio
    async def test_async_context_manager(self):
        adapter = ConcreteTransport()
        async with adapter:
            assert adapter.is_connected is True
        assert adapter.state == TransportState.CLOSED


# ──────────────── 工厂函数测试 ────────────────


class TestCreateTransport:
    """传输适配器工厂函数测试"""

    def test_create_websocket_adapter(self):
        adapter = create_transport(TransportType.WEBSOCKET, agent_id="test")
        assert adapter is not None
        assert adapter.transport_type == TransportType.WEBSOCKET

    def test_unsupported_type_raises(self):
        with pytest.raises(ValueError, match="不支持的传输类型"):
            create_transport(TransportType.HTTP)

    def test_create_with_custom_config(self):
        config = TransportConfig(connect_timeout=60)
        adapter = create_transport(TransportType.WEBSOCKET, config=config, agent_id="test")
        assert adapter.config.connect_timeout == 60
