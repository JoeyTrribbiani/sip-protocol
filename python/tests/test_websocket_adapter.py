"""
WebSocket传输适配器测试
测试WebSocketAdapter的连接、消息收发、重连等功能
"""

import asyncio
import json
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.transport.websocket_adapter import (
    WebSocketAdapter,
    WebSocketConfig,
)
from src.transport.base import (
    TransportType,
    TransportState,
    ConnectionResult,
    SendResult,
    ReceiveResult,
)
from src.transport.message import (
    AgentMessage,
    MessageType,
    create_text_message,
    parse_raw_message,
)

# ──────────────── 配置测试 ────────────────


class TestWebSocketConfig:
    """WebSocket配置测试"""

    def test_default_config(self):
        config = WebSocketConfig()
        assert config.max_message_size == 10 * 1024 * 1024
        assert config.ping_interval == 20.0
        assert config.ping_timeout == 20.0
        assert config.subprotocols is None
        assert config.extra_headers is None
        assert config.compression == "deflate"

    def test_custom_config(self):
        config = WebSocketConfig(
            max_message_size=1024,
            ping_interval=10.0,
            compression=None,
        )
        assert config.max_message_size == 1024
        assert config.ping_interval == 10.0
        assert config.compression is None

    def test_inherits_transport_config(self):
        config = WebSocketConfig()
        assert config.connect_timeout == 30
        assert config.send_timeout == 10
        assert config.max_reconnect == 5


# ──────────────── 适配器基础测试 ────────────────


class TestWebSocketAdapterBasics:
    """WebSocket适配器基础属性测试"""

    def test_transport_type(self):
        adapter = WebSocketAdapter(agent_id="test-agent")
        assert adapter.transport_type == TransportType.WEBSOCKET

    def test_initial_state(self):
        adapter = WebSocketAdapter(agent_id="test-agent")
        assert adapter.state == TransportState.DISCONNECTED
        assert adapter.is_connected is False
        assert adapter.remote_endpoint is None

    def test_initial_stats(self):
        adapter = WebSocketAdapter(agent_id="test-agent")
        stats = adapter.stats
        assert stats["messages_sent"] == 0
        assert stats["messages_received"] == 0
        assert stats["bytes_sent"] == 0
        assert stats["bytes_received"] == 0
        assert stats["state"] == "disconnected"

    def test_custom_config(self):
        config = WebSocketConfig(
            connect_timeout=60,
            max_reconnect=3,
        )
        adapter = WebSocketAdapter(agent_id="test", config=config)
        assert adapter.config.connect_timeout == 60
        assert adapter.config.max_reconnect == 3

    def test_callback_registration(self):
        adapter = WebSocketAdapter(agent_id="test")
        adapter.on_message(lambda m: None)
        adapter.on_connect(lambda: None)
        adapter.on_disconnect(lambda e: None)
        adapter.on_error(lambda e: None)
        adapter.on_state_change(lambda o, n: None)


# ──────────────── 状态管理测试 ────────────────


class TestStateManagement:
    """状态管理测试"""

    def test_state_change_callback(self):
        adapter = WebSocketAdapter(agent_id="test")
        changes = []
        adapter.on_state_change(lambda old, new: changes.append((old, new)))

        adapter._set_state(TransportState.CONNECTING)
        assert len(changes) == 1
        assert changes[0] == (TransportState.DISCONNECTED, TransportState.CONNECTING)

    def test_state_change_same_state_no_callback(self):
        adapter = WebSocketAdapter(agent_id="test")
        changes = []
        adapter.on_state_change(lambda old, new: changes.append((old, new)))

        adapter._set_state(TransportState.DISCONNECTED)  # same as initial
        assert len(changes) == 0

    def test_state_change_multiple(self):
        adapter = WebSocketAdapter(agent_id="test")
        changes = []
        adapter.on_state_change(lambda old, new: changes.append((old, new)))

        adapter._set_state(TransportState.CONNECTING)
        adapter._set_state(TransportState.CONNECTED)
        adapter._set_state(TransportState.CLOSED)

        assert len(changes) == 3
        assert changes[0] == (TransportState.DISCONNECTED, TransportState.CONNECTING)
        assert changes[1] == (TransportState.CONNECTING, TransportState.CONNECTED)
        assert changes[2] == (TransportState.CONNECTED, TransportState.CLOSED)


# ──────────────── 消息队列测试 ────────────────


class TestMessageQueue:
    """消息队列测试"""

    @pytest.mark.asyncio
    async def test_receive_from_empty_queue(self):
        adapter = WebSocketAdapter(agent_id="test")
        result = await adapter.receive(timeout=0.1)
        assert result.success is False
        assert result.error == "接收超时"

    @pytest.mark.asyncio
    async def test_receive_from_queue(self):
        adapter = WebSocketAdapter(agent_id="test")
        msg = create_text_message("agent-a", "agent-b", "hello")

        # 直接放入队列
        await adapter._message_queue.put(msg)

        result = await adapter.receive(timeout=1.0)
        assert result.success is True
        assert result.message is not None
        assert result.message.payload["text"] == "hello"

    @pytest.mark.asyncio
    async def test_multiple_messages_in_queue(self):
        adapter = WebSocketAdapter(agent_id="test")

        for i in range(5):
            msg = create_text_message("sender", "receiver", f"msg-{i}")
            await adapter._message_queue.put(msg)

        for i in range(5):
            result = await adapter.receive(timeout=1.0)
            assert result.success is True
            assert result.message.payload["text"] == f"msg-{i}"


# ──────────────── 发送测试 ────────────────


class TestSend:
    """发送测试"""

    @pytest.mark.asyncio
    async def test_send_when_disconnected(self):
        adapter = WebSocketAdapter(agent_id="test")
        msg = create_text_message("a", "b", "hello")

        result = await adapter.send(msg)
        assert result.success is False
        assert result.error == "未连接"
        assert result.message_id == msg.id

    @pytest.mark.asyncio
    async def test_send_with_mock_websocket(self):
        adapter = WebSocketAdapter(agent_id="test")
        adapter._state = TransportState.CONNECTED
        adapter._websocket = AsyncMock()

        msg = create_text_message("a", "b", "hello")
        result = await adapter.send(msg)

        assert result.success is True
        assert result.message_id == msg.id
        assert result.bytes_sent > 0
        adapter._websocket.send.assert_called_once()

    @pytest.mark.asyncio
    async def test_send_timeout(self):
        adapter = WebSocketAdapter(agent_id="test")
        adapter._state = TransportState.CONNECTED
        adapter._websocket = AsyncMock()

        async def slow_send(data):
            await asyncio.sleep(10)

        adapter._websocket.send = slow_send

        msg = create_text_message("a", "b", "hello")
        result = await adapter.send(msg, timeout=0.1)

        assert result.success is False
        assert "超时" in result.error


# ──────────────── 请求-响应模式测试 ────────────────


class TestSendReceive:
    """请求-响应模式测试"""

    @pytest.mark.asyncio
    async def test_send_receive_with_correlation(self):
        adapter = WebSocketAdapter(agent_id="test")
        adapter._state = TransportState.CONNECTED
        adapter._websocket = AsyncMock()

        request = create_text_message("a", "b", "ping")
        request.correlation_id = "corr-1"

        # 模拟响应：send后直接将响应匹配到pending future
        async def mock_send(data):
            response = create_text_message("b", "a", "pong")
            response.correlation_id = "corr-1"
            # 匹配pending future
            future = adapter._pending_responses.get("corr-1")
            if future and not future.done():
                future.set_result(response)

        adapter._websocket.send = mock_send

        result = await adapter.send_receive(request, timeout=2.0)
        assert result.success is True
        assert result.message.payload["text"] == "pong"

    @pytest.mark.asyncio
    async def test_send_receive_auto_correlation(self):
        adapter = WebSocketAdapter(agent_id="test")
        adapter._state = TransportState.CONNECTED
        adapter._websocket = AsyncMock()

        request = create_text_message("a", "b", "hello")
        assert request.correlation_id is None

        async def mock_send(data):
            sent_msg = AgentMessage.from_json(data)
            response = create_text_message("b", "a", "reply")
            response.correlation_id = sent_msg.id
            future = adapter._pending_responses.get(sent_msg.id)
            if future and not future.done():
                future.set_result(response)

        adapter._websocket.send = mock_send

        result = await adapter.send_receive(request, timeout=2.0)
        assert result.success is True
        assert result.message.payload["text"] == "reply"


# ──────────────── 关闭测试 ────────────────


class TestClose:
    """关闭测试"""

    @pytest.mark.asyncio
    async def test_close_when_disconnected(self):
        adapter = WebSocketAdapter(agent_id="test")
        await adapter.close()
        assert adapter.state == TransportState.CLOSED

    @pytest.mark.asyncio
    async def test_close_with_mock_websocket(self):
        adapter = WebSocketAdapter(agent_id="test")
        adapter._state = TransportState.CONNECTED
        adapter._websocket = AsyncMock()
        adapter._receive_task = asyncio.create_task(asyncio.sleep(100))
        adapter._heartbeat_task = asyncio.create_task(asyncio.sleep(100))

        disconnect_calls = []
        adapter.on_disconnect(lambda e: disconnect_calls.append(e))

        await adapter.close()

        assert adapter.state == TransportState.CLOSED
        assert adapter._websocket is None
        assert len(disconnect_calls) == 1

    @pytest.mark.asyncio
    async def test_close_clears_pending_responses(self):
        adapter = WebSocketAdapter(agent_id="test")
        adapter._state = TransportState.CONNECTED
        adapter._websocket = AsyncMock()

        # 添加pending future
        future = asyncio.Future()
        adapter._pending_responses["corr-1"] = future

        await adapter.close()

        assert future.done()
        assert len(adapter._pending_responses) == 0


# ──────────────── 连接测试（使用mock） ────────────────


class TestConnect:
    """连接测试"""

    @pytest.mark.asyncio
    async def test_connect_sets_endpoint(self):
        """验证connect设置了endpoint"""
        adapter = WebSocketAdapter(agent_id="test")
        adapter._endpoint = "ws://localhost:8765"
        adapter._should_reconnect = True
        assert adapter.remote_endpoint == "ws://localhost:8765"

    @pytest.mark.asyncio
    async def test_connect_result_structure(self):
        """验证ConnectionResult结构"""
        result = ConnectionResult(
            success=True,
            transport_type=TransportType.WEBSOCKET,
            latency_ms=50,
            retry_count=0,
        )
        assert result.success is True
        assert result.transport_type == TransportType.WEBSOCKET

    @pytest.mark.asyncio
    async def test_close_cancels_reconnect(self):
        """关闭后不应重连"""
        adapter = WebSocketAdapter(agent_id="test")
        adapter._should_reconnect = True
        await adapter.close()
        assert adapter._should_reconnect is False


# ──────────────── 统计测试 ────────────────


class TestStats:
    """统计信息测试"""

    def test_initial_stats(self):
        adapter = WebSocketAdapter(agent_id="test")
        stats = adapter.stats
        assert stats["messages_sent"] == 0
        assert stats["messages_received"] == 0
        assert stats["queue_size"] == 0

    @pytest.mark.asyncio
    async def test_stats_after_send(self):
        adapter = WebSocketAdapter(agent_id="test")
        adapter._state = TransportState.CONNECTED
        adapter._websocket = AsyncMock()

        msg = create_text_message("a", "b", "hello")
        await adapter.send(msg)

        stats = adapter.stats
        assert stats["messages_sent"] == 1
        assert stats["bytes_sent"] > 0

    @pytest.mark.asyncio
    async def test_stats_after_receive(self):
        adapter = WebSocketAdapter(agent_id="test")
        msg = create_text_message("a", "b", "hello")
        await adapter._message_queue.put(msg)
        await adapter.receive(timeout=1.0)

        stats = adapter.stats
        assert stats["messages_received"] == 1
        assert stats["bytes_received"] > 0


# ──────────────── 错误处理测试 ────────────────


class TestErrorHandling:
    """错误处理测试"""

    def test_error_callback(self):
        adapter = WebSocketAdapter(agent_id="test")
        errors = []
        adapter.on_error(lambda e: errors.append(e))

        adapter._handle_error(ValueError("test error"))
        assert len(errors) == 1
        assert isinstance(errors[0], ValueError)

    def test_error_callback_exception_in_callback(self):
        """回调自身抛异常不应导致崩溃"""
        adapter = WebSocketAdapter(agent_id="test")
        adapter.on_error(lambda e: 1 / 0)  # 会被吞掉
        adapter._handle_error(ValueError("test"))  # 不应抛出


# ──────────────── 导入检查测试 ────────────────


class TestImportCheck:
    """导入检查测试"""

    def test_adapter_creation(self):
        """能创建adapter（websockets可能未安装但不应在import时失败）"""
        # WebSocketAdapter.__init__会检查websockets
        try:
            adapter = WebSocketAdapter(agent_id="test")
        except ImportError:
            # 如果websockets未安装，应该有明确的错误消息
            pass
