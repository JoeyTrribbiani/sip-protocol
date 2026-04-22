"""
WebSocket传输适配器模块
实现基于WebSocket的Agent消息传输

功能特性：
1. 支持ws://和wss://协议
2. 自动重连机制
3. 心跳保活
4. 消息压缩（可选）
5. 优雅关闭

使用方式：
    adapter = WebSocketAdapter(agent_id="agent:hermes")
    await adapter.connect("ws://localhost:8765")
    await adapter.send(message)
    msg = await adapter.receive()
    await adapter.close()
"""

import asyncio
import time
from typing import Any, Callable, Dict, List, Optional
from dataclasses import dataclass

from .base import (
    TransportAdapter,
    TransportType,
    TransportState,
    TransportConfig,
    ConnectionResult,
    SendResult,
    ReceiveResult,
)
from .message import AgentMessage, parse_raw_message

try:
    import websockets
    from websockets.exceptions import (
        ConnectionClosed,
        ConnectionClosedError,
        ConnectionClosedOK,
    )
except ImportError:
    websockets = None  # type: ignore


# ──────────────── 数据类 ────────────────


@dataclass
class WebSocketConfig(TransportConfig):
    """WebSocket特定配置"""

    # 最大消息大小 (字节)
    max_message_size: int = 10 * 1024 * 1024  # 10MB
    # Ping间隔 (秒)
    ping_interval: float = 20.0
    # Ping超时 (秒)
    ping_timeout: float = 20.0
    # 子协议列表
    subprotocols: Optional[List[str]] = None
    # 额外的请求头
    extra_headers: Optional[Dict[str, str]] = None
    # 启用自动压缩
    compression: Optional[str] = "deflate"  # None, "deflate", "gzip"


# ──────────────── WebSocket适配器 ────────────────


class WebSocketAdapter(TransportAdapter):
    """
    WebSocket传输适配器

    实现WebSocket协议的Agent消息传输，支持：
    - 自动重连
    - 心跳保活
    - 消息压缩
    - 优雅关闭
    """

    def __init__(
        self,
        agent_id: str,
        config: Optional[WebSocketConfig] = None,
    ):
        """
        初始化WebSocket适配器

        Args:
            agent_id: Agent ID
            config: WebSocket配置
        """
        if websockets is None:
            raise ImportError("websockets库未安装，请运行: pip install websockets")

        self.agent_id = agent_id
        self.config = config or WebSocketConfig()

        # 连接状态
        self._state = TransportState.DISCONNECTED
        self._websocket: Optional["websockets.WebSocketClientProtocol"] = None
        self._endpoint: Optional[str] = None
        self._connect_task: Optional[asyncio.Task] = None
        self._receive_task: Optional[asyncio.Task] = None
        self._heartbeat_task: Optional[asyncio.Task] = None

        # 重连状态
        self._reconnect_count: int = 0
        self._should_reconnect: bool = False

        # 消息队列
        self._message_queue: asyncio.Queue[AgentMessage] = asyncio.Queue()
        self._pending_responses: Dict[str, asyncio.Future] = {}

        # 统计
        self._stats = {
            "messages_sent": 0,
            "messages_received": 0,
            "bytes_sent": 0,
            "bytes_received": 0,
            "reconnect_count": 0,
            "connected_at": None,
            "last_heartbeat_at": None,
        }

        # 回调
        self._on_message_callback: Optional[Callable[[AgentMessage], None]] = None
        self._on_connect_callback: Optional[Callable[[], None]] = None
        self._on_disconnect_callback: Optional[Callable[[Optional[str]], None]] = None
        self._on_error_callback: Optional[Callable[[Exception], None]] = None
        self._on_state_change_callback: Optional[
            Callable[[TransportState, TransportState], None]
        ] = None

    # ──────────────── 属性 ────────────────

    @property
    def transport_type(self) -> TransportType:
        """获取传输类型"""
        return TransportType.WEBSOCKET

    @property
    def state(self) -> TransportState:
        """获取当前状态"""
        return self._state

    @property
    def is_connected(self) -> bool:
        """是否已连接"""
        return self._state == TransportState.CONNECTED and self._websocket is not None

    @property
    def remote_endpoint(self) -> Optional[str]:
        """获取远程端点地址"""
        return self._endpoint

    @property
    def stats(self) -> Dict[str, Any]:
        """获取统计信息"""
        return {
            **self._stats,
            "state": self._state.value,
            "endpoint": self._endpoint,
            "queue_size": self._message_queue.qsize(),
        }

    # ──────────────── 状态管理 ────────────────

    def _set_state(self, new_state: TransportState) -> None:
        """更新状态并触发回调"""
        if self._state == new_state:
            return

        old_state = self._state
        self._state = new_state

        if self._on_state_change_callback:
            try:
                self._on_state_change_callback(old_state, new_state)
            except Exception as e:  # pylint: disable=broad-exception-caught
                if self._on_error_callback:
                    self._on_error_callback(e)

    # ──────────────── 生命周期 ────────────────

    async def connect(
        self,
        endpoint: str,
        timeout: Optional[int] = None,
    ) -> ConnectionResult:
        """
        建立WebSocket连接

        Args:
            endpoint: WebSocket URL (ws://或wss://)
            timeout: 连接超时时间（秒）

        Returns:
            ConnectionResult: 连接结果
        """
        connect_timeout = timeout or self.config.connect_timeout
        start_time = time.time()

        self._endpoint = endpoint
        self._should_reconnect = True
        self._reconnect_count = 0

        return await self._connect_with_retry(connect_timeout, start_time)

    async def _connect_with_retry(
        self,
        timeout: int,
        start_time: float,
    ) -> ConnectionResult:
        """带重试的连接实现"""
        max_retries = self.config.max_reconnect

        while True:
            try:
                self._set_state(TransportState.CONNECTING)

                # 构建连接参数
                connect_kwargs: Dict[str, Any] = {
                    "close_timeout": 1.0,
                }

                # 添加压缩配置
                if self.config.compression:
                    connect_kwargs["compression"] = self.config.compression

                # 添加子协议
                if self.config.subprotocols:
                    connect_kwargs["subprotocols"] = self.config.subprotocols

                # 添加额外请求头
                if self.config.extra_headers:
                    connect_kwargs["extra_headers"] = self.config.extra_headers

                # 建立连接
                assert websockets is not None
                self._websocket = await asyncio.wait_for(
                    websockets.connect(
                        self._endpoint,
                        **connect_kwargs,
                    ),
                    timeout=timeout,
                )

                latency_ms = int((time.time() - start_time) * 1000)
                self._set_state(TransportState.CONNECTED)
                self._stats["connected_at"] = time.time()  # type: ignore[assignment]

                # 启动接收任务
                self._receive_task = asyncio.create_task(self._receive_loop())
                # 启动心跳任务
                self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())

                # 触发连接回调
                if self._on_connect_callback:
                    try:
                        self._on_connect_callback()
                    except Exception as e:  # pylint: disable=broad-exception-caught
                        if self._on_error_callback:
                            self._on_error_callback(e)

                return ConnectionResult(
                    success=True,
                    transport_type=TransportType.WEBSOCKET,
                    latency_ms=latency_ms,
                    retry_count=self._reconnect_count,
                )

            except asyncio.TimeoutError:
                error = f"连接超时: {self._endpoint}"
            except (ConnectionError, OSError, ValueError, RuntimeError) as e:
                error = str(e)

            # 重连逻辑
            if not self._should_reconnect:
                break

            if (  # pylint: disable=chained-comparison
                max_retries >= 0 and self._reconnect_count >= max_retries
            ):
                break

            self._reconnect_count += 1
            self._set_state(TransportState.RECONNECTING)
            self._stats["reconnect_count"] = self._reconnect_count

            # 等待后重试
            delay = self.config.reconnect_delay * (2 ** min(self._reconnect_count - 1, 5))
            await asyncio.sleep(delay)

        # 连接失败
        self._set_state(TransportState.ERROR)
        return ConnectionResult(
            success=False,
            transport_type=TransportType.WEBSOCKET,
            error=error,
            retry_count=self._reconnect_count,
        )

    async def close(self) -> None:
        """关闭WebSocket连接"""
        self._should_reconnect = False

        # 取消任务
        if self._receive_task:
            self._receive_task.cancel()
            self._receive_task = None

        if self._heartbeat_task:
            self._heartbeat_task.cancel()
            self._heartbeat_task = None

        # 关闭WebSocket
        if self._websocket:
            try:
                await self._websocket.close()
            except (ConnectionError, OSError):
                pass
            self._websocket = None

        # 触发断开回调
        if self._on_disconnect_callback:
            try:
                self._on_disconnect_callback(None)
            except Exception:  # pylint: disable=broad-exception-caught
                pass

        self._set_state(TransportState.CLOSED)

        # 清理pending响应
        for future in self._pending_responses.values():
            if not future.done():
                future.set_exception(ConnectionError("连接已关闭"))
        self._pending_responses.clear()

    # ──────────────── 消息收发 ────────────────

    async def send(self, message: AgentMessage, timeout: Optional[int] = None) -> SendResult:
        """
        发送消息

        Args:
            message: 要发送的消息
            timeout: 发送超时时间（秒）

        Returns:
            SendResult: 发送结果
        """
        if not self.is_connected or self._websocket is None:
            return SendResult(
                success=False,
                message_id=message.id,
                error="未连接",
            )

        send_timeout = timeout or self.config.send_timeout
        message_json = message.to_json()
        bytes_sent = len(message_json.encode("utf-8"))

        try:
            await asyncio.wait_for(
                self._websocket.send(message_json),
                timeout=send_timeout,
            )

            self._stats["messages_sent"] = int(self._stats.get("messages_sent", 0)) + 1
            self._stats["bytes_sent"] = int(self._stats.get("bytes_sent", 0)) + bytes_sent

            return SendResult(
                success=True,
                message_id=message.id,
                bytes_sent=bytes_sent,
            )

        except asyncio.TimeoutError:
            error = "发送超时"
            self._handle_error(ConnectionError(error))
        except (ConnectionError, OSError, RuntimeError) as e:
            error = str(e)
            self._handle_error(e)

        return SendResult(
            success=False,
            message_id=message.id,
            error=error,
        )

    async def receive(self, timeout: Optional[int] = None) -> ReceiveResult:
        """
        接收消息（从队列中获取）

        Args:
            timeout: 超时时间（秒），None表示无限等待

        Returns:
            ReceiveResult: 接收结果
        """
        try:
            if timeout is None:
                message = await self._message_queue.get()
            else:
                message = await asyncio.wait_for(
                    self._message_queue.get(),
                    timeout=timeout,
                )

            bytes_received = len(message.to_json().encode("utf-8"))
            self._stats["messages_received"] = int(self._stats.get("messages_received", 0)) + 1
            self._stats["bytes_received"] = (
                int(self._stats.get("bytes_received", 0)) + bytes_received
            )

            return ReceiveResult(
                success=True,
                message=message,
                bytes_received=bytes_received,
            )

        except asyncio.TimeoutError:
            return ReceiveResult(
                success=False,
                error="接收超时",
            )
        except asyncio.CancelledError:
            return ReceiveResult(
                success=False,
                error="接收已取消",
            )

    async def send_receive(
        self,
        message: AgentMessage,
        timeout: Optional[int] = None,
    ) -> ReceiveResult:
        """
        发送并等待响应（请求-响应模式）

        使用correlation_id匹配响应。

        Args:
            message: 要发送的消息
            timeout: 超时时间（秒）

        Returns:
            ReceiveResult: 响应结果
        """
        if not message.correlation_id:
            # 自动分配correlation_id
            message.correlation_id = message.id

        # 创建Future等待响应
        response_future: asyncio.Future = asyncio.Future()
        self._pending_responses[message.correlation_id] = response_future

        try:
            # 发送消息
            send_result = await self.send(message, timeout)
            if not send_result.success:
                return ReceiveResult(
                    success=False,
                    error=f"发送失败: {send_result.error}",
                )

            # 等待响应
            if timeout is None:
                response_msg = await response_future
            else:
                response_msg = await asyncio.wait_for(response_future, timeout=timeout)

            return ReceiveResult(
                success=True,
                message=response_msg,
            )

        except asyncio.TimeoutError:
            return ReceiveResult(
                success=False,
                error="等待响应超时",
            )
        except (RuntimeError, ValueError, ConnectionError) as e:
            return ReceiveResult(
                success=False,
                error=str(e),
            )
        finally:
            self._pending_responses.pop(message.correlation_id, None)

    # ──────────────── 内部循环 ────────────────

    async def _receive_loop(self) -> None:
        """接收消息循环"""
        while self.is_connected and self._websocket is not None:
            try:
                raw_message = await asyncio.wait_for(
                    self._websocket.recv(),
                    timeout=self.config.receive_timeout,
                )

                # 解析消息
                try:
                    message = parse_raw_message(raw_message)
                except (ValueError, KeyError) as e:
                    self._handle_error(ValueError(f"消息解析失败: {e}"))
                    continue

                # 检查是否是响应消息
                if message.correlation_id and message.correlation_id in self._pending_responses:
                    future = self._pending_responses.pop(message.correlation_id)
                    if not future.done():
                        future.set_result(message)
                else:
                    # 普通消息放入队列
                    await self._message_queue.put(message)

                    # 触发消息回调
                    if self._on_message_callback:
                        try:
                            self._on_message_callback(message)
                        except Exception as e:  # pylint: disable=broad-exception-caught
                            self._handle_error(e)

            except asyncio.TimeoutError:
                # 接收超时，继续循环
                continue
            except ConnectionClosedOK:
                # 正常关闭
                break
            except ConnectionClosedError as e:
                self._handle_error(e)
                break
            except (ConnectionError, OSError) as e:
                self._handle_error(e)
                break

        # 如果是断开连接且需要重连
        if self._should_reconnect and self._endpoint:
            self._set_state(TransportState.RECONNECTING)
            asyncio.create_task(
                self._connect_with_retry(
                    self.config.connect_timeout,
                    time.time(),
                )
            )

    async def _heartbeat_loop(self) -> None:
        """心跳保活循环"""
        while self.is_connected:
            try:
                await asyncio.sleep(self.config.heartbeat_interval)

                if self._websocket is not None:
                    await self._websocket.ping()
                    self._stats["last_heartbeat_at"] = time.time()  # type: ignore[assignment]

            except (ConnectionError, OSError) as e:
                self._handle_error(e)
                break

    # ──────────────── 错误处理 ────────────────

    def _handle_error(self, error: Exception) -> None:
        """处理错误"""
        if self._on_error_callback:
            try:
                self._on_error_callback(error)
            except Exception:  # pylint: disable=broad-exception-caught
                pass

        # 如果是连接错误，触发断开回调
        if isinstance(error, ConnectionClosed):
            self._set_state(TransportState.DISCONNECTED)
            if self._on_disconnect_callback:
                try:
                    self._on_disconnect_callback(str(error))
                except Exception:  # pylint: disable=broad-exception-caught
                    pass
        else:
            self._set_state(TransportState.ERROR)

    # ──────────────── 回调注册 ────────────────

    def on_message(self, callback: Callable[[AgentMessage], None]) -> None:
        """注册消息接收回调"""
        self._on_message_callback = callback

    def on_connect(self, callback: Callable[[], None]) -> None:
        """注册连接成功回调"""
        self._on_connect_callback = callback

    def on_disconnect(self, callback: Callable[[Optional[str]], None]) -> None:
        """注册断开连接回调"""
        self._on_disconnect_callback = callback

    def on_error(self, callback: Callable[[Exception], None]) -> None:
        """注册错误回调"""
        self._on_error_callback = callback

    def on_state_change(
        self,
        callback: Callable[[TransportState, TransportState], None],
    ) -> None:
        """注册状态变更回调"""
        self._on_state_change_callback = callback
