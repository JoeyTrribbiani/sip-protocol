"""
传输层抽象接口模块
定义所有传输适配器的统一接口

设计原则：
1. 统一接口：所有传输方式实现相同的API
2. 可扩展：新的传输方式只需实现抽象基类
3. 可测试：接口抽象便于mock和单元测试
4. 类型安全：使用Protocol和类型注解
"""

from abc import ABC, abstractmethod
from enum import Enum
from typing import Any, Callable, Dict, Optional
from dataclasses import dataclass

from .message import AgentMessage

# ──────────────── 枚举 ────────────────


class TransportType(str, Enum):
    """传输类型枚举"""

    OPENCRAW = "openclaw"
    WEBSOCKET = "websocket"
    HTTP = "http"
    GRPC = "grpc"
    QUIC = "quic"


class TransportState(str, Enum):
    """传输层状态"""

    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    RECONNECTING = "reconnecting"
    ERROR = "error"
    CLOSED = "closed"


# ──────────────── 数据类 ────────────────


@dataclass
class TransportConfig:
    """传输配置基类"""

    # 连接超时 (秒)
    connect_timeout: int = 30
    # 发送超时 (秒)
    send_timeout: int = 10
    # 接收超时 (秒)
    receive_timeout: int = 30
    # 心跳间隔 (秒)
    heartbeat_interval: int = 30
    # 最大重连次数 (0=不重连, -1=无限)
    max_reconnect: int = 5
    # 重连延迟 (秒)
    reconnect_delay: float = 1.0
    # 启用压缩
    enable_compression: bool = False
    # 启用加密 (传输层加密，非应用层SIP)
    enable_tls: bool = False


@dataclass
class ConnectionResult:
    """连接结果"""

    success: bool
    transport_type: TransportType
    error: Optional[str] = None
    latency_ms: int = 0
    retry_count: int = 0


@dataclass
class SendResult:
    """发送结果"""

    success: bool
    message_id: str
    error: Optional[str] = None
    bytes_sent: int = 0


@dataclass
class ReceiveResult:
    """接收结果"""

    success: bool
    message: Optional[AgentMessage] = None
    error: Optional[str] = None
    bytes_received: int = 0


# ──────────────── 抽象基类 ────────────────


class TransportAdapter(ABC):
    """
    传输适配器抽象基类

    所有传输实现（OpenClaw、WebSocket、HTTP等）都必须实现此接口。

    生命周期：
    1. 创建适配器
    2. connect() - 建立连接
    3. send() / receive() - 收发消息
    4. close() - 关闭连接
    """

    # ──────────────── 属性 ────────────────

    @property
    @abstractmethod
    def transport_type(self) -> TransportType:
        """获取传输类型"""

    @property
    @abstractmethod
    def state(self) -> TransportState:
        """获取当前状态"""

    @property
    @abstractmethod
    def is_connected(self) -> bool:
        """是否已连接"""

    @property
    @abstractmethod
    def remote_endpoint(self) -> Optional[str]:
        """获取远程端点地址"""

    @property
    @abstractmethod
    def stats(self) -> Dict[str, Any]:
        """获取统计信息"""

    # ──────────────── 生命周期 ────────────────

    @abstractmethod
    async def connect(
        self,
        endpoint: str,
        timeout: Optional[int] = None,
    ) -> ConnectionResult:
        """
        建立连接

        Args:
            endpoint: 远程端点 (URL、地址等)
            timeout: 超时时间（秒），None使用默认值

        Returns:
            ConnectionResult: 连接结果
        """

    @abstractmethod
    async def close(self) -> None:
        """关闭连接，释放资源"""

    async def __aenter__(self) -> "TransportAdapter":
        """异步上下文管理器入口"""
        await self.connect()  # pylint: disable=no-value-for-parameter
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """异步上下文管理器退出"""
        await self.close()

    # ──────────────── 消息收发 ────────────────

    @abstractmethod
    async def send(self, message: AgentMessage, timeout: Optional[int] = None) -> SendResult:
        """
        发送消息

        Args:
            message: 要发送的消息
            timeout: 超时时间（秒），None使用默认值

        Returns:
            SendResult: 发送结果
        """

    @abstractmethod
    async def receive(self, timeout: Optional[int] = None) -> ReceiveResult:
        """
        接收消息（阻塞等待）

        Args:
            timeout: 超时时间（秒），None表示无限等待

        Returns:
            ReceiveResult: 接收结果
        """

    @abstractmethod
    async def send_receive(
        self,
        message: AgentMessage,
        timeout: Optional[int] = None,
    ) -> ReceiveResult:
        """
        发送并等待响应（请求-响应模式）

        Args:
            message: 要发送的消息
            timeout: 超时时间（秒）

        Returns:
            ReceiveResult: 响应结果
        """

    # ──────────────── 回调注册 ────────────────

    @abstractmethod
    def on_message(self, callback: Callable[[AgentMessage], None]) -> None:
        """
        注册消息接收回调

        Args:
            callback: 接收到消息时调用的函数
        """

    @abstractmethod
    def on_connect(self, callback: Callable[[], None]) -> None:
        """
        注册连接成功回调

        Args:
            callback: 连接成功时调用的函数
        """

    @abstractmethod
    def on_disconnect(self, callback: Callable[[Optional[str]], None]) -> None:
        """
        注册断开连接回调

        Args:
            callback: 断开连接时调用的函数，参数为错误信息
        """

    @abstractmethod
    def on_error(self, callback: Callable[[Exception], None]) -> None:
        """
        注册错误回调

        Args:
            callback: 发生错误时调用的函数
        """

    @abstractmethod
    def on_state_change(
        self,
        callback: Callable[[TransportState, TransportState], None],
    ) -> None:
        """
        注册状态变更回调

        Args:
            callback: 状态变更时调用的函数，参数为 (old_state, new_state)
        """

    # ──────────────── 辅助方法 ────────────────

    def _set_state(self, new_state: TransportState) -> None:
        """更新状态并触发回调（子类应覆盖此方法以调用回调）"""


# ──────────────── 工厂函数 ────────────────


def create_transport(
    transport_type: TransportType,
    config: Optional[TransportConfig] = None,
    **kwargs: Any,
) -> TransportAdapter:
    """
    工厂函数：创建传输适配器

    Args:
        transport_type: 传输类型
        config: 传输配置
        **kwargs: 适配器特定参数

    Returns:
        TransportAdapter: 传输适配器实例

    Raises:
        ValueError: 不支持的传输类型
    """
    # 延迟导入避免循环依赖  # pylint: disable=import-outside-toplevel
    from .openclaw_adapter import OpenClawAdapter  # pylint: disable=import-outside-toplevel
    from .websocket_adapter import WebSocketAdapter  # pylint: disable=import-outside-toplevel

    adapter_map: Dict[TransportType, type] = {
        TransportType.OPENCRAW: OpenClawAdapter,
        TransportType.WEBSOCKET: WebSocketAdapter,
    }

    adapter_class = adapter_map.get(transport_type)
    if not adapter_class:
        raise ValueError(f"不支持的传输类型: {transport_type}")

    # WebSocketAdapter需要agent_id作为第一个参数
    if transport_type == TransportType.WEBSOCKET:
        agent_id = kwargs.pop("agent_id", "default-agent")
        return adapter_class(agent_id=agent_id, config=config, **kwargs)

    return adapter_class(config=config, **kwargs)
