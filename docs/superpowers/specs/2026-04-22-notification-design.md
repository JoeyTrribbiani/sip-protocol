# 通知机制设计文档

> 版本: v1.0
> 日期: 2026-04-22
> 状态: 已批准
> 关联: M3 (sip-protocol-report.md Section 8.3.2 差距5)

## 1. 问题陈述

SIP是拉取模式，Agent需要保持连接才能收到消息。长时间任务完成后，等待方Agent无法被主动通知。

## 2. 设计原则

1. **优先复用现有机制** — 复用OfflineQueue（已有），不重新发明轮子
2. **轮询优先** — Agent场景通常在localhost/NAT后，回调URL不现实
3. **Webhook作为可选高级功能** — 仅在有公网可达端点的Agent上启用
4. **同步API** — 与现有SIP项目一致

## 3. 分层实现

### Layer 1：轮询模式（基础，复用OfflineQueue）

直接复用已有的`OfflineQueue`模块：

```python
from sip_protocol.protocol.offline_queue import OfflineQueue

# 发送方：Agent A 完成任务后入队
queue = OfflineQueue(agent_id="agent-a")
queue.enqueue(
    sender_id="agent-b",
    recipient_id="agent-a",
    payload={
        "message_type": "task_result",
        "task_id": "task-xxx",
        "parts": [{"type": "text", "text": "任务完成"}],
    },
)

# 接收方：Agent A 上线后轮询投递
pending = queue.deliver_pending()
for msg in pending:
    handle(msg)
    queue.ack(msg["id"])
```

**优点**：零新增代码，OfflineQueue已有TTL、重试、ACK机制。

### Layer 2：长轮询（增强，低延迟）

```python
class NotificationManager:
    """通知管理器 — 基于长轮询的低延迟通知"""

    def __init__(self, db_path: str = "~/.openclaw/sip_notifications.db"):
        self._store: dict[str, list[Notification]] = {}
        self._waiters: dict[str, threading.Event] = {}

    def send(self, recipient_id: str, event: str, payload: dict) -> str:
        """发送通知，返回通知ID"""

    def wait_for_event(
        self,
        agent_id: str,
        timeout: float = 30.0,
        event_filter: list[str] | None = None,
    ) -> Notification | None:
        """长轮询：等待事件到达或超时

        - 有事件立即返回
        - 超时返回None
        - 支持按事件类型过滤
        """

    def poll(self, agent_id: str, limit: int = 10) -> list[Notification]:
        """短轮询：获取待处理通知（不阻塞）"""

    def ack(self, notification_id: str) -> None:
        """确认通知"""
```

**长轮询实现**：使用`threading.Event`实现非阻塞等待：

```python
def wait_for_event(self, agent_id: str, timeout: float = 30.0,
                   event_filter: list[str] | None = None) -> Notification | None:
    # 检查是否有已缓存的通知
    cached = self._get_cached(agent_id, event_filter)
    if cached:
        return cached

    # 没有则等待
    event = threading.Event()
    self._waiters[agent_id] = event

    if event.wait(timeout=timeout):
        return self._get_cached(agent_id, event_filter)
    return None  # 超时
```

### Layer 3：Webhook推送（可选，高级功能）

仅适用于有公网可达HTTP端点的Agent（如云端部署的Agent）：

```python
@dataclass
class WebhookSubscription:
    id: str                    # 订阅ID
    agent_id: str              # 订阅者Agent ID
    callback_url: str          # 回调URL
    events: list[str]          # 订阅的事件类型
    secret: str                # HMAC签名密钥


class WebhookManager:
    """Webhook推送管理器 — 可选高级功能"""

    # URL安全策略
    MAX_URL_LENGTH = 2048
    ALLOWED_SCHEMES = ("https",)  # 仅允许HTTPS
    REQUEST_TIMEOUT = 10.0         # 单次请求超时
    MAX_RETRIES = 3               # 最大重试次数
    RETRY_BACKOFF = 2.0           # 重试退避系数

    def subscribe(self, agent_id: str, callback_url: str,
                  events: list[str], secret: str) -> WebhookSubscription:
        """注册Webhook订阅"""

    def unsubscribe(self, subscription_id: str) -> None:
        """取消订阅"""

    def notify(self, event: str, payload: dict) -> list[dict]:
        """向订阅了此事件的所有Agent发送推送"""

    def verify_signature(self, payload: bytes, signature: str,
                          secret: str) -> bool:
        """验证Webhook回调签名（HMAC-SHA256）"""
```

**安全措施**：
- 仅允许HTTPS URL（`ALLOWED_SCHEMES`）
- URL长度限制2048字符
- 回调签名验证（HMAC-SHA256）
- 请求超时10秒
- 最多重试3次，指数退避
- 失败记录日志

**Secret存储**：
```python
# Secret使用Argon2id哈希后存储，不存明文
from sip_protocol.crypto.argon2 import hash_psk

hashed_secret = hash_psk(subscription.secret)
store.save(subscription.id, hashed_secret)
```

## 4. Notification 数据结构

```python
@dataclass
class Notification:
    id: str                     # UUIDv7
    sender_id: str              # 发送者Agent ID
    recipient_id: str           # 接收者Agent ID
    event: str                  # 事件类型
    payload: dict               # 事件数据（复用S1 Message Schema格式）
    created_at: float
    delivered: bool = False     # 是否已投递
    acked: bool = False         # 是否已确认
```

**事件类型枚举**：

```python
class EventType(str, Enum):
    TASK_COMPLETED = "task_completed"
    TASK_FAILED = "task_failed"
    TASK_INPUT_REQUIRED = "task_input_required"
    FILE_READY = "file_ready"
    AGENT_ONLINE = "agent_online"
    AGENT_OFFLINE = "agent_offline"
    CUSTOM = "custom"
```

## 5. 优先级建议

| 优先级 | 层次 | 状态 | 工作量 |
|--------|------|------|--------|
| P0 | Layer 1: 复用OfflineQueue | ✅ 已有 | 0 |
| P1 | Layer 2: NotificationManager长轮询 | 未实现 | 1周 |
| P2 | Layer 3: WebhookManager | 未实现 | 2周 |

## 6. 模块位置

```
python/src/sip_protocol/
├── notification/
│   ├── __init__.py
│   ├── types.py          # Notification, EventType
│   ├── manager.py        # NotificationManager (Layer 2)
│   └── webhook.py        # WebhookManager (Layer 3)
```
