# Agent Registry 设计文档

> 版本: v1.0
> 日期: 2026-04-22
> 状态: 已批准
> 关联: S4 (sip-protocol-report.md Section 8.5.1)

## 1. 问题陈述

需要一个中心化的Agent注册表来存储和查询AgentCard。
本地优先实现（SQLite），架构支持未来切换到分布式KV存储。

## 2. 设计原则

1. **同步API** — 与现有SIP项目一致，使用同步函数签名，不引入asyncio
2. **本地优先** — SQLite存储，未来可扩展为分布式
3. **心跳+TTL** — Agent定期心跳续约，超时标记离线
4. **可配置** — 心跳频率、TTL、离线保留时间均可配置

## 3. 配置

```python
@dataclass
class RegistryConfig:
    """注册中心配置"""
    default_ttl: int = 300           # 默认在线TTL（秒），5分钟
    heartbeat_interval: int = 120    # 心跳间隔（秒），2分钟
    offline_ttl: int = 86400         # 离线AgentCard保留时间（秒），24小时
    db_path: str = "~/.openclaw/sip_registry.db"  # SQLite路径
    cleanup_interval: int = 3600     # 清理检查间隔（秒），1小时
```

## 4. AgentFilter

```python
@dataclass
class AgentFilter:
    """Agent查询过滤条件，所有字段可选"""
    skills: list[str] | None = None         # 按技能ID过滤（OR关系）
    tags: list[str] | None = None           # 按标签过滤（OR关系）
    capabilities: list[str] | None = None   # 按能力名过滤（OR关系）
    status: str | None = None               # "online" | "offline" | "all"
```

## 5. AgentRegistry

```python
@dataclass
class AgentRegistration:
    """注册记录（内部状态）"""
    agent_name: str
    card: AgentCard
    status: str                    # "online" | "offline"
    registered_at: float           # 首次注册时间戳
    last_heartbeat: float          # 最后心跳时间戳
    expires_at: float              # 在线过期时间戳
    offline_since: float | None    # 离线时间戳


class AgentRegistry:
    """Agent注册中心 — 同步API"""

    def __init__(self, config: RegistryConfig | None = None):
        self._config = config or RegistryConfig()
        self._store: dict[str, AgentRegistration] = {}  # 内存存储
        self._init_db()

    # === 注册/注销 ===

    def register(self, card: AgentCard) -> str:
        """注册Agent，返回registration_id（UUIDv7）"""

    def deregister(self, agent_name: str) -> bool:
        """注销Agent，返回是否成功"""

    # === 查询 ===

    def get(self, agent_name: str) -> AgentCard | None:
        """查询指定Agent的AgentCard（含离线）"""

    def list_all(self) -> list[AgentCard]:
        """列出所有AgentCard（含离线）"""

    def query(self, filter: AgentFilter) -> list[AgentCard]:
        """按过滤条件查询AgentCard"""

    def list_online(self) -> list[AgentCard]:
        """仅列出在线Agent"""

    # === 心跳 ===

    def heartbeat(self, agent_name: str) -> bool:
        """心跳续约，返回是否成功（Agent必须已注册）"""

    def check_health(self) -> list[str]:
        """检查所有Agent健康状态，返回不健康的Agent名列表"""

    # === 维护 ===

    def cleanup(self) -> int:
        """清理过期Agent，返回清理数量（过期在线 + 超期离线）"""
```

## 6. SQLite存储

使用与现有MessageStore一致的SQLite存储：

```sql
CREATE TABLE IF NOT EXISTS agents (
    agent_name TEXT PRIMARY KEY,
    card_json TEXT NOT NULL,           -- AgentCard JSON
    status TEXT NOT NULL DEFAULT 'online',
    registered_at REAL NOT NULL,
    last_heartbeat REAL NOT NULL,
    expires_at REAL NOT NULL,
    offline_since REAL
);

CREATE INDEX IF NOT EXISTS idx_agents_status ON agents(status);
CREATE INDEX IF NOT EXISTS idx_agents_expires ON agents(expires_at);
```

## 7. 心跳与生命周期

```
时间线:
  t=0     注册 Agent（status=online, expires_at=now+TTL）
  t=120   心跳续约（expires_at=now+TTL）
  t=240   心跳续约
  t=360   心跳续约
  t=500   未心跳（超过TTL=300秒）
  t=500   check_health() → 标记为offline, offline_since=now
  ...
  t=500+86400  cleanup() → 删除AgentCard（超过offline_ttl）
```

## 8. 模块位置

```
python/src/sip_protocol/
├── discovery/
│   ├── __init__.py
│   ├── registry.py        # AgentRegistry, AgentRegistration
│   └── registry_store.py  # SQLite存储层
```
