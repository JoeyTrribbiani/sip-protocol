# S2 AgentCard + S4 AgentRegistry 实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 实现 AgentCard 数据结构（S2）和 AgentRegistry 注册中心（S4），支持能力发现、心跳续约、在线状态管理。

**Architecture:** S2 是纯数据结构层，S4 是注册/查询/心跳服务层。先实现 S2（被 S4 依赖），再实现 S4。

**Tech Stack:** Python 3.11+, stdlib dataclasses + enum, sqlite3

**设计文档:**
- S2: `docs/superpowers/specs/2026-04-22-agent-card-design.md`
- S4: `docs/superpowers/specs/2026-04-22-agent-registry-design.md`

**关键约束:**
- 纯同步 API，无 async/await
- 纯 stdlib dataclasses + enum，无 pydantic
- Pylint max-args=7
- 注释/文档中文，标识符英文
- 现有 582 测试必须零回归

---

## 文件结构

```
python/src/sip_protocol/
├── discovery/
│   ├── __init__.py                # 导出公开 API
│   ├── agent_card.py             # S2: AgentCard, Capabilities, Skill, AuthScheme, Endpoints
│   ├── registry.py               # S4: AgentRegistry, AgentRegistration, AgentFilter, RegistryConfig
│   └── registry_store.py        # S4: SQLite 存储层
└── tests/
    ├── test_agent_card.py       # S2: AgentCard 序列化/反序列化
    ├── test_registry.py         # S4: 注册/查询/心跳/清理
    └── test_registry_store.py    # S4: SQLite 存储层
```

---

### Task 1: S2 — AgentCard 数据结构

**Files:**
- Create: `src/sip_protocol/discovery/__init__.py`
- Create: `src/sip_protocol/discovery/agent_card.py`
- Create: `tests/test_agent_card.py`

- [ ] **Step 1: 创建 discovery 包**

创建 `discovery/__init__.py`，空文件。

- [ ] **Step 2: 实现 Capabilities, Skill, AuthScheme, Endpoints**

在 `agent_card.py` 中按设计文档实现 4 个 dataclass：

```python
@dataclass(frozen=True)
class Capabilities:
    """Agent能力声明"""
    streaming: bool = False
    push_notifications: bool = False
    task_management: bool = False
    file_transfer: bool = False
    group_communication: bool = False
    max_message_size: int = 1048576
    supported_schemas: list[str] = field(default_factory=lambda: ["sip-msg/v1"])

@dataclass
class Skill:
    """Agent技能"""
    id: str
    name: str
    description: str
    input_schema: dict | None = None
    output_schema: dict | None = None
    tags: list[str] = field(default_factory=list)

@dataclass(frozen=True)
class AuthScheme:
    """认证方案声明（不含凭证）"""
    type: str
    description: str = ""

@dataclass(frozen=True)
class Endpoints:
    """多端点配置"""
    primary: str
    streaming: str | None = None
    file_transfer: str | None = None
    health: str | None = None
```

每个 dataclass 实现 `to_dict()` 和 `from_dict()` 类方法。使用 `frozen=True` 保证不可变。

- [ ] **Step 3: 实现 AgentCard**

按设计文档实现 `AgentCard` dataclass（不冻结，因为 `metadata` 需要可变）：

```python
@dataclass
class AgentCard:
    name: str
    description: str
    version: str
    url: str
    capabilities: Capabilities
    authentication: list[AuthScheme]
    skills: list[Skill]
    endpoints: Endpoints
    metadata: dict[str, Any] = field(default_factory=dict)
```

`to_dict()` 将嵌套的 dataclass 展开为 dict。`from_dict()` 从 dict 递归重建。

- [ ] **Step 4: 写 AgentCard 测试**

```python
"""AgentCard 数据结构测试"""
```

测试覆盖：
- to_dict / from_dict 往返
- frozen dataclass 不可变
- 默认值正确
- 缺少必填字段时 from_dict 抛 KeyError
- 完整字段 round-trip

- [ ] **Step 5: 运行全量测试**

```bash
pytest tests/ -q
```

预期：582 passed

- [ ] **Step 6: 提交**

```bash
git add src/sip_protocol/discovery/ tests/test_agent_card.py
git commit -m "feat(S2): AgentCard数据结构 + 序列化"
```

---

### Task 2: S4 — AgentRegistry 核心逻辑

**Files:**
- Create: `src/sip_protocol/discovery/registry.py`
- Create: `tests/test_registry.py`

- [ ] **Step 1: 实现 RegistryConfig 和 AgentFilter**

```python
@dataclass
class RegistryConfig:
    """注册中心配置"""
    default_ttl: int = 300
    heartbeat_interval: int = 120
    offline_ttl: int = 86400
    db_path: str = "~/.openclaw/sip_registry.db"
    cleanup_interval: int = 3600

@dataclass
class AgentFilter:
    """Agent查询过滤条件"""
    skills: list[str] | None = None
    tags: list[str] | None = None
    capabilities: list[str] | None = None
    status: str | None = None
```

- [ ] **Step 2: 实现 AgentRegistration**

```python
@dataclass
class AgentRegistration:
    """注册记录"""
    agent_name: str
    card: AgentCard
    status: str
    registered_at: float
    last_heartbeat: float
    expires_at: float
    offline_since: float | None = None
```

- [ ] **Step 3: 实现 AgentRegistry 内存版本**

先实现内存存储（dict），后续 Task 3 加 SQLite。

核心方法：
- `register(card)` → 生成 registration_id（UUID7），存入 `_store`
- `deregister(agent_name)` → 从 `_store` 删除
- `get(agent_name)` → 返回 AgentCard 或 None
- `list_all()` → 返回所有 AgentCard
- `query(filter)` → 按条件过滤
- `list_online()` → status=="online"
- `heartbeat(agent_name)` → 更新 expires_at，返回 bool
- `check_health()` → 检查过期，标记 offline
- `cleanup()` → 清理过期离线记录

注意：`register` 中 `agent_name` 取 `card.name` 作为唯一键。

- [ ] **Step 4: 写 AgentRegistry 测试**

测试覆盖：
- 注册/注销/重复注册
- get/list_all/query/list_online
- 心跳续约
- 过期自动标记 offline
- cleanup 清理过期记录
- 边界：未注册 Agent 心跳/注销失败

- [ ] **Step 5: 运行全量测试 + 提交**

```bash
pytest tests/ -q
git add src/sip_protocol/discovery/registry.py tests/test_registry.py
git commit -m "feat(S4): AgentRegistry内存版本 + 心跳生命周期"
```

---

### Task 3: S4 — SQLite 存储层

**Files:**
- Create: `src/sip_protocol/discovery/registry_store.py`
- Create: `tests/test_registry_store.py`

- [ ] **Step 1: 实现 RegistryStore**

设计文档的 SQLite schema：

```sql
CREATE TABLE IF NOT EXISTS agents (
    agent_name TEXT PRIMARY KEY,
    card_json TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'online',
    registered_at REAL NOT NULL,
    last_heartbeat REAL NOT NULL,
    expires_at REAL NOT NULL,
    offline_since REAL
);
CREATE INDEX IF NOT EXISTS idx_agents_status ON agents(status);
CREATE INDEX IF NOT EXISTS idx_agents_expires ON agents(expires_at);
```

方法：
- `_init_db()` → 建表
- `save(registration)` → INSERT OR REPLACE
- `load(agent_name)` → 查询返回 AgentRegistration
- `delete(agent_name)` → DELETE
- `list_all()` → SELECT * 返回 list
- `update_status(agent_name, status, ...)` → UPDATE
- `find_expired()` → SELECT WHERE expires_at < now AND status='online'
- `find_offline_expired()` → SELECT WHERE offline_since IS NOT NULL AND (now - offline_since) > offline_ttl

- [ ] **Step 2: 集成 RegistryStore 到 AgentRegistry**

修改 `registry.py`：
- `__init__` 中初始化 `RegistryStore`
- `register` → 同时写内存和 SQLite
- `deregister` → 同时删内存和 SQLite
- `load` → 启动时从 SQLite 加载到内存
- `heartbeat` → 同时更新内存和 SQLite
- `check_health` / `cleanup` → 查 SQLite 后同步内存状态

- [ ] **Step 3: 写 RegistryStore 测试**

测试覆盖：
- 建表正确性（表结构、索引）
- save/load/delete 往返
- update_status
- find_expired / find_offline_expired

- [ ] **Step 4: 更新 __init__.py 导出**

```python
from .agent_card import AgentCard, Capabilities, Skill, AuthScheme, Endpoints
from .registry import AgentRegistry, AgentFilter, RegistryConfig
```

- [ ] **Step 5: 运行全量测试 + 提交**

```bash
pytest tests/ -q
git add src/sip_protocol/discovery/ tests/test_registry_store.py
git commit -m "feat(S4): SQLite存储层 + 内存/持久化双写"
```

---

### Task 4: Lint + 类型检查 + CHANGELOG

- [ ] **Step 1: Black 格式化**

```bash
black src/sip_protocol/discovery/
```

- [ ] **Step 2: Pylint 检查**

```bash
pylint src/sip_protocol/discovery/
```

预期：10.00/10

- [ ] **Step 3: MyPy 检查**

```bash
mypy src/sip_protocol/discovery/
```

- [ ] **Step 4: 运行全量测试**

```bash
pytest tests/ -q
```

- [ ] **Step 5: 更新 CHANGELOG**

在 `[Unreleased]` 下追加：

```markdown
#### 能力发现（S2 + S4）
- **AgentCard** — 自描述数据结构（Capabilities, Skill, AuthScheme, Endpoints），frozen dataclass + 序列化往返
- **AgentRegistry** — 注册/注销/查询/心跳续约，内存+SQLite 双写
- **AgentFilter** — 按技能/标签/能力/状态过滤查询
```

- [ ] **Step 6: 提交**

```bash
git add CHANGELOG.md
git commit -m "docs: 更新CHANGELOG记录S2+S4能力发现模块"
```
