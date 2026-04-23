# S1 SIP 混合 Schema 设计文档（v2）

> **状态：** 已批准
> **日期：** 2026-04-23
> **基于：** 2026-04-22-sip-message-schema-design.md v1 + 用户反馈 + MCP Gateway Registry 对齐
> **变更原因：** SIP 定位从"独立协议栈"调整为"加密层（TLS for Agent Communication）"，采用混合模式

## 定位变更

SIP 从"独立 Agent 通信协议"调整为**任何 Agent 通信协议的端到端加密层**。

- **之前：** SIP 是完整协议栈（发现 + 注册 + 认证 + 消息 + 加密）
- **现在：** SIP = 信封加密层。发现/注册/认证交给 MCP Gateway Registry 等外部系统

互补关系：
```
MCP Gateway Registry → 发现 Agent（"找到谁"）
        ↓
SIP Protocol         → 加密通道（"安全说话"）
```

## 混合模式架构

SIP 同时支持两种 payload 类型：

1. **透传模式** — payload 是任意字节（通常是 A2A JSON），SIP 不解析
2. **结构化模式** — payload 是 SIPMessage JSON，用于握手控制、错误通知等协议内消息

```
SIPEnvelope（信封层 — 极简，只管路由+加密）
├── id: str                    # 信封ID（去重/ACK用）
├── conversation_id: str       # 路由用
├── sender_id: str
├── recipient_id: str | None
├── recipient_group: str | None
├── recipient_type: str        # direct/group/broadcast
├── timestamp: str             # ISO 8601 UTC
├── schema: str                # "sip-envelope/v1"
├── content_type: str          # payload格式标识（顶层字段）
├── content_encoding: str      # identity/gzip/deflate
├── payload: bytes             # 任意字节内容
└── headers: dict              # 可扩展元数据（priority, ttl, custom）

SIPMessage（消息层 — 语义丰富，在 payload 里）
├── id: str                    # 消息ID
├── conversation_id: str
├── parent_id: str | None      # 消息关系链（回复哪条消息）
├── schema: str                # "sip-msg/v1"
├── message_type: MessageType  # 9种消息类型
├── task_id: str | None
├── sender_id: str
├── recipient_id: str | None
├── recipient_group: str | None
├── recipient_type: RecipientType
├── timestamp: str
├── parts: list[Part]          # 8种Part类型
└── metadata: dict             # priority, ttl, reply_to, custom
```

## 设计决策

### D1: parent_id 只在 SIPMessage，不在 SIPEnvelope

**理由：** parent_id 是消息语义（"回复哪条消息"），不是信封语义。A2A 消息自身有 reply_to 字段，信封不需要重复。

### D2: content_type 提升为信封顶层字段

**理由：** 加密前需要根据 content_type 决定是否压缩、是否签名。路由层也需要据此分发。藏在 headers 里每次都要解析 dict，效率低。

### D3: 新增 content_encoding 字段

**理由：** payload 可能很大，需要压缩。大于 4KB 的 payload 自动 gzip 压缩。

值域：
- `"identity"` — 无压缩（默认）
- `"gzip"` — gzip 压缩
- `"deflate"` — deflate 压缩

### D4: 信封序列化第一天用 JSON + base64

```json
{
    "id": "msg-xxx",
    "conversation_id": "conv-xxx",
    "sender_id": "agent-a",
    "recipient_id": "agent-b",
    "recipient_type": "direct",
    "timestamp": "2026-04-23T12:00:00Z",
    "schema": "sip-envelope/v1",
    "content_type": "application/a2a+json",
    "content_encoding": "identity",
    "payload": "<base64编码的字节>",
    "headers": {"priority": "normal", "ttl": 300}
}
```

**第一天 JSON，后续需要性能时再考虑 MessagePack。**

### D5: content_type 常用值

| content_type | 含义 | 使用场景 |
|---|---|---|
| `application/sip-msg+json` | SIP 结构化消息 | 协议控制、握手元数据、错误通知 |
| `application/a2a+json` | A2A 协议消息 | 透传 A2A 通信 |
| `application/octet-stream` | 任意二进制 | 文件传输、自定义协议 |
| `application/json` | 通用 JSON | 兼容场景 |

## 文件结构（更新）

```
python/src/sip_protocol/
├── exceptions.py              # P2: 异常类体系（不变）
├── schema/
│   ├── __init__.py           # 公共导出（新增 SIPEnvelope）
│   ├── types.py              # MessageType, Priority, RecipientType（不变）
│   ├── parts.py              # 8种Part类型（不变）
│   ├── envelope.py           # 新增: SIPEnvelope 数据类
│   ├── message.py            # SIPMessage 数据类（不变，schema="sip-msg/v1"）
│   └── validation.py         # 验证逻辑（不变）
python/tests/
├── test_exceptions.py         # P2: 异常测试（不变）
├── test_schema.py            # S1: Schema 测试（不变）
└── test_envelope.py           # 新增: SIPEnvelope 测试
```

## SIPEnvelope 数据类

```python
@dataclass
class SIPEnvelope:
    """SIP信封 — 加密层的最小载体"""

    id: str = field(default_factory=_generate_uuid7)
    conversation_id: str = field(default_factory=_generate_uuid7)
    sender_id: str = ""
    recipient_id: str | None = None
    recipient_group: str | None = None
    recipient_type: RecipientType = RecipientType.DIRECT
    timestamp: str = field(default_factory=_iso_now)
    schema: str = "sip-envelope/v1"
    content_type: str = "application/octet-stream"
    content_encoding: str = "identity"
    payload: bytes = b""
    headers: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]: ...
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SIPEnvelope: ...

    def to_json(self) -> bytes:
        """序列化为 JSON 字节（payload 用 base64 编码）"""
        ...
    @classmethod
    def from_json(cls, data: bytes) -> SIPEnvelope:
        """从 JSON 字节反序列化（payload 自动 base64 解码）"""
        ...
```

## 对现有 S1 设计的影响

| 模块 | 变化 |
|------|------|
| types.py | 无变化 |
| parts.py | 无变化 |
| message.py | 无变化（parent_id 保留在 SIPMessage） |
| validation.py | 无变化 |
| __init__.py | 新增 SIPEnvelope 导出 |
| envelope.py | **新增** |
| test_envelope.py | **新增** |

## 与 MCP Gateway Registry 的集成点

- S2 AgentCard — 对齐 A2A v0.3.0 标准，与 Gateway Registry 的 AgentCard 格式兼容
- S4 Agent Registry — 变为 Gateway Registry 的 thin wrapper（通过其 API 发现 Agent）
- M4 认证 — 复用 Gateway Registry 的 OAuth/Keycloak，SIP 在认证后做 Triple DH
- S3 HTTP 适配器 — 对接 Gateway 的 HTTP 端点

## 未变更的 S1 原始设计

以下内容保持 v1 设计不变：

- MessageType 枚举（9种）
- Priority 枚举（4级）
- RecipientType 枚举（3种）
- 8种 Part 类型（Text, Data, FileRef, FileData, ToolRequest, ToolResponse, Context, Stream）
- SIPMessage 完整数据类（含 parent_id, message_type, parts, task_id, metadata）
- create_message() 工厂函数
- validate_message() / validate_parts() 验证逻辑
