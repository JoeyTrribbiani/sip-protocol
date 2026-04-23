# SIP Message Schema 设计文档

> 版本: v1.0
> 日期: 2026-04-22
> 状态: 已批准
> 关联: S1 (sip-protocol-report.md Section 8.3.1)

## 1. 问题陈述

当前SIP消息是原始加密字节流，Agent无法表达结构化任务、上下文、工具调用。需要定义一个标准的Application Layer消息格式，在SIP加密层之上承载Agent通信语义。

## 2. 设计原则

1. **加密层透明** — Application Payload在加密层之上，解密后再解析，不污染加密层
2. **A2A对齐** — Part模型参考A2A协议的TextPart/FilePart/DataPart，为后续兼容铺路
3. **向后兼容** — 无`schema`字段的旧消息按原始字节处理，不破坏现有通信
4. **强类型** — 所有关键字段使用枚举，第一天就是enum，不使用裸字符串
5. **多模态** — `parts`数组支持混合内容类型

## 3. 消息结构

### 3.1 完整消息格式

```json
{
  "id": "msg-0194a2b3-7f1a-7b2e-8c3d-4e5f6a7b8c9d",
  "conversation_id": "conv-0194a2b3-0000-7b2e-8c3d-000000000000",
  "parent_id": "msg-0194a2b3-0000-7b2e-8c3d-000000000001",
  "schema": "sip-msg/v1",
  "message_type": "task_delegate",
  "task_id": "task-0194a2b3-0000-7b2e-8c3d-000000000002",
  "sender_id": "agent-openclaw",
  "recipient_id": "agent-hermes",
  "recipient_group": null,
  "recipient_type": "direct",
  "timestamp": "2026-04-22T12:00:00Z",
  "parts": [
    {"type": "text", "text": "请分析Q1销售数据"}
  ],
  "metadata": {
    "priority": "high",
    "ttl": 3600,
    "reply_to": "msg-0194a2b3-0000-7b2e-8c3d-000000000003",
    "custom": {}
  }
}
```

### 3.2 消息ID体系

三个ID各司其职：

| 字段 | 必填 | 说明 |
|------|------|------|
| `id` | 是 | UUIDv7（时间排序），用于去重和ACK |
| `conversation_id` | 是 | UUIDv7，把多轮消息串成对话 |
| `parent_id` | 否 | 引用链，回复哪条消息 |

### 3.3 收件人模型

使用`recipient_type`枚举 + 两个字段互斥的方式，不解析字符串前缀：

```python
class RecipientType(str, Enum):
    DIRECT = "direct"       # 单播，使用 recipient_id
    GROUP = "group"         # 组播，使用 recipient_group
    BROADCAST = "broadcast" # 广播，两者都不填
```

- `recipient_type = DIRECT` → `recipient_id`必填，`recipient_group`为null
- `recipient_type = GROUP` → `recipient_group`必填，`recipient_id`为null
- `recipient_type = BROADCAST` → 两者都为null

## 4. MessageType 枚举

```python
class MessageType(str, Enum):
    TEXT = "text"                            # 纯文本对话
    TASK_DELEGATE = "task_delegate"          # 任务委托
    TASK_UPDATE = "task_update"              # 任务状态更新
    TASK_RESULT = "task_result"              # 任务结果
    CONTEXT_SHARE = "context_share"          # 上下文共享
    CAPABILITY_ANNOUNCE = "capability_announce"  # 能力声明
    FILE_TRANSFER_PROGRESS = "file_transfer_progress"  # 文件传输进度
    HEARTBEAT = "heartbeat"                  # 心跳/存活
    ERROR = "error"                          # 错误
```

扩展规则：新增类型必须以minor版本升级（v1.x），不删除旧类型。

## 5. Priority 枚举

```python
class Priority(str, Enum):
    LOW = "low"          # 低优先级
    NORMAL = "normal"    # 正常
    HIGH = "high"        # 高优先级
    URGENT = "urgent"    # 紧急
```

## 6. Part 类型系统

采用 discriminated union 模式，通过`type`字段区分：

### 6.1 TextPart

```json
{"type": "text", "text": "请分析Q1销售数据"}
```

### 6.2 DataPart

```json
{
  "type": "data",
  "content_type": "application/json",
  "data": {"columns": ["sales", "date"], "rows": [...]}
}
```

### 6.3 FileRefPart（轻量引用）

```json
{
  "type": "file_ref",
  "url": "sip://store/chunk/abc123",
  "hash": "sha256:abcdef...",
  "name": "report.pdf",
  "size": 10485760,
  "mime_type": "application/pdf"
}
```

### 6.4 FileDataPart（重量级内联）

```json
{
  "type": "file_data",
  "data": "base64encodedcontent...",
  "name": "config.json",
  "mime_type": "application/json"
}
```

### 6.5 ToolRequestPart

```json
{
  "type": "tool_request",
  "call_id": "call-uuid-xxx",
  "name": "sql_query",
  "arguments": {"query": "SELECT * FROM sales"}
}
```

### 6.6 ToolResponsePart

```json
{
  "type": "tool_response",
  "call_id": "call-uuid-xxx",
  "result": {"rows": [...]},
  "error": null
}
```

### 6.7 ContextPart

```json
{
  "type": "context",
  "key": "user_preference",
  "value": {"language": "zh-CN", "timezone": "Asia/Shanghai"},
  "ttl": 86400
}
```

### 6.8 StreamPart（预留，暂不实现）

```json
{
  "type": "stream",
  "chunk_index": 3,
  "total_chunks": null,
  "is_final": false,
  "data": "分块数据"
}
```

## 7. Metadata 结构

```json
{
  "reply_to": "msg-uuid-xxx",   // 回复哪条消息（引用关系）
  "priority": "high",           // Priority枚举
  "ttl": 3600,                  // 消息过期时间（秒），0=不过期
  "custom": {}                  // 自由扩展字段
}
```

- `reply_to`：Agent多轮对话的核心引用关系
- `ttl`：过期后接收方可拒绝处理
- `custom`：用户/应用自由扩展，不影响协议解析

## 8. 文件大小阈值策略

与F1文件传输模块协同：

- `< inline_threshold`（默认4KB，可配置）→ `FileDataPart`（base64内联）
- `>= inline_threshold` → `FileRefPart`（引用，由FileTransferManager处理）

```python
@dataclass
class MessageSchemaConfig:
    inline_threshold: int = 4096  # 文件内联阈值（字节）
```

## 9. 向后兼容策略

1. 解密后检查payload是否有`schema`字段
2. 有`schema` → 按SIP Message Schema解析
3. 无`schema` → 按原始UTF-8文本处理（v1.0之前的行为）
4. 未知`schema`版本 → 返回`MessageSchemaError`

## 10. 验证规则

```python
def validate_message(msg: dict) -> list[str]:
    errors = []
    # 必填字段
    for field in ["id", "conversation_id", "schema", "message_type",
                  "sender_id", "recipient_type", "timestamp", "parts"]:
        if field not in msg:
            errors.append(f"missing required field: {field}")
    # 收件人互斥检查
    if msg.get("recipient_type") == "direct" and not msg.get("recipient_id"):
        errors.append("DIRECT type requires recipient_id")
    # parts非空
    if not msg.get("parts"):
        errors.append("parts must not be empty")
    return errors
```

## 11. 模块位置

```
python/src/sip_protocol/
├── schema/
│   ├── __init__.py
│   ├── message.py        # SIPMessage, Part 类型定义
│   ├── types.py          # MessageType, Priority, RecipientType 枚举
│   └── validation.py     # 消息验证逻辑
```
