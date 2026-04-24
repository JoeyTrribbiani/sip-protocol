# SIP 协议架构设计

> Swarm Intelligence Protocol — 端到端加密的多 Agent 通信协议（TLS for Agent Communication）

## 概述

SIP 采用分层架构：从底层加密原语到高层消息结构，每一层职责明确。基于 Signal Double Ratchet，使用 XChaCha20-Poly1305 + X25519 + Triple DH。

**技术栈：** Python 3.11+, stdlib dataclasses + enum, cryptography, argon2-cffi

**核心原则：**
- 单一职责 — 每个模块/文件只负责一个功能
- 高内聚低耦合 — 模块内部紧密，模块之间松散
- 纯同步 API — 无 async/await，简化调用方
- 接口稳定 — Protocol 定义抽象，实现可替换

---

## 分层架构

```
┌─────────────────────────────────────────────────────────────┐
│                    传输适配器层（transport）                  │
│     WebSocket │ OpenClaw │ Hermes │ MCP Server              │
├─────────────────────────────────────────────────────────────┤
│                    协议层（protocol）                        │
│     握手 │ 消息 │ 群组 │ Rekey │ 分片 │ 恢复 │ 决策        │
├──────────────────┬──────────────────────────────────────────┤
│ 结构化层（schema）│          文件传输层（file_transfer）      │
│ Envelope │ Message│  Config │ Manifest │ Store │ Manager    │
│ 8 种 Part       │                                       │
├──────────────────┴──────────────────────────────────────────┤
│                    管理层（managers）                        │
│     会话状态 │ Nonce 防重放 │ 群组成员                       │
├─────────────────────────────────────────────────────────────┤
│                    加密原语层（crypto）                      │
│  XChaCha20 │ AES-GCM │ X25519 │ HKDF │ Argon2             │
└─────────────────────────────────────────────────────────────┘
```

---

## 混合消息模式（S1）

SIP 采用「信封 + 消息」双层结构：

### SIPEnvelope — 加密载体
```python
@dataclass
class SIPEnvelope:
    version: str          # 协议版本
    payload: bytes        # 加密后的密文（bytes，不解析内容）
    content_type: str     # 顶层字段：payload 的 MIME 类型
    content_encoding: str # 顶层字段：编码方式（如 "aes256-gcm"）
    sender: str           # 发送者标识
    recipient: str        # 接收者标识
    timestamp: str        # ISO 8601 UTC
    nonce: str            # 加密 nonce
    session_id: str       # 会话 ID
```

### SIPMessage — 结构化语义
```python
@dataclass
class SIPMessage:
    message_id: str       # UUID7
    sender: str
    recipient: str
    content_type: str
    parts: list[Part]     # 8 种 Part 类型
    parent_id: str        # 父消息 ID（不在信封层）
    created_at: str
    expires_at: str
```

### 8 种 Part 类型

| Part | 用途 | 语义 |
|------|------|------|
| TextPart | 文本消息 | 轻量，直接内联 |
| BinaryPart | 二进制数据 | base64 内联 |
| FileRefPart | 文件引用 | 轻量引用，指向 manifest |
| FileDataPart | 文件内联 | 小文件 base64 内联 |
| AgentRefPart | Agent 引用 | 引用其他 Agent |
| TaskPart | 任务描述 | 结构化任务信息 |
| ControlPart | 控制指令 | 协议级控制消息 |
| ErrorPart | 错误信息 | 结构化错误报告 |

---

## 文件传输（F1）

### 设计策略
- **小文件**（≤ inline_threshold，默认 4KB）→ FileDataPart（base64 内联到消息中）
- **大文件**（> inline_threshold）→ FileRefPart（引用）+ LocalFileStore（本地存储块）

### 分块流程

```
发送方:
  文件 → 分块（chunk_size=1MB）→ 计算 hash → 存入 LocalFileStore → 返回 FileRefPart

接收方:
  FileRefPart → 读取 manifest → 逐块读取并校验 hash → 重组 → 写入输出路径
```

### 关键组件

| 组件 | 职责 |
|------|------|
| FileTransferConfig | 阈值配置（inline_threshold, chunk_size, max_file_size） |
| FileChunk + FileManifest | 块元数据 + 文件清单（序列化支持） |
| FileStore (Protocol) | 存储接口定义 |
| LocalFileStore | 本地文件系统实现（目录结构化、过期清理） |
| FileTransferManager | 核心协调器（send_file, receive_file, get_progress） |
| TransferStatus | 状态机（PENDING → SENDING → COMPLETED/FAILED/CANCELED） |
| TransferProgress | 归一化进度追踪（0..1） |

### 安全特性
- 路径遍历防护（os.path.realpath 校验）
- 文件名冲突自动重命名（`file.txt` → `file (2).txt`）
- 逐块 SHA-256 hash 校验 + 整体内容 hash 校验
- 文件大小限制（默认 5GB）

---

## 异常体系（P2）

```
SIPError（基类，code + message + severity + recoverable + details）
├── CryptoError
│   ├── EncryptionError
│   ├── DecryptionError
│   └── KeyDerivationError
├── ProtocolError
│   ├── HandshakeError
│   ├── SessionError
│   └── ReplayError
├── SchemaError
│   ├── ValidationError
│   └── SerializationError
├── TransportError
│   ├── ConnectionError
│   └── TimeoutError
├── FileTransferError
│   ├── ChunkIntegrityError
│   └── FileTooLargeError
└── GroupError
    ├── GroupMembershipError
    └── GroupEncryptionError
```

所有异常支持 `to_dict()` / `SIPError.from_dict()` 序列化往返。

---

## 模块依赖关系

```
transport/ ──→ protocol/ ──→ crypto/
    │              │            │
    │              └──→ managers/
    │
    └──→ schema/ ←── file_transfer/
           │
           └──→ exceptions.py（全局）
```

**依赖规则：**
- 上层可调用下层，下层不可调用上层
- 同层模块可相互调用（如 protocol/group → protocol/message）
- exceptions.py 是全局叶子依赖，被所有模块引用

---

## 数据流

### 加密消息发送

```
SIPMessage → JSON 序列化 → bytes
    → XChaCha20-Poly1305 加密（密文 + nonce + tag）
    → 封装为 SIPEnvelope（payload = 密文）
    → 传输层发送
```

### 加密消息接收

```
传输层接收 → SIPEnvelope
    → nonce 重放检查（managers/nonce）
    → XChaCha20-Poly1305 解密
    → JSON 反序列化 → SIPMessage
```

### 文件传输

```
小文件: 文件路径 → read → base64 编码 → FileDataPart → 放入 SIPMessage.parts
大文件: 文件路径 → 分块 + hash → LocalFileStore 存储 → FileManifest → FileRefPart
```

---

## 协议加固（P3）

针对 e2ee-protocol.md 设计文档的 10 项差距，完成以下修复：

### 安全修复
- **Handshake** — 删除 `complete_handshake` 中重复的三重 DH 计算
- **Resume** — 签名数据绑定 `message["sender_id"]`，与验证函数一致
- **Nonce** — `set` 改为 `OrderedDict`，保证 FIFO 淘汰顺序

### 加密加固
- **群组 Double Ratchet** — `chain_key` 每条消息推进（`HKDF("message-key")` → `HKDF("chain-key")`），确保前向保密
- **Skip Ratchet** — 乱序消息统一用 `chain-key` 标签推进 chain_key，非预生成路径存储 skip_key 供延迟解密
- **Rekey** — 旧密钥通过 `ctypes.memset` 安全擦除（bytearray 类型），接收端计数器触发轮换检查
- **Rekey 闭环** — `process_rekey_response` / `handle_rekey_request` / `get_pending_rekey_request` 方法补全 request→response→apply 流程

### 功能补全
- **版本协商** — 4 步协议：`create_version_offer` → `create_version_response` → `parse_version_response`（含 `local_supported` 验证）

---

## 设计决策记录

| 决策 | 原因 |
|------|------|
| SIP 定位为加密层 | 不与应用层协议（A2A/MCP）耦合，作为透明加密通道 |
| 信封与消息分离 | 加密层只需处理 bytes payload，不解析业务语义 |
| FileRefPart / FileDataPart 分离 | 两种语义完全不同（引用 vs 内联），不应混为一谈 |
| 纯同步 API | 降低复杂度，调用方可自行决定是否异步包装 |
| 纯 stdlib（无 pydantic） | 减少依赖，dataclass + enum 足够 |
| kwargs.setdefault() 异常继承 | 避免 from_dict 反序列化时 "multiple values for keyword argument" |
