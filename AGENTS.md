# AGENTS.md

> SIP Protocol 项目结构与模块职责速览

## 目录结构

```
sip-protocol/
├── python/                        # 主实现语言（Python 3.11+）
│   └── src/sip_protocol/
│       ├── __init__.py            # 包入口，__version__
│       ├── __main__.py            # CLI 入口（python -m sip_protocol）
│       ├── exceptions.py          # 全局异常体系（17 个分层异常 + 错误注册表）
│       ├── crypto/                # 加密原语层
│       ├── protocol/              # 协议层
│       ├── schema/                # 消息结构化层（S1）
│       ├── file_transfer/         # 文件传输模块（F1）
│       ├── managers/              # 会话与 nonce 管理
│       └── transport/             # 传输适配器层
├── javascript/                    # 早期 JS 实现（不活跃）
├── docs/                          # 文档
│   ├── architecture.md            # 架构设计
│   ├── superpowers/specs/         # 设计规格文档
│   └── superpowers/plans/         # 实施计划文档
├── CHANGELOG.md                   # 变更日志
├── CONTRIBUTING.md                # 贡献指南
└── README.md                      # 项目简介
```

## 模块职责

### `exceptions.py` — 全局异常体系
- SIPError 基类（dataclass + Exception），to_dict / from_dict 序列化
- 17 个分层异常：CryptoError, ProtocolError, SchemaError, TransportError, FileTransferError 等
- _register_error 装饰器 + _ERROR_REGISTRY 错误注册表
- **下游依赖：** 被所有模块引用，不依赖任何业务模块

### `crypto/` — 加密原语层
| 文件 | 职责 |
|------|------|
| `xchacha20_poly1305.py` | XChaCha20-Poly1305 AEAD 加密/解密（主算法） |
| `aes_gcm.py` | AES-256-GCM 加密/解密（备选算法） |
| `dh.py` | X25519 ECDH 密钥交换 |
| `hkdf.py` | HKDF-SHA256 密钥派生 |
| `argon2.py` | Argon2id PSK 哈希 |
- **依赖：** cryptography, argon2-cffi
- **被依赖：** protocol/, transport/

### `protocol/` — 协议层
| 文件 | 职责 |
|------|------|
| `handshake.py` | 三重 DH 握手协议 |
| `message.py` | 加密消息构建与解析 |
| `group.py` | 群组 Double Ratchet + Skip Ratchet |
| `rekey.py` | 密钥轮换 |
| `resume.py` | 连接恢复 |
| `version.py` | 协议版本协商（SIP-1.0 ~ SIP-1.3） |
| `fragment.py` | 大消息分片与重组 |
| `decision.py` | 集体决策引擎（提案/投票） |
| `persistence.py` | SQLite 消息持久化 |
| `offline_queue.py` | 离线消息队列 |
| `group_simple.py` | 简化群组实现（占位） |
- **依赖：** crypto/, managers/
- **被依赖：** transport/

### `schema/` — 消息结构化层（S1）
| 文件 | 职责 |
|------|------|
| `envelope.py` | SIPEnvelope 加密载体（payload=bytes, content_type, content_encoding） |
| `message.py` | SIPMessage 结构化语义（message_id, sender, recipient, parts, parent_id） |
| `parts.py` | 8 种 Part 类型（Text, Binary, FileRef, FileData, AgentRef, Task, Control, Error） |
| `types.py` | MessageType, PartType 枚举 |
| `validation.py` | validate_message() 入口验证 |
| `_utils.py` | 内部工具（_generate_uuid7, _iso_now） |
- **依赖：** 无业务依赖，仅 stdlib
- **被依赖：** file_transfer/, transport/

### `file_transfer/` — 文件传输模块（F1）
| 文件 | 职责 |
|------|------|
| `config.py` | FileTransferConfig（阈值、块大小、大小限制） |
| `manifest.py` | FileChunk + FileManifest（元数据与块列表） |
| `store.py` | FileStore 协议 + LocalFileStore（本地文件系统存储） |
| `manager.py` | FileTransferManager（分块/存储/引用协调，TransferProgress） |
- **依赖：** schema/parts（FileRefPart, FileDataPart）, schema/_utils, exceptions.py
- **被依赖：** 调用方（transport 层或上层应用）

### `managers/` — 会话与 nonce 管理
| 文件 | 职责 |
|------|------|
| `session.py` | 会话状态管理（序列化/反序列化/过期检查） |
| `nonce.py` | Nonce 管理器（防重放攻击） |
| `group.py` | 群组成员管理（加入/离开） |
- **依赖：** 无业务依赖
- **被依赖：** protocol/

### `transport/` — 传输适配器层
| 文件 | 职责 |
|------|------|
| `base.py` | TransportAdapter 抽象基类 |
| `encrypted_channel.py` | 加密通道（完整生命周期管理） |
| `message.py` | Agent 消息格式（TEXT/ENCRYPTED/CONTROL） |
| `openclaw_adapter.py` | OpenClaw CLI 适配器 |
| `hermes_claude_adapter.py` | Hermes ↔ Claude Code 适配器 |
| `websocket_adapter.py` | WebSocket 传输适配器 |
| `sip_mcp_server.py` | MCP Server（stdio JSON-RPC） |
- **依赖：** protocol/, crypto/, managers/
- **被依赖：** 上层应用

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

## 关键约定

- **纯同步 API** — 无 async/await
- **纯 stdlib** — dataclasses + enum，无 pydantic
- **注释中文，标识符英文**
- **异常继承链** — kwargs.setdefault() 避免序列化冲突
- **Pylint 10.00/10** — max-args=7，用 MessageOptions 绕过
