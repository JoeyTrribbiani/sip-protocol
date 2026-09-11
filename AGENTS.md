# AGENTS.md

> SIP 加密库项目结构与模块职责速览（v2.0 encryption-only）

## 目录结构

```
sip-protocol/
├── python/                        # 主实现语言（Python 3.11+）
│   └── src/sip_protocol/
│       ├── __init__.py            # 包入口，__version__ = 2.0.0
│       ├── __main__.py            # MCP 入口（python -m sip_protocol）
│       ├── exceptions.py          # 全局异常体系（分层异常 + 错误注册表）
│       ├── crypto/                # 加密原语层
│       ├── protocol/              # 协议层（握手/消息/Rekey）
│       ├── managers/              # 会话与 nonce 管理
│       └── transport/             # 加密通道与 MCP Server
├── docs/                          # 文档（architecture + e2ee-protocol + 3 个设计稿）
├── CHANGELOG.md                   # 变更日志
├── CONTRIBUTING.md                # 贡献指南
└── README.md                      # 项目简介
```

## 模块职责

### `exceptions.py` — 全局异常体系
- SIPError 基类（dataclass + Exception），to_dict / from_dict 序列化
- 分层异常：CryptoError, ProtocolError, TransportError 等
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
- **被依赖：** protocol/

### `protocol/` — 协议层
| 文件 | 职责 |
|------|------|
| `handshake.py` | 三重 DH 握手协议 |
| `message.py` | 加密消息构建与解析（payload + replay tag） |
| `rekey.py` | 密钥轮换（request→response→apply 闭环 + _secure_wipe） |
- **依赖：** crypto/, managers/
- **被依赖：** transport/

### `managers/` — 会话与 nonce 管理
| 文件 | 职责 |
|------|------|
| `session.py` | 会话状态管理（序列化/反序列化/过期检查） |
| `nonce.py` | Nonce 管理器（OrderedDict FIFO 淘汰，防重放攻击） |
- **依赖：** 无业务依赖
- **被依赖：** protocol/, transport/

### `transport/` — 传输层
| 文件 | 职责 |
|------|------|
| `encrypted_channel.py` | 加密通道（生命周期管理 + Rekey 闭环 + 接收端触发） |
| `message.py` | Agent 消息格式（TEXT/ENCRYPTED/CONTROL） |
| `sip_mcp_server.py` | MCP Server（stdio JSON-RPC，四工具，OpenClaw 在用） |
- **依赖：** protocol/, crypto/, managers/
- **被依赖：** 上层应用

## 模块依赖关系

```
transport/ ──→ protocol/ ──→ crypto/
    │              │
    │              └──→ managers/
    └──→ exceptions.py（全局）
```

## 关键约定

- **纯同步 API** — 无 async/await
- **纯 stdlib** — dataclasses + enum，无 pydantic
- **注释中文，标识符英文**
- **异常继承链** — kwargs.setdefault() 避免序列化冲突
- **Pylint 10.00/10** — max-args=7，用 MessageOptions 绕过
- **MCP 四工具行为冻结** — sip_handshake/sip_encrypt/sip_decrypt/sip_rekey 不得变更响应结构（黄金基线管控）
- **MCP 入口** — `python3.11 -m sip_protocol --psk <key> --agent-id <id>`（openclaw.json 通路，改造不可破坏）
- **v2.0 已移除** — schema/file_transfer/discovery/group/decision/fragment/offline_queue/persistence/resume/version/各平台适配器/javascript（git 历史 ≤ v1.4.0 可回溯）
