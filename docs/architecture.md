# SIP 加密库架构设计

> Secure Intelligence Protocol — Agent 间端到端加密通道（TLS for Agent Communication）

## 概述

SIP 自 v2.0 起专注加密层：为任意两个 Agent 提供端到端加密通道，不解析、不关心业务消息内容。基于 Triple DH 握手 + XChaCha20-Poly1305 消息加密 + Rekey 前向保密 + Nonce 防重放。

**技术栈：** Python 3.11+, stdlib dataclasses + enum, cryptography, argon2-cffi

**核心原则：**
- 单一职责 — 每个模块/文件只负责一个功能
- 高内聚低耦合 — 模块内部紧密，模块之间松散
- 纯同步 API — 无 async/await，简化调用方
- 纯 stdlib 数据结构 — dataclasses + enum，无 pydantic 依赖

---

## 分层架构

```
┌─────────────────────────────────────────────────────────────┐
│                    传输层（transport）                        │
│     EncryptedChannel 加密通道 │ AgentMessage │ MCP Server   │
├─────────────────────────────────────────────────────────────┤
│                    协议层（protocol）                        │
│     三重DH握手 │ 加密消息构建 │ Rekey 密钥轮换              │
├─────────────────────────────────────────────────────────────┤
│                    管理层（managers）                        │
│     会话状态（SessionState） │ Nonce 防重放                 │
├─────────────────────────────────────────────────────────────┤
│                    加密原语层（crypto）                      │
│  XChaCha20-Poly1305 │ AES-GCM │ X25519 │ HKDF │ Argon2id   │
└─────────────────────────────────────────────────────────────┘
```

依赖方向自上而下单向流动，`exceptions.py` 作为全局异常体系被所有层引用。

---

## 加密原语层（crypto/）

| 文件 | 职责 |
|------|------|
| `xchacha20_poly1305.py` | XChaCha20-Poly1305 AEAD 加密/解密（主算法） |
| `aes_gcm.py` | AES-256-GCM 加密/解密（备选算法） |
| `dh.py` | X25519 ECDH 密钥交换 |
| `hkdf.py` | HKDF-SHA256 密钥派生 |
| `argon2.py` | Argon2id PSK 哈希 |

- **依赖：** cryptography, argon2-cffi
- **被依赖：** protocol/

## 协议层（protocol/）

| 文件 | 职责 |
|------|------|
| `handshake.py` | 三重 DH 握手（initiate → respond → complete） |
| `message.py` | 加密消息构建与解析（payload + replay tag） |
| `rekey.py` | 密钥轮换（request → response → apply 闭环 + 旧密钥安全擦除） |

- **依赖：** crypto/
- **被依赖：** transport/

## 管理层（managers/）

| 文件 | 职责 |
|------|------|
| `session.py` | 会话状态管理（序列化/反序列化/过期检查） |
| `nonce.py` | Nonce 管理器（OrderedDict FIFO 淘汰，防重放攻击） |

- **依赖：** 无业务依赖
- **被依赖：** protocol/, transport/

## 传输层（transport/）

| 文件 | 职责 |
|------|------|
| `encrypted_channel.py` | 加密通道（生命周期管理 + Rekey 闭环 + 接收端触发） |
| `message.py` | Agent 消息格式（TEXT/ENCRYPTED/CONTROL） |
| `sip_mcp_server.py` | MCP Server（stdio JSON-RPC，四工具） |

- **依赖：** protocol/, crypto/, managers/
- **被依赖：** 上层应用（OpenClaw 经 MCP 接入）

---

## MCP Server 四工具

OpenClaw 等宿主经 stdio JSON-RPC 调用（`python -m sip_protocol --psk <key> --agent-id <id>`）：

| 工具 | 职责 |
|------|------|
| `sip_handshake` | 三重 DH 握手（initiator / responder / complete 三角色） |
| `sip_encrypt` | 加密消息（要求通道已建立） |
| `sip_decrypt` | 解密消息（要求通道已建立） |
| `sip_rekey` | 密钥轮换（initiator / responder 两角色） |

注意：握手 `complete` 依赖同进程的 `initiator` 状态（Auth 消息绑定发起方临时密钥），
宿主应使用长驻进程逐条收发请求。

---

## 安全机制

| 机制 | 实现 |
|------|------|
| 端到端加密 | XChaCha20-Poly1305 AEAD（主）+ AES-256-GCM（备选） |
| 前向保密 | Triple DH 握手 + Rekey 轮换闭环 + 旧密钥安全擦除 |
| 抗重放 | Nonce FIFO 淘汰 + 消息计数器 + Replay Tag |
| 抗篡改 | AEAD 认证标签 |
| 中间人防护 | PSK (Argon2id) 绑定 |
| 时序攻击防护 | 恒定时间比较 |

---

## 历史模块（v2.0 移除）

以下应用层模块在 v2.0 瘦身中移除，可在 git 历史（≤ v1.4.0）中回溯：

- `schema/`（S1 结构化消息）、`file_transfer/`（F1 分块传输）
- `discovery/`（S2+S4 AgentCard/AgentRegistry）
- `protocol/` 中的 group、group_simple、decision、fragment、offline_queue、persistence、resume、version
- `transport/` 中的 base、openclaw_adapter、hermes_claude_adapter、websocket_adapter
- `javascript/` 早期实现
