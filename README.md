# SIP协议 - Swarm Intelligence Protocol

> 端到端加密的多Agent通信协议 — Agent 通信的加密层（TLS for Agent Communication）

[![CI/CD](https://github.com/JoeyTrribbiani/sip-protocol/workflows/CI%2FCD/badge.svg)](https://github.com/JoeyTrribbiani/sip-protocol/actions)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

---

## 概述

SIP协议基于 Signal Double Ratchet，使用 XChaCha20-Poly1305 + X25519 + Triple DH，为多Agent提供端到端加密通道。SIP 不解析业务消息内容，定位为透明加密层。

**技术栈：** Python 3.11+ / stdlib dataclasses + enum / cryptography / argon2-cffi

---

## 架构

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

## 安装

```bash
# 使用 uv（推荐）
cd python
uv venv --python 3.11 .venv
source .venv/bin/activate
uv pip install -e ".[dev]"

# 或使用 pip
pip install -e python/
```

---

## 快速开始

### 消息结构化（S1 混合模式）

```python
from sip_protocol.schema.message import SIPMessage, create_message
from sip_protocol.schema.envelope import SIPEnvelope
from sip_protocol.schema.parts import TextPart

# 创建结构化消息
msg = create_message(
    sender="agent-a",
    recipient="agent-b",
    parts=[TextPart(text="Hello, SIP!")],
)

# 封装进加密信封（payload 为 bytes，不解析内容）
envelope = SIPEnvelope(
    version="SIP-1.3",
    payload=b"<encrypted_bytes>",
    content_type="application/sip-message+json",
    content_encoding="xchacha20-poly1305",
    sender="agent-a",
    recipient="agent-b",
    session_id="session-001",
)
```

### 文件传输（F1）

```python
from sip_protocol.file_transfer import FileTransferManager, FileTransferConfig

config = FileTransferConfig(inline_threshold=4096, chunk_size=1048576)
manager = FileTransferManager(config=config)

# 发送文件（小文件 → FileDataPart 内联，大文件 → FileRefPart 引用）
part = manager.send_file("/path/to/report.pdf")

# 接收文件（自动校验块 hash、路径遍历防护、文件名冲突重命名）
manager.receive_file(part, "/output/path/report.pdf")
```

---

## 模块概览

| 模块 | 状态 | 说明 |
|------|------|------|
| `crypto/` | ✅ 完成 | XChaCha20-Poly1305, AES-256-GCM, X25519, HKDF, Argon2 |
| `protocol/` | ✅ 完成 | Triple DH 握手、消息加密、群组 Double Ratchet、Rekey |
| `managers/` | ✅ 完成 | 会话状态、Nonce 防重放、群组成员 |
| `schema/` | ✅ 完成（S1） | SIPEnvelope + SIPMessage 混合模式、8 种 Part 类型 |
| `file_transfer/` | ✅ 完成（F1） | 分块存储、FileRefPart/FileDataPart 引用策略 |
| `transport/` | ✅ 完成 | 加密通道、WebSocket/OpenClaw/Hermes/MCP 适配器 |
| `exceptions.py` | ✅ 完成（P2） | 17 个分层异常 + 错误注册表 |

完整架构详见 [AGENTS.md](./AGENTS.md) 和 [docs/architecture.md](./docs/architecture.md)。

---

## 质量指标

| 指标 | 值 |
|------|------|
| 测试用例 | 553 passed, 36 skipped |
| 覆盖率 | 82% |
| Pylint | 10.00/10 |
| MyPy | 0 errors |
| Black | clean |

---

## 安全

- **端到端加密** — XChaCha20-Poly1305（主）+ AES-256-GCM（备选）
- **前向保密** — Signal Double Ratchet + Triple DH
- **抗重放** — Nonce + Replay Tag
- **抗篡改** — AEAD 认证标签
- **中间人防护** — PSK (Argon2id) 验证
- **时序攻击防护** — 恒定时间比较

---

## 贡献

详见 [CONTRIBUTING.md](./CONTRIBUTING.md)。

**开发规范：** Black + Pylint 10.00 + MyPy strict + pytest 80%+

**开发流程：** Fork → 创建分支 → 编写代码和测试 → PR

---

## 许可证

Apache License 2.0 — 详见 [LICENSE](./LICENSE)

---

## 致谢

- Signal Protocol: https://signal.org/docs/
- X25519: https://cr.yp.to/ecdh.html
- XChaCha20-Poly1305: https://datatracker.ietf.org/doc/draft-irtf-cfrg-xchacha/
- Argon2: https://github.com/P-H-C/phc-winner-argon2
