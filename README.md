# SIP 加密库

> Secure Intelligence Protocol — Agent 间端到端加密通道（TLS for Agent Communication）
> 纯加密层：不解析、不关心业务消息内容，业务层零侵入

[![python](https://img.shields.io/badge/python-3.11-blue.svg)](https://www.python.org/)
[![algorithm](https://img.shields.io/badge/AEAD-XChaCha20--Poly1305-brightgreen.svg)](https://datatracker.ietf.org/doc/draft-irtf-cfrg-xchacha/)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](./LICENSE)

---

## 算法清单

| 用途 | 算法 | 模块 |
|------|------|------|
| 对称加密（主） | XChaCha20-Poly1305 AEAD | `crypto/xchacha20_poly1305.py` |
| 对称加密（备选） | AES-256-GCM AEAD | `crypto/aes_gcm.py` |
| 密钥交换 | X25519 ECDH（三重 DH） | `crypto/dh.py` |
| 密钥派生 | HKDF-SHA256 | `crypto/hkdf.py` |
| PSK 哈希 | Argon2id | `crypto/argon2.py` |
| 防重放 | Nonce FIFO 淘汰 + 消息计数器 + Replay Tag | `managers/nonce.py` |
| 前向保密 | Triple DH 握手 + Rekey 轮换闭环 + 旧密钥安全擦除 | `protocol/handshake.py` `protocol/rekey.py` |

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

运行时依赖仅 `cryptography` 与 `argon2-cffi`，Python ≥ 3.11。

## 快速上手

### 加密通道（推荐入口）

```python
from sip_protocol.transport import EncryptedChannel

psk = b"shared-psk-between-two-agents"  # 生产环境从安全渠道获取

channel_a = EncryptedChannel(agent_id="agent-a", psk=psk)
channel_b = EncryptedChannel(agent_id="agent-b", psk=psk)

# 1. 三重 DH 握手（hello/auth 消息经任意载体传给对方）
hello = channel_a.initiate()
auth = channel_b.respond_to_handshake(hello)
channel_a.complete_handshake(auth)

# 2. 加密 → 解密
msg = channel_a.send("你好，Agent B！", "agent-b")
assert channel_b.receive(msg) == "你好，Agent B！"

# 3. 手动 Rekey（也可配置 rekey_after_messages / rekey_after_seconds 自动触发）
from sip_protocol.protocol.rekey import RekeyManager

mgr_a = RekeyManager(channel_a.session_keys, is_initiator=True)
req = mgr_a.create_rekey_request(reason="manual")

mgr_b = RekeyManager(channel_b.session_keys, is_initiator=False)
assert mgr_b.validate_rekey_request(req)
resp = mgr_b.process_rekey_request(req)

new_keys_a = mgr_a.process_rekey_response(resp)
mgr_a.apply_new_keys(new_keys_a)
mgr_b.apply_new_keys(mgr_b.temp_new_keys)
```

### 协议层原语

```python
from sip_protocol.protocol.handshake import initiate_handshake, respond_handshake, complete_handshake
from sip_protocol.protocol.message import encrypt_message, decrypt_message

psk = b"shared-psk-between-two-agents"
hello, state_a = initiate_handshake(psk)
auth, state_b, keys_b = respond_handshake(hello, psk)
keys_a, session_state = complete_handshake(auth, state_a)

enc = encrypt_message(
    keys_a["encryption_key"], "hello", "agent-a", "agent-b",
    counter=1, replay_key=keys_a["replay_key"],
)
assert decrypt_message(keys_b["encryption_key"], enc) == "hello"
```

## API 参考

| 模块 | 主要入口 | 说明 |
|------|---------|------|
| `crypto/` | `encrypt_xchacha20_poly1305` / `generate_keypair` / `hkdf` / `hash_psk` | 加密原语，可独立使用 |
| `protocol/` | `initiate_handshake` / `encrypt_message` / `RekeyManager` | 三重 DH、消息加解密、密钥轮换 |
| `managers/` | `SessionState` / `NonceManager` | 会话状态、防重放 |
| `transport/` | `EncryptedChannel` / `AgentMessage` / `SipMcpServer` | 加密通道、消息格式、MCP Server |
| `exceptions.py` | `SIPError` 及分层子类 | 全局异常体系 + 错误注册表 |

架构详见 [docs/architecture.md](./docs/architecture.md)，协议权威规范见 [docs/e2ee-protocol.md](./docs/e2ee-protocol.md)。

### MCP Server（四工具）

OpenClaw 等宿主经 stdio JSON-RPC 接入：

```bash
python -m sip_protocol --psk <shared-key> --agent-id <agent-id>
```

| 工具 | 职责 |
|------|------|
| `sip_handshake` | 三重 DH 握手（initiator / responder / complete 三角色） |
| `sip_encrypt` | 加密消息（要求通道已建立） |
| `sip_decrypt` | 解密消息（要求通道已建立） |
| `sip_rekey` | 密钥轮换（initiator / responder 两角色） |

注意：握手 `complete` 依赖同进程的 `initiator` 状态，宿主应使用长驻进程逐条收发请求。

## 安全注意事项

- **PSK 管理** — PSK 经 Argon2id 哈希后参与三重 DH，用于中间人防护；生产环境 PSK 不得硬编码进代码或入库
- **恒定时间比较** — 认证标签与 replay tag 均使用恒定时间比较，防时序攻击
- **旧密钥擦除** — Rekey 应用新密钥后旧密钥经 `ctypes.memset` 安全擦除
- **重放窗口** — Nonce 管理器 FIFO 淘汰 + 时间戳验证，超窗消息拒绝
- **未覆盖** — 本库不做密钥托管、设备指纹与后量子安全；后量子 KEX 见 [设计稿](./docs/superpowers/specs/2026-04-22-post-quantum-kex-design.md)
- **漏洞披露** — 安全问题请勿直接开公开 Issue，参见 [CONTRIBUTING.md](./CONTRIBUTING.md)

## 质量指标

| 指标 | 值 |
|------|------|
| 测试用例 | 207 passed |
| 覆盖率 | 88% |
| Pylint | 10.00/10 |
| MyPy | 0 errors |
| Black | clean |

## 贡献

详见 [CONTRIBUTING.md](./CONTRIBUTING.md)。开发规范：Black + Pylint 10.00 + MyPy + pytest。

## 许可证

Apache License 2.0 — 详见 [LICENSE](./LICENSE)

## 致谢

- Signal Protocol: https://signal.org/docs/
- X25519: https://cr.yp.to/ecdh.html
- XChaCha20-Poly1305: https://datatracker.ietf.org/doc/draft-irtf-cfrg-xchacha/
- Argon2: https://github.com/P-H-C/phc-winner-argon2
