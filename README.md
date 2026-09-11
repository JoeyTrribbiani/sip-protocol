# SIP 加密库

> **SIP = Secure Inter-agent Protocol** — Agent 间端到端加密通道（TLS for Agent Communication）
> 纯加密层：不解析、不关心业务消息内容，业务层零侵入
>
> 命名声明：本项目的 SIP 指 Secure Inter-agent Protocol，与 IETF RFC 3261 定义的
> SIP（Session Initiation Protocol，VoIP 会话发起协议）**无关**——无关联、无衍生、
> 不共享任何语义或线格式。
>
> 协议是正式的：线格式权威规范见 **[docs/SPEC.md](./docs/SPEC.md)**（SPEC v1.0，
> 字节级定义 + 规范↔测试交叉索引 + 独立参考实现互操作验证）。

[![CI](https://github.com/JoeyTrribbiani/sip-protocol/actions/workflows/ci.yml/badge.svg)](https://github.com/JoeyTrribbiani/sip-protocol/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/JoeyTrribbiani/sip-protocol/badge.svg)](https://codecov.io/gh/JoeyTrribbiani/sip-protocol)
[![python](https://img.shields.io/badge/python-3.11-blue.svg)](https://www.python.org/)
[![cryptography](https://img.shields.io/badge/cryptography-41%2B-blue.svg)](https://github.com/pyca/cryptography)
[![AEAD](https://img.shields.io/badge/AEAD-ChaCha20--Poly1305-brightgreen.svg)](https://datatracker.ietf.org/doc/html/rfc8439)
[![pytest](https://img.shields.io/badge/pytest-7.4%2B-brightgreen.svg)](https://docs.pytest.org/)
[![code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](./LICENSE)

---

## 算法清单

| 用途 | 算法 | 模块 |
|------|------|------|
| 对称加密（主） | ChaCha20-Poly1305 AEAD（RFC 8439，12 字节随机 nonce；模块名 `xchacha20_poly1305`，见 [SPEC D1](./docs/SPEC.md)） | `crypto/xchacha20_poly1305.py` |
| 对称加密（备选） | AES-256-GCM AEAD（独立原语，无 wire 路径） | `crypto/aes_gcm.py` |
| 密钥交换 | X25519 ECDH（三重 DH） | `crypto/dh.py` |
| 密钥派生 | HKDF-SHA256 | `crypto/hkdf.py` |
| PSK 哈希 | Argon2id | `crypto/argon2.py` |
| 防重放 | Replay Tag（HMAC） + 消息计数器单调递增 + 时间戳窗 + Nonce FIFO（原语，见 SPEC §8/D3） | `managers/nonce.py` |
| 前向保密 | Triple DH 握手 + Rekey 轮换闭环 + 旧密钥安全擦除 | `protocol/handshake.py` `protocol/rekey.py` |
| 加密文件 | SIPFT1.0：流式分块 AEAD + HKDF 块独立密钥 + tag 链防篡改重排 | `filetransfer/` |

## 安装

```bash
# 使用 uv（推荐，仓库根执行；CI 同款 uv sync --frozen）
uv venv --python 3.11 .venv
source .venv/bin/activate
uv sync

# 或使用 pip（仅运行时依赖；开发依赖见 pyproject [dependency-groups].dev）
pip install -e .
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

### 加密文件（大 payload 场景）

`EncryptedChannel` 加密的是单条消息（全量内存），文件场景用 `filetransfer/`：
流式分块、常量内存、每块独立密钥、AEAD tag 链防篡改/重排/拼接/截断。
工件（`.sipft`）自包含，可走任意通道（dsh / git / 网盘），离线解包。

```python
import os
from sip_protocol.filetransfer import pack_file, unpack_file

master_key = os.urandom(32)  # 也可复用握手派生的会话密钥

result = pack_file("report.zip", master_key)          # → report.zip.sipft
out = unpack_file(result.artifact_path, master_key)   # 校验全链后才落盘
# 篡改/乱序/截断/错密钥 → ChunkIntegrityError / ArtifactCorruptedError，fail-fast
```

## API 参考

> 分层依赖（自上而下单向）：`filetransfer/`（应用层）与 `transport/` → `protocol/` →
> `crypto/`；`managers/` 提供会话状态与防重放，被 `protocol/` 与 `transport/` 复用；
> `exceptions.py` 为全局异常体系。
> 完整架构图见 [docs/architecture.md](./docs/architecture.md)。

| 模块 | 主要入口 | 说明 |
|------|---------|------|
| `crypto/` | `encrypt_xchacha20_poly1305` / `generate_keypair` / `hkdf` / `hash_psk` | 加密原语，可独立使用 |
| `protocol/` | `initiate_handshake` / `encrypt_message` / `RekeyManager` | 三重 DH、消息加解密、密钥轮换 |
| `managers/` | `SessionState` / `NonceManager` | 会话状态、防重放 |
| `transport/` | `EncryptedChannel` / `AgentMessage` / `SipMcpServer` | 加密通道、消息格式、MCP Server |
| `filetransfer/` | `pack_file` / `unpack_file` | 加密文件工件（应用层，仅依赖 crypto 原语） |
| `exceptions.py` | `SIPError` 及分层子类 | 全局异常体系 + 错误注册表 |

架构详见 [docs/architecture.md](./docs/architecture.md)，**线格式权威规范见 [docs/SPEC.md](./docs/SPEC.md)**
（字节级消息定义、密钥调度、错误码全表、版本演进策略、规范↔测试交叉索引；
历史设计稿 [docs/e2ee-protocol.md](./docs/e2ee-protocol.md) 保留供参考）。

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

## dsh 接入

本仓库根即一个 dsh 插件（`dsh-sip-protocol`，零部署纯声明式）：
`package.json` + `cordis.patch.yml` + `lib/index.mjs`。注册 agent 工具
`sip_encrypt` / `sip_decrypt`（ChaCha20-Poly1305 AEAD 一次性加解密，见 SPEC D1）与
`encrypted_file_pack` / `encrypted_file_unpack`（SIPFT1.0 流式加密文件工件），
每次调用 spawn Python，不守护服务进程。前置条件：解释器可导入 `sip_protocol`
（默认 `python3.11`，可用 `SIP_PYTHON` 覆盖）。

```bash
npx -y @deepseek-ai/dsh@0.1.2-rc.1 plugin --profile <profile> add <本仓库路径>
```

## 安全注意事项

- **PSK 管理** — PSK 经 Argon2id 哈希后参与三重 DH，用于中间人防护；生产环境 PSK 不得硬编码进代码或入库
- **加密文件工件** — SIPFT1.0：每块独立 HKDF 密钥 + AEAD tag 链（乱序/拼接/截断/跨工件移植逐块拒判，fail-fast）；文件名等元数据随头部加密且认证；流式常量内存
- **恒定时间比较** — 认证标签与 replay tag 均使用恒定时间比较，防时序攻击
- **旧密钥擦除** — Rekey 应用新密钥后旧密钥经 `ctypes.memset` 安全擦除
- **重放窗口** — Nonce 管理器 FIFO 淘汰 + 时间戳验证，超窗消息拒绝
- **版本强制** — 不认识的协议/信封/工件版本在任何密码学计算之前拒绝（SPEC §11.2）
- **未覆盖** — 本库不做密钥托管、设备指纹与后量子安全；后量子 KEX 见 [设计稿](./docs/superpowers/specs/2026-04-22-post-quantum-kex-design.md)；完整威胁模型与已知限制见 [SPEC §12](./docs/SPEC.md)
- **漏洞披露** — 安全问题请勿直接开公开 Issue，走私有安全报告入口，见 [SECURITY.md](./SECURITY.md)

## 治理

**规范优先**：协议行为变更（wire 格式/密钥调度/错误语义）必须先改
[SPEC.md](./docs/SPEC.md) 并同步交叉索引（`tests/test_spec_index.py` 机器校验），
互操作测试向量随之再生成——规范、实现、测试三方一致才算数。

- **维护承诺** — 主线维护 encryption-only 架构（v2.0 起）；CI 五层（uv 锁定安装 /
  Black+Pylint 10.00 / MyPy / pytest+覆盖率 / pip-audit）+ wheel 清单核验全绿才可合入；
  安全问题响应时限见 [SECURITY.md](./SECURITY.md)
- **路线图** — SPEC §13 登记项的渐进收敛（AEAD 命名与实现对齐、NonceManager 接线
  或移除、协议路径错误码化）；后量子 KEX（设计稿已有）；真 XChaCha20（随 SIP-2.0 评估）
- **非目标** — 不做消息内容解析/业务编排/平台适配/群组/分片（v2.0 已移除，git 历史
  ≤ v1.4.0 可回溯）；不做后量子（当前版本）；不做传输层本身（TCP/WS/消息队列由宿主选型）
- **互操作** — `scripts/interop/reference_impl.py` 为规范级第二实现（不读主库源码），
  `tests/vectors/` 测试向量供任意第三方实现自验；欢迎其它语言的独立实现接入向量集

## 质量指标

| 指标 | 值 |
|------|------|
| 测试用例 | 283 passed（含 26 互操作 + 3 规范索引校验） |
| 覆盖率 | 89% |
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
- ChaCha20-Poly1305 (RFC 8439): https://datatracker.ietf.org/doc/html/rfc8439
- XChaCha20 draft（未采用，见 SPEC D1）: https://datatracker.ietf.org/doc/draft-irtf-cfrg-xchacha/
- Argon2: https://github.com/P-H-C/phc-winner-argon2
