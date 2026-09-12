# AGENTS.md

> SIP 加密库项目结构与模块职责速览（v2.2.0 双套件：EN 国际 / ZH 国密）

## 目录结构

```
sip-protocol/                     # 根级单包布局（2026-09-11 扁平化，对齐 rf 家族分发库标准）
├── src/sip_protocol/
│   ├── __init__.py                # 包入口，__version__ = 2.2.0
│   ├── __main__.py                # MCP 入口（python -m sip_protocol，--suite EN|ZH 可选）
│   ├── exceptions.py              # 全局异常体系（分层异常 + 错误注册表）
│   ├── crypto/                    # 加密原语层（EN: X25519/ChaCha/HKDF-SHA256 + ZH: SM2/SM3/SM4-GCM）
│   ├── protocol/                  # 协议层（握手/消息/Rekey，套件协商贯通）
│   ├── managers/                  # 会话与 nonce 管理
│   ├── transport/                 # 加密通道与 MCP Server（suite 构造参数）
│   └── filetransfer/              # 加密文件工件（应用层，.sipft，套件带外约定）
├── tests/                         # pytest 测试（371 用例：283 EN 回归 + 88 国密；含 interop 双套件/规范索引校验）
│   └── vectors/                   # 互操作测试向量（EN + ZH 两份，主库导出，参考实现消费）
├── scripts/interop/               # 独立参考实现（仅依 SPEC，零 import 主库；EN+ZH 双套件）+ 向量生成
├── lib/index.mjs + package.json   # dsh 壳插件（dsh-sip-protocol，根级并存）
├── docs/
│   ├── SPEC.md                    # SIP-1.0 线格式权威规范（v1.1：双套件 + 交叉索引 + 偏差登记 D1-D10）
│   ├── adr/001-sm-crypto-lib.md   # 国密原语选型决策记录（ADR-001）
│   ├── architecture.md / e2ee-protocol.md（历史设计稿，被 SPEC 取代）/ 3 个设计稿
├── pyproject.toml + uv.lock       # 打包与依赖锁定（根级；cryptography>=42，gmssl 仅 dev 组）
├── CHANGELOG.md                   # 变更日志
├── CONTRIBUTING.md                # 贡献指南
├── SECURITY.md                    # 安全策略（披露入口/攻击面/支持版本）
└── README.md                      # 项目简介（含治理节 + 双套件算法表）
```

## 模块职责

### `exceptions.py` — 全局异常体系
- SIPError 基类（dataclass + Exception），to_dict / from_dict 序列化
- 分层异常：CryptoError, ProtocolError, TransportError 等
- _register_error 装饰器 + _ERROR_REGISTRY 错误注册表
- **下游依赖：** 被所有模块引用，不依赖任何业务模块

### `crypto/` — 加密原语层（双套件分派，接口签名不变，缺省 EN）
| 文件 | 职责 |
|------|------|
| `suite.py` | 套件常量（EN/ZH）/校验/digestmod 工厂/公钥与密钥长度表 |
| `xchacha20_poly1305.py` | AEAD 分派：EN → ChaCha20-Poly1305（RFC 8439）；ZH → SM4-GCM（偏差 D1 模块双承载） |
| `sm4_gcm.py` | SM4-GCM AEAD（RFC 8998 形态，偏差 D10；cryptography/OpenSSL C 实现） |
| `aes_gcm.py` | AES-256-GCM 加密/解密（备选算法，无 wire 路径） |
| `dh.py` | 密钥交换分派：EN → X25519（RFC 7748）；ZH → SM2；序列化/解析辅助（长度不符→SuiteNegotiationError） |
| `sm2.py` | SM2 曲线运算（GM/T 0003.5，自研仿射点乘；原始 ECDH 取 x 坐标，偏差 D9；与 gmssl 交叉验证） |
| `hkdf.py` | HKDF 分派：EN → HKDF-SHA256；ZH → HKDF-SM3（ZH 三元组 16+32+32） |
| `sm3.py` | SM3 杂凑（GM/T 0004）+ hashlib 风格适配器（HMAC-SM3 经标准库 hmac） |
| `argon2.py` | Argon2id PSK 哈希（**套件无关**，ADR-001 决策 5） |
- **依赖：** cryptography(>=42，SM4-GCM 下限), argon2-cffi；gmssl 仅 dev 组（测试交叉验证，非运行时）
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

### `filetransfer/` — 加密文件工件（应用层，v2.1 重建）
| 文件 | 职责 |
|------|------|
| `format.py` | SIPFT1.0 工件布局 + 密钥调度（HKDF 头/块独立密钥）+ AAD 构造 |
| `packer.py` | pack_file：流式分块加密（常量内存，tmp+原子替换） |
| `unpacker.py` | unpack_file：逐块认证 fail-fast + 路径防穿越 + 冲突重命名 |
- **依赖：** crypto/（hkdf, xchacha20_poly1305）+ exceptions.py；不依赖 transport/protocol
- **被依赖：** dsh 壳 encrypted_file_pack / encrypted_file_unpack
- **背景：** v1.x file_transfer（明文落盘引用式）评估后按 dsh 公制重做，非原样恢复

## 模块依赖关系

```
filetransfer/ ──→ crypto/            （应用层，仅复用原语）
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
- **规范优先（SPEC-first）** — wire 格式/密钥调度/错误语义变更必须先改 docs/SPEC.md 并同步
  §14 交叉索引（tests/test_spec_index.py 机器校验）与互操作向量（scripts/interop/generate_vectors.py，
  EN 与 --suite zh 两份）；规范↔代码偏差登记在 SPEC §13（D1-D10），如实记述不擅改
- **双套件（v2.2）** — EN（缺省，行为逐位不变）/ ZH（国密 SM2/SM3/SM4-GCM，ADR-001）；
  协商为单选无降级（SuiteNegotiationError SIP-PROTO-005，缺 suite 字段=EN 向后兼容）；
  EN 的 wire/序列化不得携带 suite 字段（tests/test_sm_suite.py::TestENWireUnchanged 红线盯着）
- **SIP = Secure Inter-agent Protocol** — 与 RFC 3261 (VoIP SIP) 无关；历史展开 "Secure Intelligence Protocol" 停用
- **版本字段强制** — SIP-1.0 / SIP-TRANSPORT-1.0 / SIPFT1.0 三层版本不匹配一律拒绝（SPEC §11.2）；
  套件演进不改线协议版本（suite 是 §11.3 可选字段先例）
- **MCP 入口** — `python3.11 -m sip_protocol --psk <key> --agent-id <id>`（openclaw.json 通路，改造不可破坏；
  可选 `--suite ZH` 走国密，缺省 EN 不带该参数即历史行为）
- **v2.0 已移除** — schema/discovery/group/decision/fragment/offline_queue/persistence/resume/version/各平台适配器/javascript（git 历史 ≤ v1.4.0 可回溯）；file_transfer 已于 v2.1 以 `filetransfer/` 按新架构重建
