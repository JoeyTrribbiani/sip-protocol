# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### 新增（协议化改造：让它成为名副其实的协议）

- **`docs/SPEC.md` — SIP-1.0 线格式权威规范（SPEC v1.0，Experimental/Living）**
  - 从 v2.1.0 实现逐字节反推：术语/角色、三重 DH 握手状态机与消息字段表、
    Auth HMAC transcript 字节级定义（含 json.dumps 分隔符复刻）、密钥调度标签树、
    会话消息 wire 格式与接收端五步处理顺序、Rekey 消息/验证/派生/切换时序、
    SIPFT1.0 二进制布局偏移表与 AAD tag 链、错误码全表（标注 wire 使用现状）、
    版本协商与演进策略（fail-closed，拒绝行为 MUST 化）、安全考虑
  - **§13 实现偏差登记 D1-D8**：XChaCha 命名 vs ChaCha20 实现、Argon2 固定盐、
    NonceManager 未接线、协议路径 ValueError vs SIP-xxx 码、Complete 回执无验证路径、
    bytes 擦除限制等——如实记述不擅改
  - **§14 规范↔测试交叉索引**：每个章节列出对应测试文件/用例，
    `tests/test_spec_index.py` 机器校验引用真实性（防规范-测试漂移）
  - 取代 docs/e2ee-protocol.md 作为权威文档（后者保留为历史设计稿）
- **互操作第二实现 `scripts/interop/reference_impl.py` + 测试向量**
  - 参考实现仅依 SPEC 反推（零 import 主库；HKDF 按 RFC 5869 自实现；
    X25519/ChaCha20-Poly1305/Argon2id 作原语复用），覆盖握手双侧/消息/rekey/SIPFT
  - `scripts/interop/generate_vectors.py` 从主库捕获握手中间态/私钥/密文/tag →
    `tests/vectors/sip_test_vectors.json`（确定性 nonce/file_id 注入）
  - `tests/test_interop.py` 26 用例：静态向量回放 + CI 即时重建（fresh-ci 参数化，
    生成→参考实现消费→双向断言）+ 活体对话（握手→双向消息→双向 rekey→信封层往返）
    + 负路径（篡改签名/密文/replay_tag/计数器重放/错版本/工件篡改，双方必拒）
  - 参考实现按 SPEC 独立实现全程未遇规范歧义（无回修）
- **`SECURITY.md`** — 攻击面/信任模型、支持版本、私有披露入口与响应时限、
  draft 披露政策（GitHub 自动识别展示安全报告入口）
- **README 治理节** — 规范优先流程、维护承诺、路线图（SPEC §13 收敛/PQ KEX）、
  非目标、互操作接入方式

### 变更

- **命名消歧（零改名）** — SIP 统一展开为 **Secure Inter-agent Protocol**
  （README 首段/SPEC 术语节/pyproject description/仓库 description+topics），
  显式声明与 IETF RFC 3261（VoIP Session Initiation Protocol）无关：无关联无衍生；
  历史展开 "Secure Intelligence Protocol" 停用
- **版本字段强制校验（SPEC §11.2 / 偏差 D7，唯一功能改动，4 文件）**
  - 审计结论：`SIP-1.0`/`SIP-TRANSPORT-1.0` 版本串此前只写不读（工件魔数例外）
  - `respond_handshake`/`complete_handshake` 入口校验 → `VersionNegotiationError`
    （SIP-PROTO-003 首次生效；双继承 ValueError 保持既有捕获路径/MCP -32005 映射）
  - `validate_rekey_request/response` 校验版本 → False（bool 语义一致）
  - `AgentMessage.from_dict` 信封版本校验 → `MessageSchemaError`（SIP-MSG-001 首次生效），
    lenient-on-absent / strict-on-wrong
  - 单版本协议无降级协商，拒绝先于任何密码学计算
- **README 诚实化** — AEAD 徽章/算法表/dsh 描述按实现更正为 ChaCha20-Poly1305
  （RFC 8439，指向 SPEC D1）；测试计数 239→283；漏洞披露指向 SECURITY.md

### 测试

- 239 → **283 passed**（+15 版本校验 +26 互操作 +3 规范索引机器校验），覆盖率 89%
  保持；pylint 10.00 / mypy 0 errors / black clean / wheel 24 py 核验不变

### 修复

- **CI Security Audit（uv sync --frozen 首跑）** — 切冻结安装后暴露 uv.lock
  锁定的 cryptography 46.0.7 含 PYSEC-2026-3552/3553/3554 + GHSA-537c-gmf6-5ccf
  （修复版 48.0.1~50.0.0；原 requirements 安装每次拉最新版故从未撞上）；
  `uv lock --upgrade-package cryptography` → 50.0.1，跨大版本兼容性经
  239 测试 + pylint 10.00 + mypy + wheel 核验全绿验收

### 变更（封装标准化，零功能改动）

- **布局扁平化（ed1dcac）** — `python/` 嵌套子项目上提根级单包
  （`src/` `tests/` `examples/` `pyproject.toml` `uv.lock` 居根级），对齐
  rf-ops-library 分发库标准；加密核心 git mv 纯 rename 零字节改动，
  239 测试/89% 覆盖率与基线一致；删冗余副本 python/README.md、
  python/CONTRIBUTING.md、python/.gitignore；CI working-directory、
  codecov 路径、lib/index.mjs 提示、README/CONTRIBUTING/AGENTS.md 引用同步
- **依赖锁定统一 uv（1861674）** — dev 依赖迁移 pyproject
  `[dependency-groups]`（并集 requirements-dev.txt，补 CI 在用的 pip-audit），
  删 requirements*.txt 双轨；uv.lock 刷新（62 packages）；CI 重写为
  `uv sync --frozen`（本地=CI 同命令）→ black/pylint/mypy → pytest →
  `uv build` + wheel 清单核验（24 py 全数断言）→ pip-audit；
  pyproject 显式 src-layout `package-dir`
- **外部通路复验** — MCP editable 重装（`python3.11 -m sip_protocol` 寻址
  根级 src/）、dsh 壳 pnpm link 与 lib/index.mjs spawn 链路不受影响

### 修复

- **CI Security Audit（run#83）** — runner 预装 setuptools 79.0.1 触发
  pip-audit `PYSEC-2026-3447`（修复版 83.0.0）审计失败；setuptools 为 runner
  环境自带、非项目依赖（requirements 未引入），与既有 CVE-2026-3219 忽略
  同理（先例 f2a9092），追加 `--ignore-vuln PYSEC-2026-3447`

## [2.1.0] - 2026-09-11

新增：加密文件传输 `filetransfer/`（v1.x `file_transfer/` 评估后按新架构重建，非原样恢复）。
旧实现为"明文分块落盘 + 引用传输"（依赖已删的 schema/ 与共享文件系统假设，chunk 不加密、
全量内存、无流式），与纯加密库定位冲突，故不回搬代码；新实现是 transport 之上的应用层模块，
仅复用现有 crypto 原语，零新增底层依赖。

### 新增

- **`filetransfer/` — 加密文件工件（SIPFT1.0，.sipft）**
  - `pack_file` / `unpack_file`：自包含加密工件，可走任意通道（dsh tool / git / 网盘），离线解包
  - 流式分块加密：逐块读-加密-写，峰值内存与文件大小无关（8MB 文件实测峰值 < 文件一半）
  - HKDF 块独立密钥：header_key 与 chunk_key(file_id, index) 均从 master_key 派生
  - AEAD tag 链防篡改/重排/拼接/截断：每块 AAD 绑定 MAGIC+file_id+块序+前一帧标签，
    链首为认证头部的标签；跨工件移植（同密钥）也被 file_id 绑定拒绝；逐块 fail-fast
  - 认证头部：文件名/MIME/大小等元数据加密且认证；解包端输出路径 basename 清洗（防穿越）
    + 同名冲突自动 "(2)" 重命名；半成品 tmp 文件失败即清理，成功原子替换
  - 大小护栏：默认分块 1MB（1KB..16MB）、单文件 5GB、分块数 65536 上限
- **`crypto/xchacha20_poly1305.py`** — 加解密原语新增可选 `aad` 参数（默认 None，
  既有调用点行为不变；filetransfer tag 链在用）
- **`exceptions.py`** — 新增 `ArtifactCorruptedError`（SIP-FILE-003）；
  `ChunkIntegrityError` 补 `details.chunk_index`（dsh tool 错误响应可见失败块号）
- **dsh 壳 v0.2** — 新注册公用 agent tool `encrypted_file_pack` / `encrypted_file_unpack`
  （与 sip_encrypt/sip_decrypt 同款 defineTool + ctx.tools.register 声明模式，
  一次性 spawn Python，密钥走 stdin；qa-platform profile link 直用）
- **测试 +32**（207 → 239）：往返（空/单块/对齐/非对齐）、乱序拒判、删块拒判、
  整帧交换拒判、跨工件拼接拒判、篡改（密文/标签/头部/魔数）拒判、截断/尾部垃圾拒判、
  错密钥拒判、大文件流式内存上界、路径穿越清洗、冲突重命名、AAD 原语兼容性

### 评估结论（discovery/ 与 schema/ 处置）

- **`file_transfer/` → 恢复（重做）**：大 payload 内存策略 / 块独立密钥 + tag 链整流完整性 /
  自包含工件对 dsh 生态即插即用，均为消息加密（单条全量内存）覆盖不了的增值
- **`discovery/` → 不恢复**：AgentCard/Registry 是服务发现语义，与加密正交
- **`schema/` → 不恢复**：结构化消息信封是应用层框架；filetransfer 自带最小认证 manifest

### 修复

- **v2.0 瘦身残留清理**：`discovery/`、`file_transfer/`、`schema/` 三个目录在源码树
  中仅剩 `__pycache__` 缓存壳（源文件已在 2.0.0 删除，但编译缓存未清且被 gitignore，
  导致 `ls` 验收时误判"模块仍在"）。清理后源码树与 README/AGENTS.md/docs 模块清单
  逐条一致——审计确认无需补写模块文档：残留目录本就无代码，`managers/`/`transport/`
  均为保留核心且已有文档
- **README 徽标补齐**：徽章 3 → 8 枚，对照 harness `python-ci-standard.md` 规范与
  `.github/workflows/ci.yml` 实跑项（Black/Pylint/MyPy/pytest+codecov/pip-audit）
  不虚挂：新增 CI 状态、codecov、cryptography、pytest、code style black；
  lint 工具实为 Black（非 ruff），按规范挂 black 官方徽章
- **README API 参考节补分层依赖一行**：transport → protocol → crypto，managers
  被 protocol/transport 复用——README 单独可读，不必跳转 architecture.md

## [2.0.0] - 2026-09-11

定位重构：从多 Agent 协同协议瘦身为**纯加密库**（encryption-only）。
只保留握手/加解密/Rekey/防重放核心，应用层职责全部移除（git 历史 ≤ v1.4.0 可回溯）。

### 移除（Breaking）

- **非加密模块**: `discovery/`（AgentCard/AgentRegistry）、`file_transfer/`（F1）、
  `schema/`（S1 结构化消息）
- **protocol/ 应用层**: group、group_simple（群组 Double Ratchet）、decision（集体决策）、
  fragment（分片）、offline_queue、persistence（SQLite）、resume（连接恢复）、version（版本协商）
- **transport/ 适配器**: base、openclaw_adapter、hermes_claude_adapter、websocket_adapter
- **javascript/ 早期实现**与根 JS 工具链（package.json/.husky）
- 对应测试 22 个删除，4 个混合测试裁剪；docs 21 个失效文档清洗（保留 5 个对齐新定位）

### 变更

- `transport/__init__.py` 收敛导出（EncryptedChannel/AgentMessage/SipMcpServer）
- `tests/test_e2e_three_party.py` 改写为 MCP 长驻进程模式（修复跨进程 complete 必败的既有损坏），
  硬编码生产 PSK 替换为独立测试 PSK
- 版本号统一至 2.0.0（原 pyproject 1.4.0 与 `__init__` 1.0.0 不一致）
- README 重写为纯加密库定位（算法清单/快速上手/API 参考/安全注意事项 + 徽章三件）
- CI 收敛为 python-ci-standard 档位 A（L1-L5），移除 JS 测试与 JS 性能流水线

### 保障

- MCP 四工具行为不变：黄金基线 diff 逐字节一致（initialize/tools_list schema/全流程/错误码）
- 核心层测试 207 passed 全绿；覆盖率 88%；Pylint 10.00/10；MyPy 零问题；Black clean

## [1.4.0] - 2026-04-25

### 修复

#### 协议修复（P3）
- **Handshake** — 删除 `complete_handshake` 中重复的三重 DH 计算（G9）
- **Resume** — 修复 `verify_session_resume` 签名验证字段 `session_id` → `sender_id`（G8）
- **Nonce** — `set` 改为 `OrderedDict`，保证 FIFO 淘汰顺序（G10）
- **Rekey** — 旧密钥安全擦除（`ctypes.memset`）+ 接收端计数器触发检查（G5/G6）
- **Rekey 闭环** — `process_rekey_response`/`handle_rekey_request` 方法补全，支持完整的 request→response→apply 流程（G4）
- **群组 Double Ratchet** — `chain_key` 推进（`HKDF` message-key → chain-key）+ Skip Ratchet 乱序处理（G1/G2/G3）
- **版本协商** — 添加 4 步协商协议（`version_offer` → `version_response` → 解析）（G7）

### 新增

#### 能力发现（S2 + S4）
- **AgentCard**（src/sip_protocol/discovery/agent_card.py）
  - 自描述数据结构：Capabilities（frozen）、Skill、AuthScheme（frozen）、Endpoints（frozen）
  - AgentRegistration 注册记录
  - to_dict / from_dict 递归序列化往返
- **AgentRegistry**（src/sip_protocol/discovery/registry.py）
  - 注册/注销/查询/心跳续约，内存 + SQLite 双写
  - AgentFilter 按技能/标签/能力/状态过滤查询（OR 语义）
  - check_health 过期标记 offline，cleanup 清理超期离线记录
  - RegistryConfig 可配置 TTL/心跳间隔/离线保留时间
- **RegistryStore**（src/sip_protocol/discovery/registry_store.py）
  - SQLite 持久化层，参数化查询，零 SQL 注入风险
  - find_expired / find_offline_expired 支持定时清理

#### SIP 混合 Schema（S1）
- **SIPEnvelope**（src/sip_protocol/schema/envelope.py）
  - 加密载体数据类，payload 为 bytes，content_type + content_encoding 顶层字段
  - to_dict / from_dict 序列化支持
- **SIPMessage**（src/sip_protocol/schema/message.py）
  - 结构化语义数据类，包含 message_id、sender、recipient、content_type、parts
  - parent_id 在消息层（不在信封层）
  - create_message() 工厂函数 + MessageOptions 参数对象
- **8 种 Part 类型**（src/sip_protocol/schema/parts.py）
  - TextPart, BinaryPart, FileRefPart, FileDataPart, AgentRefPart, TaskPart, ControlPart, ErrorPart
  - FileRefPart（轻量引用）与 FileDataPart（重量级内联）语义分离
- **验证逻辑**（src/sip_protocol/schema/validation.py）
  - validate_message() 入口验证函数
- **工具函数**（src/sip_protocol/schema/_utils.py）
  - _generate_uuid7()、_iso_now() 提取去重

#### 异常类体系（P2）
- **SIPError** 基类（src/sip_protocol/exceptions.py）
  - 基于 dataclass，17 个分层异常，to_dict / from_dict 序列化
  - _register_error 装饰器 + _ERROR_REGISTRY 注册表

#### 文件传输（F1）
- **FileTransferConfig**（src/sip_protocol/file_transfer/config.py）
  - 可配置阈值：inline_threshold, chunk_size, max_file_size
  - should_inline() / validate_size()
- **FileChunk + FileManifest**（src/sip_protocol/file_transfer/manifest.py）
  - 文件块描述（index, size, hash）
  - 文件清单（元数据 + 块列表 + 序列化）
- **LocalFileStore**（src/sip_protocol/file_transfer/store.py）
  - 本地文件系统存储，目录结构化
  - FileStore Protocol 定义接口
  - 过期文件自动清理
- **FileTransferManager**（src/sip_protocol/file_transfer/manager.py）
  - send_file()：小文件内联（FileDataPart），大文件分块引用（FileRefPart）
  - receive_file()：引用解析 → 块校验 → 重组
  - TransferProgress 进度追踪
- **文件传输异常**（追加到 exceptions.py）
  - FileTransferError, ChunkIntegrityError, FileTooLargeError

### 统计

- 测试：630 passed, 36 skipped
- 覆盖率：83%
- Pylint：10.00/10
- Black：通过
- MyPy：0 errors

## [1.3.0] - 2026-04-22

### 新增

#### 消息持久化
- **MessageStore**（src/protocol/persistence.py）
  - 基于SQLite的轻量级消息存储
  - 按发送者/接收者/类型/时间/会话过滤查询
  - 分页支持（limit + offset）
  - 过期消息自动清理（默认30天）
  - 加密消息原样存储
  - 会话列表查询
  - 14个测试全部通过

#### 离线消息队列
- **OfflineQueue**（src/protocol/offline_queue.py）
  - Agent离线时缓存消息，上线后按优先级投递
  - 投递确认/拒绝重入队机制
  - 消息过期清理
  - 最大重试次数（默认3次）
  - 队列状态查询
  - 11个测试全部通过

#### 多Agent加密通信配置
- SIP MCP Server（`python -m sip_protocol --psk <key>`）
  - stdio JSON-RPC 2.0 MCP协议
  - 4个工具：sip_handshake / sip_encrypt / sip_decrypt / sip_rekey
  - 三重DH握手端到端测试通过
- 多Agent配置指南（docs/multi-agent-setup.md）
  - OpenClaw / Hermes / Claude Code 三方适配器配置
  - PSK密钥分发
  - 集体决策/持久化/离线队列使用示例

#### 测试覆盖补充
- session.py: 18% → 100%
- group.py: 43% → 91%
- nonce.py: 60% → 95%
- 新增68个测试

### 变更

#### 包结构重构
- 创建 `sip_protocol` 父包（crypto/protocol/transport/managers）
- 所有模块从 `src.xxx` 迁移至 `sip_protocol.xxx`
- 添加 `__main__.py` 入口：`python -m sip_protocol`
- 删除临时standalone脚本，使用原有 sip_mcp_server.py
- 所有测试导入路径同步更新
- CI配置更新：pylint/mypy/black/coverage 路径指向 `src/sip_protocol/`

### 修复

- JS XChaCha20-Poly1305 Buffer兼容性：@noble/ciphers要求纯Uint8Array，不能传Node.js Buffer
- offline_queue MyPy类型错误：message.get返回Any，用str()包裹
- WebSocket传输层文档标记不一致：架构图从🟡修正为✅

### 文档

- 架构分析报告（docs/sip-protocol-report.md）：87/100 A级
- Agent通信适配度分析：加密层95%，应用层30%
- 演进路线图：短期/中期/长期改进计划
- 与A2A/MCP整合策略

### 统计

- 测试：328 passed, 3 skipped
- 覆盖率：81%
- Pylint：10.00/10
- Black：通过

## [1.2.0] - 2026-04-22

### 新增

#### Agent A → Agent C 适配器
- **HermesClaudeAdapter**（src/transport/hermes_claude_adapter.py）
  - Hermes ↔ Claude Code 通过SIP协议端到端加密通信
  - 架构：Hermes (加密) → OpenClaw sessions_send → Claude Code (解密)
  - 发送前SIP加密+base64编码，接收后base64解码+SIP解密
  - 使用示例（examples/hermes_claude_encrypted.py）

#### 集体决策机制
- **DecisionEngine**（src/protocol/decision.py）
  - 提案创建（Proposal）
  - 投票（Vote）
  - 5种决策策略：简单多数、绝对多数、一致同意、加权投票、一票否决
  - 跨Agent投票（导出/导入）
  - 提案状态管理（pending/approved/rejected/expired/cancelled）
  - 超时自动过期

#### 文档改进
- README算法描述统一为XChaCha20-Poly1305（主）+ AES-256-GCM（备选）
- 添加ASCII架构图
- 添加测试覆盖率数据（207测试，82%覆盖率）
- 联系方式改为GitHub链接
- CHANGELOG拆分为v1.1.0版本

### 修复

- 修复JS示例async/await混用
- 修复hermes_claude_adapter的Pylint/MyPy警告
- WebSocket测试在无websockets库时跳过
- 修复transport层stats.get()的MyPy None+int错误

### 变更

- **测试总数**: 235个（新增24个决策测试 + 7个适配器测试）
- **CI/CD**: 全部通过（Black/Pylint/MyPy/pytest）
- **Hermes评审**: 7.8/10

## [1.1.0] - 2026-04-22

### 新增

#### P2 增强功能
- **协议版本协商**（src/protocol/version.py）
  - 支持 SIP-1.0 ~ SIP-1.3
  - 版本比较和向后兼容检查
- **消息分片支持**（src/protocol/fragment.py）
  - 自动分片大消息（>1MB）
  - 分片重组和超时处理（30秒）
- **连接恢复机制**（src/protocol/resume.py）
  - 会话状态序列化/反序列化
  - 24小时TTL过期检查
  - 消息计数器验证

#### P3 群组加密完善
- **群组管理消息**（9种消息类型）
  - group_init、group_join_ack、group_chain_key、group_chain_key_ack
  - group_add_member、group_join_request、group_leave、group_leave_ack、group_error
- **完整成员管理流程**
  - 成员加入流程（6步，后向保密）
  - 成员离开流程（4步，前向保密）
- **简化群组实现**（src/protocol/group_simple.py）

#### 传输层
- **Agent消息格式**（src/transport/message.py）
  - 3种消息类型：TEXT / ENCRYPTED / CONTROL
  - 4种优先级：LOW / NORMAL / HIGH / URGENT
  - 10种控制动作
- **加密通道**（src/transport/encrypted_channel.py）
  - 完整生命周期：IDLE → HANDSHAKING → ESTABLISHED → CLOSED
  - 握手、加密收发、Rekey、心跳、断开
  - 重放攻击防护
- **OpenClaw适配器**（src/transport/openclaw_adapter.py）
  - 封装加密通道 + OpenClaw CLI集成
  - sessions_spawn / sessions_send适配
  - 三方消息转发

#### 集成测试与性能测试
- **端到端集成测试**（tests/test_integration.py）
  - 完整握手流程
  - 完整生命周期（握手→加密→Rekey→恢复）
- **性能测试**（tests/test_performance.py）
  - 高频消息发送测试
  - 大规模群组测试
  - 压力测试
- **三方通信示例**（examples/three_party_chat.py）
  - Hermes ↔ OpenClaw ↔ Claude Code 加密通信演示

#### 测试
- **Rekey测试用例**（tests/test_rekey.py，9个测试场景）
- **P2功能测试**（tests/test_p2_features.py，18个测试）
- **群组管理测试**（tests/test_group_management.py，13个测试）
- **传输层测试**（tests/test_transport.py，61个测试）
- **测试向量生成脚本**（python/generate_test_vectors.py）

### 修复

#### CI/CD 问题
- 修复 ModuleNotFoundError（添加 __init__.py 文件和 pip install -e .）
- 修复 Black 格式化问题（aes_gcm.py、hkdf.py）
- 修复 Pylint 警告（未使用导入、类型错误等）
- 修复 MyPy 类型错误（transport层24个错误）
- 修复 pyproject.toml 包发现配置

#### 代码质量
- 修复 handshake.py 三重DH重复计算
- 修复 handshake.py 时间戳不一致导致偶发HMAC验证失败
- 修复 group.py 调试 print 语句
- 修复 group_simple.py MyPy 返回类型错误

### 变更

#### 代码质量
- **Pylint评分**: 10.00/10（满分）
- **测试总数**: 117个（Python 111 + JavaScript 6）
- **测试覆盖率**: 82%
- **所有CI/CD检查通过**
  - ✅ Black: 所有文件格式正确
  - ✅ Pylint: 10.00/10
  - ✅ MyPy: 无类型错误
  - ✅ Python测试: 111个测试全部通过
  - ✅ JavaScript测试: 6个测试全部通过

---

## [1.0.0] - 2026-04-21

### 新增

#### 核心功能
- 端到端加密（E2EE）支持
- 基于Signal Double Ratchet的握手协议
- 三重DH密钥交换（X25519）
- XChaCha20-Poly1305对称加密
- HKDF-SHA256密钥派生
- Argon2id PSK哈希
- 群组加密支持（Double Ratchet + Skip Ratchet）
- 防重放攻击（Nonce + Replay Tag）
- 消息认证（HMAC-SHA256）
- PSK验证（防止中间人攻击）
- Rekey密钥轮换

#### 语言实现
- Python 3.11+ 实现完整
- Node.js 20+ 实现完整

#### 文档
- 完整的协议文档（docs/e2ee-protocol.md）
- 群智协同架构文档（docs/agent-chat-architecture.md）
- Python示例代码
- JavaScript示例代码

#### 测试
- Python单元测试
- JavaScript单元测试
- 测试覆盖率报告

### 性能

- DH密钥交换：~0.025ms
- HKDF密钥派生：~0.010ms
- 加密（1KB）：~0.006ms
- 群组加密（顺序）：~0.025ms
- 群组加密（乱序）：~0.050ms

### 安全

- 使用加密安全的随机数生成器
- 使用恒定时间比较（防止时序攻击）
- 支持前向保密
- 支持后向保密

---

## [0.1.0] - 2026-04-20

### 新增

- 基本握手协议
- 消息加密/解密
- Python实现（单文件）
- JavaScript实现（单文件）
- 基本测试

---

## [0.0.1] - 2026-04-19

### 新增

- 项目初始化
- 协议设计文档
- README
- LICENSE
