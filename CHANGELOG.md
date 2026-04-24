# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
