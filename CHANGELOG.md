# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
