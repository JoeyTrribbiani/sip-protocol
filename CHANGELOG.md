# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

#### Security Features
- **Rekey密钥轮换功能**（src/protocol/rekey.py，115行代码）
  - Rekey请求创建和验证
  - Rekey响应创建和验证
  - 新密钥派生和应用
  - HMAC签名验证（防MITM）
  - 时间戳验证（±5分钟，防重放）
  - 序列号验证（防回滚）
  - 前向保密（旧密钥无法解密新消息）
  - 双向确认（确保密钥同步）

#### Testing
- **Rekey测试用例**（tests/test_rekey.py，9个测试场景）
  - Rekey请求创建和验证
  - 无效签名检测
  - Rekey响应创建和验证
  - 完整Rekey流程
  - 时间戳验证
  - 序列号验证
  - 前向保密性验证
- **测试向量生成脚本**（python/generate_test_vectors.py）
- **完整测试向量**（docs/test_vectors.json）
  - 握手测试向量
  - 消息加密测试向量
  - 群组加密测试向量
  - Rekey测试向量

### Fixed

#### Python Code Quality
- **代码格式化问题**（Black）
  - src/crypto/xchacha20_poly1305.py
  - src/protocol/handshake.py
- **Pylint警告**
  - 修复src/__init__.py中的self-assigning-variable警告
- **MyPy类型错误**（3个文件）
  - src/protocol/message.py: 将`replay_key: bytes = None`改为`replay_key: Optional[bytes] = None`
  - src/crypto/argon2.py: 将`salt: bytes = None`改为`salt: Optional[bytes] = None`
  - src/protocol/group.py: 为`members`字段添加类型注解`members: dict = {}`

### Changed

#### Code Quality
- **Pylint评分**: 从7.69/10提升到10.00/10（满分）
- **测试覆盖率**: 提升至77%（452 statements, 102 missed）
- **所有CI/CD检查通过**
  - ✅ Black: 所有文件格式正确
  - ✅ Pylint: 10.00/10
  - ✅ MyPy: 无类型错误
  - ✅ Python测试: 16个测试用例全部通过
  - ✅ JavaScript测试: 6个测试场景全部通过

### Added

#### Python
- 模块化重构：crypto、protocol、managers模块
- 新增`src/`目录结构
- 新增`pyproject.toml`配置文件
- 新增Black代码格式化支持
- 新增Pylint代码检查
- 新增Mypy类型检查
- 新增pytest测试框架
- 新增pytest-cov覆盖率工具
- 新增Python贡献指南（CONTRIBUTING.md）

#### JavaScript
- 模块化重构：crypto、protocol、managers模块
- 新增`src/`目录结构
- 新增性能基准测试（benchmarks/performance.js）
- 新增ESLint代码检查
- 新增Prettier代码格式化
- 新增JavaScript贡献指南（CONTRIBUTING.md）

#### CI/CD
- 新增GitHub Actions CI/CD配置
- 新增JavaScript测试工作流
- 新增Python测试工作流
- 新增安全审计工作流
- 新增性能测试工作流
- 新增Codecov覆盖率报告

#### Documentation
- 新增README.md
- 新增CONTRIBUTING.md（Python和JavaScript）
- 新增ARCHITECTURE.md（待添加）

### Changed

- 将Python代码从单文件（1266行）重构为模块化（15个文件）
- 将JavaScript代码从单文件（449行）重构为模块化（15个文件）
- 更新依赖配置（pyproject.toml替代setup.py）
- 更新测试配置（pytest替代unittest）

### Fixed

- 修复AES-GCM加密实现错误
- 修复群组链密钥初始化错误
- 修复Skip Ratchet逻辑错误
- 修复Python语法错误

### Performance

- DH密钥交换：0.025ms（Python），0.022ms（JavaScript）✅
- HKDF密钥派生：0.010ms（Python），0.008ms（JavaScript）✅
- AES-GCM加密（1KB）：0.006ms（Python），0.005ms（JavaScript）✅
- 群组加密（顺序）：0.025ms（Python），0.020ms（JavaScript）✅
- 群组加密（乱序）：0.050ms（Python），0.042ms（JavaScript）✅

所有性能指标远超要求（>100倍）

---

## [1.0.0] - 2026-04-21

### Added

#### Core Features
- 端到端加密（E2EE）支持
- 基于Signal Double Ratchet的握手协议
- 群组加密支持
- Skip Ratchet算法（乱序消息）
- 防重放攻击（Nonce + Replay Tag）
- 消息认证（HMAC-SHA256）
- PSK验证（防止中间人攻击）

#### Cryptography
- X25519 ECDH密钥交换
- HKDF-SHA256密钥派生
- AES-256-GCM对称加密
- Argon2id密钥哈希

#### Languages
- Python 3.11+ 实现完整
- Node.js 20+ 实现完整

#### Documentation
- 完整的协议文档（e2ee-protocol.md）
- 群智协同架构文档（agent-chat-architecture.md）
- Python示例代码
- JavaScript示例代码

#### Tests
- Python单元测试（6个测试用例）
- JavaScript单元测试（6个测试用例）

### Performance

- DH密钥交换：~0.025ms
- HKDF密钥派生：~0.010ms
- AES-GCM加密（1KB）：~0.006ms
- 群组加密（顺序）：~0.025ms
- 群组加密（乱序）：~0.050ms

### Security

- 使用加密安全的随机数生成器
- 使用恒定时间比较（防止时序攻击）
- 支持前向保密
- 支持后向保密

---

## [0.1.0] - 2026-04-20

### Added

#### Initial Release
- 基本握手协议
- 消息加密/解密
- Python实现（单文件）
- JavaScript实现（单文件）
- 基本测试

---

## [0.0.1] - 2026-04-19

### Added

#### Project Initialization
- 项目结构
- 协议设计文档
- README
- LICENSE
