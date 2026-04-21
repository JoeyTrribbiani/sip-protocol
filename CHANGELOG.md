# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
