# Agent群智协议（SIP）v1.0

## 简介

Swarm Intelligence Protocol (SIP) 是一个基于蜂群效应的多Agent协同通信协议，专为多Agent之间的集体决策和群组会话设计。

SIP采用端到端加密（E2EE）技术，基于成熟的Signal Double Ratchet算法，为Agent之间的通信提供银行级安全保障。协议支持一对一私聊、一对多广播、多对多群聊等多种通信模式，完美适配现代AI协同场景。

## 核心特性

### ✅ 银行级安全
- 基于Signal Double Ratchet算法（已被数亿用户验证）
- 端到端加密（E2EE），中间节点无法解密消息
- 前向保密：旧密钥泄露无法解密新消息
- 后向保密：新成员无法解密旧消息

### ✅ 完整的安全机制
- 抗重放攻击（时间戳验证 + 消息计数器 + replay_tag）
- 抗中间人攻击（MITM）（三重DH密钥交换）
- 抗密钥泄露（Argon2id密钥派生，内存困难）
- 完整性保护（HMAC-SHA256签名验证）

### ✅ 支持多种通信模式
- 一对一私聊
- 一对多广播
- 多对多群聊
- 集体决策场景

### ✅ 高性能、低开销
- 握手耗时：~46ms（含Argon2id）
- 消息加密：~0.12ms
- 群组加密：~0.12ms（顺序），~1.2ms（乱序）
- 高并发支持：成功率100%

### ✅ 现代化设计
- 协议版本协商（向后兼容）
- 消息分片支持（大文件传输）
- 连接恢复机制（无缝重连）
- 扩展字段预留（未来功能扩展）

## 应用场景

- 🤖 多Agent协同系统
- 🌐 分布式AI集群
- 👥 Agent群组会话
- 🤝 集体决策协议
- 🔐 端到端加密通信
- 📡 实时安全消息传输

## 快速开始

### Python实现

```bash
# 克隆仓库
git clone https://github.com/JoeyTrribbiani/sip-protocol.git
cd sip-protocol/python

# 安装依赖
pip install -r requirements.txt

# 运行示例（完整握手流程）
python examples/basic_handshake.py

# 运行测试套件
python tests/test_sip_protocol.py
```

### Node.js实现

```bash
# 克隆仓库
git clone https://github.com/JoeyTrribbiani/sip-protocol.git
cd sip-protocol/javascript

# 安装依赖
npm install

# 运行示例（完整握手流程）
npm run example:handshake

# 运行测试套件
npm test
```

## 性能

- 握手耗时：~46ms（含Argon2id）
- 消息加密：~0.12ms
- 群组加密：~0.12ms（顺序），~1.2ms（乱序）
- 高并发：成功率100%

详细性能数据请参见 [性能基准测试](docs/e2ee-protocol.md#性能基准测试)。

## 安全性

- 加密算法：X25519, XChaCha20-Poly1305, HKDF-SHA256, Argon2id
- 基于成熟的Signal Double Ratchet算法
- 前向保密和后向保密
- 抗重放攻击和篡改

详细安全分析请参见 [协议文档](docs/e2ee-protocol.md)。

## 常见问题

参见 [FAQ](docs/e2ee-protocol.md#常见问题解答faq)。

## 测试

### 测试套件

**Python测试：**
- 测试文件：`tests/test_sip_protocol.py`
- 测试用例：6个
  1. 基本握手流程
  2. 消息加密解密
  3. Nonce管理（防重放）
  4. 时间戳验证（防重放）
  5. 防重放标签（replay_tag）
  6. 群组加密

**Node.js测试：**
- 测试文件：`javascript/tests/test_sip_protocol.js`
- 测试用例：6个
  1. 基本握手流程
  2. 消息加密解密
  3. Nonce管理（防重放）
  4. 防重放标签（replay_tag）
  5. 群组加密
  6. 跳跃密钥（Skip Ratchet）

### 运行测试

```bash
# Python测试
cd sip-protocol/python
python tests/test_sip_protocol.py

# Node.js测试
cd sip-protocol/javascript
npm test
```

## 示例

### Python示例

- 文件：`examples/basic_handshake.py`
- 功能：完整的端到端握手流程
- Agent A和Agent B建立加密通道
- 三重DH密钥交换
- PSK哈希和密钥派生

### Node.js示例

- 文件：`javascript/examples/basic_handshake.js`
- 功能：完整的端到端握手流程
- Agent A和Agent B建立加密通道
- 三重DH密钥交换
- PSK哈希和密钥派生

## 贡献

欢迎贡献代码、报告问题或提出建议！

参见 [CONTRIBUTING.md](CONTRIBUTING.md)。

## 许可证

Apache License 2.0

## 致谢

感谢 [Signal Protocol](https://signal.org/docs/) 的启发。
