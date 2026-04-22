# SIP协议 - Swarm Intelligence Protocol

> 基于Signal Double Ratchet的多Agent端到端加密通信协议

[![CI/CD](https://github.com/JoeyTrribbiani/sip-protocol/workflows/CI%2FCD/badge.svg)](https://github.com/JoeyTrribbiani/sip-protocol/actions)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

---

## 📋 目录

- [概述](#概述)
- [特性](#特性)
- [安装](#安装)
- [快速开始](#快速开始)
- [API文档](#api文档)
- [性能](#性能)
- [安全](#安全)
- [贡献](#贡献)
- [许可证](#许可证)

---

## 概述

SIP协议（Swarm Intelligence Protocol）是一个基于Signal Double Ratchet算法的端到端加密通信协议，专为多Agent之间的安全通信设计。

**核心理念：**
- 群策群力：多个Agent协同工作，集体智慧
- 众谋寡断：集体谋划，高效决策
- 涌现智能：群体协作，超越个体

**设计原则：**
- 简单性：易于理解和实现
- 安全性：现代加密算法，前向保密
- 可调试性：JSON消息格式，便于日志分析
- 可扩展性：预留扩展字段

---

## 特性

### 核心功能
- ✅ **端到端加密**：消息只有发送方和接收方能解密
- ✅ **前向保密**：密钥泄露不影响历史消息
- ✅ **抗重放攻击**：防止重复消息
- ✅ **抗篡改**：消息完整性保护
- ✅ **身份验证**：PSK防止中间人攻击

### 群组功能
- ✅ **群组加密**：基于Double Ratchet的群组通信
- ✅ **Skip Ratchet**：支持乱序消息
- ✅ **动态成员**：支持成员加入和离开
- ✅ **自动密钥更新**：成员变化时自动更新根密钥

### 多语言支持
- ✅ **Python 3.11+**：完整实现（1266行）
- ✅ **Node.js 20+**：完整实现（15个模块）
- ✅ **API一致**：不同语言提供相同的API

### 架构概览

```
┌─────────────────────────────────────────────┐
│              SIP Protocol Stack             │
├─────────────────────────────────────────────┤
│  Transport Layer                            │
│  ┌─────────────┐ ┌──────────┐ ┌───────────┐│
│  │OpenClaw API │ │WebSocket │ │MCP Server ││
│  └──────┬──────┘ └────┬─────┘ └─────┬─────┘│
├─────────┼─────────────┼─────────────┼────────┤
│  Protocol Layer                             │
│  ┌──────────┐ ┌────────┐ ┌───────────────┐ │
│  │Handshake │ │ Rekey  │ │Version/       │ │
│  │(TripleDH)│ │ Ratchet│ │Fragment/Resume│ │
│  └────┬─────┘ └───┬────┘ └───────┬───────┘ │
├───────┼───────────┼──────────────┼──────────┤
│  Crypto Layer                               │
│  ┌───────────────┐ ┌─────┐ ┌─────────────┐│
│  │XChaCha20      │ │HKDF │ │Argon2id     ││
│  │AES-256-GCM    │ │HMAC │ │X25519 DH    ││
│  └───────────────┘ └─────┘ └─────────────┘│
└─────────────────────────────────────────────┘
```

---

## 安装

### Python

```bash
# 安装依赖
pip install -r python/requirements.txt

# 安装开发依赖
pip install -r python/requirements-dev.txt
```

### JavaScript (Node.js)

```bash
cd javascript
npm install
```

---

## 快速开始

### Python示例

```python
import sip_protocol

# 1. 生成密钥对
private_key, public_key = sip_protocol.generate_keypair()

# 2. DH密钥交换
shared_secret = sip_protocol.dh_exchange(private_key, public_key)

# 3. 派生密钥
psk_hash, _ = sip_protocol.hash_psk(b"your-psk")
encryption_key, auth_key, replay_key = sip_protocol.derive_keys(
    shared_secret, psk_hash, nonce_a, nonce_b
)

# 4. 加密消息
message = sip_protocol.encrypt_message(
    encryption_key, "Hello, SIP!", "agent-a", 1
)

# 5. 解密消息
plaintext = sip_protocol.decrypt_message(encryption_key, message)
print(plaintext)  # "Hello, SIP!"
```

### JavaScript示例

```javascript
const {
  generateKeyPair,
  dhExchange,
  hashPsk,
  deriveKeys,
  encryptMessage,
  decryptMessage
} = require('./src/index.js');

// 1. 生成密钥对
const { privateKey, publicKey } = generateKeyPair();

// 2. DH密钥交换
const sharedSecret = dhExchange(privateKey, publicKey);

// 3. 派生密钥
const { pskHash } = hashPsk(Buffer.from('your-psk'));
const { encryptionKey, authKey, replayKey } = deriveKeys(
  sharedSecret, pskHash, nonceA, nonceB
);

// 4. 加密消息
const message = encryptMessage(
  encryptionKey, 'Hello, SIP!', 'agent-a', 1
);

// 5. 解密消息
const plaintext = decryptMessage(encryptionKey, message);
console.log(plaintext); // "Hello, SIP!"
```

### 群组加密示例

```python
import sip_protocol

# 1. 初始化群组
root_key = b"..."
group_manager = sip_protocol.GroupManager("group:123", root_key)

# 2. 添加成员
chains = group_manager.initialize_group_chains(
    ["agent-a", "agent-b", "agent-c"], root_key
)

# 3. 发送消息
message = group_manager.send_group_message(
    "Hello, Group!", chains["agent-a"]["sending_chain"]
)

# 4. 接收消息
plaintext = group_manager.receive_group_message(
    message, chains["agent-b"]["receiving_chain"]
)
```

---

## API文档

### 核心API

#### Python

- `generate_keypair()` - 生成X25519密钥对
- `dh_exchange(private_key, public_key)` - ECDH密钥交换
- `hash_psk(psk, salt)` - Argon2id哈希
- `derive_keys(shared_secret, psk_hash, nonce_a, nonce_b)` - 派生会话密钥
- `encrypt_message(encryption_key, plaintext, sender_id, counter)` - 加密消息
- `decrypt_message(encryption_key, message)` - 解密消息
- `generate_replay_tag(replay_key, sender_id, counter)` - 生成防重放标签

#### JavaScript

- `generateKeyPair()` - 生成X25519密钥对
- `dhExchange(privateKey, publicKey)` - ECDH密钥交换
- `hashPsk(psk, salt)` - Argon2id哈希
- `deriveKeys(sharedSecret, pskHash, nonceA, nonceB)` - 派生会话密钥
- `encryptMessage(encryptionKey, plaintext, senderId, counter)` - 加密消息
- `decryptMessage(encryptionKey, message)` - 解密消息
- `generateReplayTag(replayKey, senderId, counter)` - 生成防重放标签

### 群组API

- `GroupManager(groupId, rootKey)` - 创建群组管理器
- `initialize_group_chains(members, rootKey)` - 初始化群组链密钥
- `send_group_message(plaintext, sending_chain)` - 发送群组消息
- `receive_group_message(message, receiving_chain)` - 接收群组消息

完整API文档请参考：
- [Python API](./docs/python-api.md)
- [JavaScript API](./docs/javascript-api.md)

---

## 性能

### 性能指标

| 指标 | 要求 | 实际（Python） | 实际（JavaScript） | 状态 |
|------|------|---------------|-------------------|------|
| DH密钥交换 | < 10ms | ~0.025ms | ~0.022ms | ✅ |
| HKDF密钥派生 | < 5ms | ~0.010ms | ~0.008ms | ✅ |
| XChaCha20-Poly1305加密（1KB） | < 1ms | ~0.006ms | ~0.005ms | ✅ |
| 群组加密（顺序） | < 0.5ms | ~0.025ms | ~0.020ms | ✅ |
| 群组加密（乱序） | < 2ms | ~0.050ms | ~0.042ms | ✅ |

### 测试覆盖率

- **测试套件**: 207个测试用例
- **覆盖率**: 82% (Python)
- **代码质量**: Pylint 9.99/10, MyPy 0 errors

**最新测试运行结果** (2026-04-22):
```
$ python3 -m pytest tests/ -v
============================= 207 passed in 4.47s ==============================
```

### 性能测试

```bash
# JavaScript性能测试
cd javascript
npm run test:performance
```

### 性能指标说明

所有性能指标均基于本地测试环境（Apple M2, 16GB RAM）
- 测试方法：连续运行1000次取平均值
- 测试数据：使用随机生成的测试向量
- 实际性能可能因硬件和环境而异

---

## 安全

### 安全特性

- ✅ **端到端加密**：使用XChaCha20-Poly1305（主）+ AES-256-GCM（备选）
- ✅ **前向保密**：密钥定期更新
- ✅ **时序攻击防护**：使用恒定时间比较
- ✅ **重放攻击防护**：Nonce + Replay Tag
- ✅ **中间人攻击防护**：PSK验证
- ✅ **侧信道攻击防护**：使用加密安全的随机数

### 安全审计

- 定期进行安全审计
- 使用`npm audit`和`pip-audit`检测依赖漏洞
- 使用`dependabot`自动更新依赖

---

## 贡献

我们欢迎所有形式的贡献！

### 贡献指南

- [Python贡献指南](./python/CONTRIBUTING.md)
- [JavaScript贡献指南](./javascript/CONTRIBUTING.md)

### 开发流程

1. Fork项目
2. 创建功能分支
3. 编写代码和测试
4. 提交Pull Request

### 代码规范

- Python: PEP 8 + Black + Pylint + Mypy
- JavaScript: ESLint + Prettier

---

## 许可证

Apache License 2.0

详见 [LICENSE](./LICENSE)

---

## 联系方式

- GitHub Issues: https://github.com/JoeyTrribbiani/sip-protocol/issues
- GitHub: [JoeyTrtribbiani](https://github.com/JoeyTrtribbiani/sip-protocol)

---

## 致谢

- Signal Protocol: https://signal.org/docs/
- X25519: https://cr.yp.to/ecdh.html
- AES-GCM: https://en.wikipedia.org/wiki/Galois/Counter_Mode
- Argon2: https://github.com/P-H-C/phc-winner-argon2
