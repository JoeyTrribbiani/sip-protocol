# SIP协议架构设计

> Swarm Intelligence Protocol - 基于Signal Double Ratchet的多Agent端到端加密通信协议

---

## 📋 目录

- [概述](#概述)
- [架构原则](#架构原则)
- [分层架构](#分层架构)
- [模块设计](#模块设计)
- [依赖关系](#依赖关系)
- [数据流](#数据流)
- [扩展性](#扩展性)

---

## 概述

SIP协议采用分层架构设计，从底层加密原语到高层应用协议，每一层都职责明确、易于维护。

**核心设计原则：**
- 单一职责：每个模块只负责一个功能
- 高内聚低耦合：模块内部紧密相关，模块之间松散耦合
- 接口稳定：对外API保持稳定，内部实现可替换
- 可测试性：每个模块都可独立测试

---

## 架构原则

### 1. 分层设计

```
┌─────────────────────────────────────┐
│        应用层（Application）          │  群组管理、会话管理
├─────────────────────────────────────┤
│        协议层（Protocol）            │  握手、消息、群组协议
├─────────────────────────────────────┤
│        加密层（Crypto）              │  DH、HKDF、AES-GCM、Argon2
├─────────────────────────────────────┤
│        原语层（Primitive）           │  随机数、哈希、MAC
└─────────────────────────────────────┘
```

### 2. 模块化设计

```
src/
├── crypto/           # 加密层（4个模块）
│   ├── dh.js         # DH密钥交换
│   ├── hkdf.js       # HKDF密钥派生
│   ├── aes-gcm.js    # AES-GCM加密
│   └── argon2.js     # PSK哈希
├── protocol/         # 协议层（3个模块）
│   ├── handshake.js  # 握手协议
│   ├── message.js    # 消息协议
│   └── group.js      # 群组协议
└── managers/         # 管理层（3个模块）
    ├── nonce.js      # Nonce管理器
    ├── session.js    # 会话状态
    └── group.js      # 群组管理器
```

### 3. 统一导出

```
src/index.js
├── 导出crypto模块（6个函数）
├── 导出protocol模块（9个函数）
└── 导出managers模块（3个类）
```

---

## 分层架构

### 1. 加密层（Crypto Layer）

**职责：** 提供底层加密原语

**模块：**
- `dh.js`：X25519 ECDH密钥交换
- `hkdf.js`：HKDF密钥派生
- `aes-gcm.js`：AES-256-GCM加密/解密
- `argon2.js`：Argon2id密钥哈希

**特点：**
- 无状态：纯函数，不维护状态
- 可替换：可以更换不同的加密库
- 性能优化：最频繁的操作在最底层

### 2. 协议层（Protocol Layer）

**职责：** 实现SIP协议的核心流程

**模块：**
- `handshake.js`：握手协议（三步握手）
- `message.js`：消息加密/解密
- `group.js`：群组加密（Double Ratchet + Skip Ratchet）

**特点：**
- 有状态：维护协议状态
- 独立性：每个协议模块独立运行
- 可扩展：预留扩展字段

### 3. 管理层（Manager Layer）

**职责：** 管理状态和资源

**模块：**
- `nonce.js`：Nonce管理器（防重放）
- `session.js`：会话状态管理
- `group.js`：群组管理器（成员管理）

**特点：**
- 状态管理：维护长期状态
- 资源清理：自动清理过期资源
- 线程安全：支持并发访问

---

## 模块设计

### Crypto模块

#### dh.js

```javascript
// 输入
privateKey: KeyObject  // 私钥
publicKey: KeyObject   // 公钥

// 输出
sharedSecret: Buffer  // 共享密钥（32字节）
```

**算法：** X25519 ECDH

**性能：** < 10ms

**安全：**
- 使用标准X25519曲线
- 每次密钥交换都生成新的临时密钥对

#### hkdf.js

```javascript
// 输入
ikm: Buffer     // 输入密钥材料
salt: Buffer    // 盐（16字节）
info: Buffer    // 上下文信息
length: Number  // 输出长度（字节）

// 输出
key: Buffer     // 派生的密钥
```

**算法：** HKDF-SHA256

**性能：** < 5ms

**安全：**
- 每次派生使用不同的盐
- 支持多个独立的派生

#### aes-gcm.js

```javascript
// 加密输入
key: Buffer     // 加密密钥（32字节）
plaintext: Buffer // 明文
iv: Buffer      // 初始化向量（12字节）

// 加密输出
ciphertext: Buffer // 密文
authTag: Buffer    // 认证标签（16字节）

// 解密输入
key: Buffer      // 解密密钥（32字节）
ciphertext: Buffer// 密文
iv: Buffer       // 初始化向量（12字节）
authTag: Buffer  // 认证标签（16字节）

// 解密输出
plaintext: Buffer // 明文
```

**算法：** AES-256-GCM

**性能：** < 1ms（1KB）

**安全：**
- 认证加密：同时保证机密性和完整性
- 每次加密使用不同的IV
- 16字节认证标签

#### argon2.js

```javascript
// 输入
psk: Buffer     // 预共享密钥
salt: Buffer    // 盐（16字节，可选）

// 输出
pskHash: Buffer // PSK哈希（32字节）
salt: Buffer    // 使用的盐
```

**算法：** Argon2id

**参数：**
- timeCost: 3
- memoryCost: 64MB
- parallelism: 4
- hashLen: 32

**安全：**
- 抗GPU/ASIC攻击
- 内存困难
- 可调参数

---

### Protocol模块

#### handshake.js

**流程：**

```
Agent A (发起方)              Agent B (响应方)
    |                              |
    |---- Handshake_Hello -------->|
    |  (ephemeral_pub, nonce)     |
    |                              |
    |<--- Handshake_Auth ----------|
    |  (ephemeral_pub, nonce)     |
    |                              |
    |------ Handshake_Complete ---->|
    |  (encrypted_confirmation)    |
    |                              |
```

**状态转换：**

```
INIT → WAIT_HELLO → WAIT_AUTH → ESTABLISHED
```

**输出：**
- `sessionKeys`：会话密钥（encryptionKey、authKey、replayKey）
- `sessionState`：会话状态

#### message.js

**消息格式：**

```json
{
  "version": "SIP-1.0",
  "type": "encrypted_message",
  "sender_id": "agent-a",
  "message_counter": 123,
  "nonce": "base64_encoded_iv",
  "ciphertext": "base64_encoded_ciphertext",
  "auth_tag": "base64_encoded_auth_tag",
  "timestamp": 1713751200000
}
```

**验证：**
- 版本检查
- 消息计数器验证
- 认证标签验证
- 时间戳验证（±5分钟）

#### group.js

**Double Ratchet算法：**

```
Sending Chain:
  chain_key_n → message_key_n, chain_key_{n+1}

Receiving Chain:
  chain_key_n → message_key_n, chain_key_{n+1}
  (支持Skip Ratchet预先生成跳跃密钥）
```

**Skip Ratchet算法：**

```
收到消息N（期望M）：
  for i in [M, M+1, ..., N-1]:
    预生成跳跃密钥 skip_keys[i]
  
  使用 skip_keys[N] 解密消息N
```

**消息格式：**

```json
{
  "version": "SIP-1.0",
  "type": "group_message",
  "timestamp": 1713751200000,
  "sender_id": "agent-a",
  "group_id": "group:123",
  "message_number": 456,
  "iv": "base64_encoded_iv",
  "ciphertext": "base64_encoded_ciphertext",
  "auth_tag": "base64_encoded_auth_tag",
  "sender_signature": "base64_encoded_signature"
}
```

---

### Manager模块

#### nonce.js

**职责：**
- 生成唯一Nonce
- 检查Nonce是否已使用
- 防止重放攻击

**数据结构：**

```
usedNonces: Set<String>
```

**策略：**
- 生成随机Nonce（24字节）
- 存储已使用的Nonce（Hex字符串）
- 限制大小：最多1000个

#### session.js

**职责：**
- 序列化/反序列化会话状态
- 更新最后活动时间

**数据结构：**

```
{
  version: String,
  agentId: String,
  remoteAgentId: String,
  remotePublicKey: String,
  encryptionKey: Buffer,
  authKey: Buffer,
  replayKey: Buffer,
  messageCounter: Number,
  pskHash: Buffer,
  salt: Buffer,
  localNonce: Buffer,
  remoteNonce: Buffer,
  createdAt: Number,
  lastActivityAt: Number
}
```

**序列化格式：**
- JSON字符串
- Base64编码二进制数据

#### group.js

**职责：**
- 管理群组成员
- 管理群组链密钥
- 处理成员加入/离开

**数据结构：**

```
{
  groupId: String,
  rootKey: Buffer,
  members: Map<memberId, {
    sending_chain: { chainKey, messageNumber, skipKeys },
    receiving_chain: { chainKey, messageNumber, skipKeys }
  }>
}
```

---

## 依赖关系

### 模块依赖图

```
┌─────────────┐
│  managers/  │
│  nonce.js   │
│  session.js │
│  group.js   │
└──────┬──────┘
       │
       ▼
┌─────────────┐
│  protocol/  │
│ handshake.js│
│  message.js │
│  group.js   │
└──────┬──────┘
       │
       ▼
┌─────────────┐
│   crypto/   │
│   dh.js     │
│   hkdf.js   │
│  aes-gcm.js │
│  argon2.js  │
└─────────────┘
```

**依赖规则：**
- 上层可以调用下层
- 下层不能调用上层
- 同层模块可以相互调用（如protocol/group.js调用protocol/message.js）

### 语言依赖

**Python：**
```
cryptography>=41.0.0  # X25519, HKDF, AES-GCM
argon2-cffi>=23.0.0    # Argon2id
```

**JavaScript (Node.js):**
```
argon2>=0.31.0  # Argon2id
crypto           # 内置X25519, HKDF, AES-GCM
```

---

## 数据流

### 握手流程

```
Agent A                           Agent B
   |                                |
   | 1. generateKeyPair()           |
   | 2. generateNonce()             |
   | 3. hashPsk(psk)               |
   |                                |
   | -- Handshake_Hello ----------->|
   |    { ephemeral_pub, nonce }    |
   |                                |
   |                    1. generateKeyPair()
   |                    2. generateNonce()
   |                    3. hashPsk(psk)
   |                    4. dhExchange(priv, pub)
   |                    5. deriveKeys()
   |                                |
   | <----- Handshake_Auth ---------|
   |    { ephemeral_pub, nonce }    |
   |                                |
   | 4. dhExchange(priv, pub)       |
   | 5. deriveKeys()                |
   | 6. verifySignature()          |
   |                                |
   | ----- Handshake_Complete ------>|
   |    { encrypted_confirmation }   |
   |                                |
```

### 消息加密流程

```
1. encryptMessage(encryptionKey, plaintext, senderId, counter)
   └─> aesGCM.encrypt(key, plaintext, iv)
       └─> { ciphertext, authTag }

2. constructMessage()
   └─> { version, sender_id, message_counter, nonce, ciphertext, auth_tag, timestamp }

3. send()
   └─> transmit(message)
```

### 消息解密流程

```
1. receive(message)
   └─> validateVersion()
       └─> validateTimestamp()
       └─> validateCounter()

2. decryptMessage(encryptionKey, message)
   └─> aesGCM.decrypt(key, ciphertext, iv, authTag)
       └─> plaintext

3. verifySignature()
   └─> hmac.compare_digest(expected, actual)
```

### 群组加密流程

```
1. sendGroupMessage(plaintext, senderId)
   └─> hkdf(chainKey, "", "message-key", 32)
       └─> messageKey

2. aesGCM.encrypt(messageKey, plaintext, iv)
   └─> { ciphertext, authTag }

3. hmac(messageKey, ciphertext)
   └─> senderSignature

4. constructGroupMessage()
   └─> { version, sender_id, group_id, message_number, iv, ciphertext, auth_tag, sender_signature }

5. updateChainKey()
   └─> hkdf(chainKey, "", "chain-key", 32)
       └─> nextChainKey
```

---

## 扩展性

### 1. 支持新的加密算法

**修改点：** `crypto/` 目录

**示例：** 添加ChaCha20-Poly1305

```javascript
// crypto/chacha20.js
export function encryptChaCha20(key, plaintext, nonce) {
  // 实现
}

export function decryptChaCha20(key, ciphertext, nonce) {
  // 实现
}
```

### 2. 支持新的协议

**修改点：** `protocol/` 目录

**示例：** 添加双因素认证协议

```javascript
// protocol/two-factor.js
export function initiateTwoFactorAuth() {
  // 实现
}

export function verifyTwoFactorAuth() {
  // 实现
}
```

### 3. 支持新的管理器

**修改点：** `managers/` 目录

**示例：** 添加密钥轮换管理器

```javascript
// managers/key-rotation.js
export class KeyRotationManager {
  constructor() {
    // 实现
  }

  rotateKeys() {
    // 实现
  }
}
```

### 4. 支持多语言

**修改点：** 新的语言目录

**示例：** 添加Go语言实现

```
go/
├── crypto/
├── protocol/
└── managers/
```

---

## 总结

SIP协议的架构设计遵循了分层、模块化、单一职责的原则，使得协议易于理解、实现和维护。

**关键优势：**
- 清晰的分层结构
- 明确的模块划分
- 松散的依赖关系
- 良好的扩展性
- 完整的测试覆盖

**下一步：**
- 完善文档体系
- 添加更多语言支持（Go、Rust、C++）
- 性能优化
- 安全审计
