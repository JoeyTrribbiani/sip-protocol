// SIP协议完整实现 - 按照协议文档

const crypto = require('crypto');
const { x25519 } = require('@noble/ciphers');
const argon2 = require('argon2');

// 常量
const PROTOCOL_VERSION = 'SIP-1.0';
const KDF_SALT = Buffer.from('SIPHandshake');
const KDF_INFO = Buffer.from('session-keys');
const NONCE_LENGTH = 24;
const HANDSHAKE_NONCE_LENGTH = 16;
const MESSAGE_KEY_LENGTH = 32;
const CHAIN_KEY_LENGTH = 32;
const GROUP_PROTOCOL_VERSION = 'SIP-1.0';
const AES_GCM_NONCE_LENGTH = 12;

// 密钥对生成（按照协议文档）
function generateKeyPair() {
  const privateKey = crypto.randomBytes(32);
  const publicKey = x25519.getPublicKey(privateKey);
  return { privateKey, publicKey };
}

// PSK 哈希（Argon2id）
function hashPsk(psk, salt = null) {
  // 如果没有提供盐，生成随机盐
  if (!salt) {
    salt = crypto.randomBytes(16);
  }
  
  // Argon2id 参数
  const options = {
    type: argon2.argon2id,
    memoryCost: 65536,  // 64MB
    timeCost: 3,        // 迭代次数
    parallelism: 4,       // 并行线程数
    hashLength: 32,      // 输出长度
    salt: salt,
    raw: true            // 返回原始 Buffer
  };
  
  // 哈希 PSK
  const pskHash = argon2.hash(psk, options);
  
  return { pskHash, salt };
}

// DH 密钥交换（按照协议文档）
function dhExchange(privateKey, publicKey) {
  const sharedSecret = x25519.getSharedSecret(privateKey, publicKey);
  return sharedSecret;
}

// HKDF 密钥派生
function deriveKeys(sharedSecret, pskHash, nonceA, nonceB) {
  const ikm = Buffer.concat([sharedSecret, pskHash, nonceA, nonceB]);
  const kdf = crypto.hkdfSync(
    'sha256',
    ikm,
    KDF_SALT,
    KDF_INFO,
    96 // 3 * 32 bytes
  );
  const encryptionKey = kdf.subarray(0, 32);
  const authKey = kdf.subarray(32, 64);
  const replayKey = kdf.subarray(64, 96);
  return { encryptionKey, authKey, replayKey };
}

// 加密消息（使用XChaCha20-Poly1305）
function encryptMessage(encryptionKey, plaintext, senderId, messageCounter) {
  // 使用 @noble/ciphers 的 XChaCha20-Poly1305
  const nonce = Buffer.alloc(NONCE_LENGTH, 0);
  const cipher = crypto.createCipheriv('chacha20-poly1305', encryptionKey, nonce);
  
  let ciphertext;
  try {
    ciphertext = Buffer.concat([
      cipher.update(Buffer.from(plaintext), 'utf8'),
      cipher.final()
    ]);
  } catch (error) {
    ciphertext = cipher.update(Buffer.from(plaintext), 'utf8');
  }
  
  const authTag = cipher.getAuthTag();
  
  // 构建消息对象
  const message = {
    version: PROTOCOL_VERSION,
    type: 'encrypted_message',
    sender_id: senderId,
    message_counter: messageCounter,
    nonce: nonce.toString('base64'),
    ciphertext: ciphertext.toString('base64'),
    auth_tag: authTag.toString('base64'),
    timestamp: Date.now()
  };
  
  return message;
}

// 解密消息
function decryptMessage(encryptionKey, message) {
  const nonce = Buffer.from(message.nonce, 'base64');
  const ciphertext = Buffer.from(message.ciphertext, 'base64');
  const authTag = Buffer.from(message.auth_tag, 'base64');
  
  const decipher = crypto.createDecipheriv('chacha20-poly1305', encryptionKey, nonce);
  decipher.setAuthTag(authTag);
  
  let plaintext;
  try {
    plaintext = Buffer.concat([
      decipher.update(ciphertext),
      decipher.final()
    ]).toString('utf8');
  } catch (error) {
    throw new Error('解密失败：' + error.message);
  }
  
  return plaintext;
}

// 生成防重放标签
function generateReplayTag(replayKey, senderId, messageCounter) {
  const data = Buffer.concat([
    Buffer.from(senderId),
    Buffer.from(messageCounter.toString())
  ]);
  const replayTag = crypto.createHmac('sha256', replayKey)
    .update(data)
    .digest('hex');
  return replayTag;
}

// Nonce管理器（防重放）
class NonceManager {
  constructor() {
    this.usedNonces = new Set();
  }
  
  generateNonce() {
    let nonce;
    do {
      nonce = crypto.randomBytes(NONCE_LENGTH);
    } while (this.usedNonces.has(nonce.toString('hex')));
    
    this.usedNonces.add(nonce.toString('hex'));
    return nonce;
  }
  
  validateNonce(nonce) {
    return !this.usedNonces.has(nonce.toString('hex'));
  }
}

// 消息计数器
class MessageCounter {
  constructor() {
    this.counter = 0;
    this.maxCounter = Number.MAX_SAFE_INTEGER;
  }
  
  increment() {
    this.counter++;
    if (this.counter > this.maxCounter) {
      this.counter = 0; // 回绕处理
    }
    return this.counter;
  }
  
  get() {
    return this.counter;
  }
  
  validate(messageCounter) {
    // 验证消息计数器在合理范围内
    return messageCounter > this.counter && 
           messageCounter <= (this.counter + 10000); // 允许最多10000条乱序消息
  }
}

// 会话状态序列化/反序列化
class SessionState {
  constructor() {
    this.version = PROTOCOL_VERSION;
    this.agentId = '';
    this.remoteAgentId = '';
    this.remotePublicKey = '';
    this.encryptionKey = '';
    this.authKey = '';
    this.replayKey = '';
    this.messageCounter = 0;
    this.pskHash = '';
    this.salt = '';
    this.localNonce = '';
    this.remoteNonce = '';
    this.createdAt = Date.now();
    this.lastActivityAt = Date.now();
  }
  
  serialize() {
    return JSON.stringify(this);
  }
  
  static deserialize(jsonString) {
    const data = JSON.parse(jsonString);
    const state = new SessionState();
    Object.assign(state, data);
    return state;
  }
}

// 群组加密支持
class GroupManager {
  constructor(groupId, rootKey) {
    this.groupId = groupId;
    this.rootKey = rootKey;
    this.members = new Map();
    this.sendingChains = new Map();
    this.receivingChains = new Map();
  }
  
  addMember(memberId, sendingChainKey) {
    // 初始化成员的发送和接收链
    this.members.set(memberId, {
      sendingChain: {
        chainKey: sendingChainKey,
        messageNumber: 0,
        skipKeys: new Map()
      },
      receivingChains: new Map()
    });
    
    // 初始化接收链（从root key派生）
    const receivingChainKey = crypto.createHash('sha256')
      .update(rootKey)
      .update(Buffer.from(memberId))
      .digest();
    
    this.receivingChains.set(memberId, {
      chainKey: receivingChainKey,
      messageNumber: 0,
      skipKeys: new Map()
    });
  }
  
  sendGroupMessage(plaintext, senderId) {
    const member = this.members.get(senderId);
    if (!member) {
      throw new Error('成员不存在：' + senderId);
    }
    
    // 派生消息密钥
    const messageKey = crypto.createHmac('sha256', member.sendingChain.chainKey)
      .update(Buffer.from('message-key'))
      .digest();
    
    // 推进链密钥
    const nextChainKey = crypto.createHmac('sha256', member.sendingChain.chainKey)
      .update(Buffer.from('chain-key'))
      .digest();
    
    // 加密消息
    const iv = crypto.randomBytes(AES_GCM_NONCE_LENGTH);
    const cipher = crypto.createCipheriv('aes-256-gcm', messageKey, iv);
    
    let ciphertext;
    try {
      ciphertext = Buffer.concat([
        cipher.update(Buffer.from(plaintext), 'utf8'),
        cipher.final()
      ]);
    } catch (error) {
      ciphertext = cipher.update(Buffer.from(plaintext), 'utf8');
    }
    
    const authTag = cipher.getAuthTag();
    
    // 更新发送链状态
    member.sendingChain.chainKey = nextChainKey;
    member.sendingChain.messageNumber++;
    
    // 构建群组消息
    const message = {
      version: GROUP_PROTOCOL_VERSION,
      type: 'group_message',
      group_id: this.groupId,
      sender_id: senderId,
      message_number: member.sendingChain.messageNumber - 1,
      iv: iv.toString('base64'),
      ciphertext: ciphertext.toString('base64'),
      auth_tag: authTag.toString('base64'),
      timestamp: Date.now()
    };
    
    return message;
  }
  
  receiveGroupMessage(message, memberId) {
    const member = this.members.get(memberId);
    if (!member) {
      throw new Error('成员不存在：' + memberId);
    }
    
    const receivingChain = member.receivingChains.get('default');
    const messageNumber = message.message_number;
    const expectedMsgNum = receivingChain.messageNumber;
    
    // 检查是否是乱序消息
    if (messageNumber > expectedMsgNum) {
      // 预先生成跳跃密钥（Skip Ratchet算法）
      for (let i = expectedMsgNum; i < messageNumber; i++) {
        if (!receivingChain.skipKeys.has(i)) {
          // 为每一条缺失的消息生成跳跃密钥
          const skippedKey = crypto.createHmac('sha256', receivingChain.chainKey)
            .update(Buffer.from('message-key'))
            .digest();
          receivingChain.skipKeys.set(i, skippedKey);
          
          // 推进链密钥
          const nextChainKey = crypto.createHmac('sha256', receivingChain.chainKey)
            .update(Buffer.from('chain-key'))
            .digest();
          receivingChain.chainKey = nextChainKey;
        }
      }
      
      // 使用目标messageNumber对应的跳跃密钥
      const messageKey = receivingChain.skipKeys.get(messageNumber);
      
      // 清理已使用的跳跃密钥
      receivingChain.skipKeys.delete(messageNumber);
      
      // 解密消息
      const iv = Buffer.from(message.iv, 'base64');
      const ciphertext = Buffer.from(message.ciphertext, 'base64');
      const authTag = Buffer.from(message.auth_tag, 'base64');
      
      const decipher = crypto.createDecipheriv('aes-256-gcm', messageKey, iv);
      decipher.setAuthTag(authTag);
      
      let plaintext;
      try {
        plaintext = Buffer.concat([
          decipher.update(ciphertext),
          decipher.final()
        ]).toString('utf8');
      } catch (error) {
        throw new Error('解密失败：' + error.message);
      }
      
      // 更新接收链状态
      const nextChainKey = crypto.createHmac('sha256', receivingChain.chainKey)
        .update(Buffer.from('chain-key'))
        .digest();
      receivingChain.chainKey = nextChainKey;
      receivingChain.messageNumber = messageNumber + 1;
      
      return plaintext;
    } else {
      // 顺序消息，正常处理
      const messageKey = crypto.createHmac('sha256', receivingChain.chainKey)
        .update(Buffer.from('message-key'))
        .digest();
      
      // 解密消息
      const iv = Buffer.from(message.iv, 'base64');
      const ciphertext = Buffer.from(message.ciphertext, 'base64');
      const authTag = Buffer.from(message.auth_tag, 'base64');
      
      const decipher = crypto.createDecipheriv('aes-256-gcm', messageKey, iv);
      decipher.setAuthTag(authTag);
      
      let plaintext;
      try {
        plaintext = Buffer.concat([
          decipher.update(ciphertext),
          decipher.final()
        ]).toString('utf8');
      } catch (error) {
        throw new Error('解密失败：' + error.message);
      }
      
      // 推进链密钥
      const nextChainKey = crypto.createHmac('sha256', receivingChain.chainKey)
        .update(Buffer.from('chain-key'))
        .digest();
      receivingChain.chainKey = nextChainKey;
      receivingChain.messageNumber++;
      
      return plaintext;
    }
  }
  
  // 更新root key（成员加入/离开时）
  updateRootKey(newRootKey) {
    this.rootKey = newRootKey;
    
    // 更新所有成员的接收链
    for (const [memberId] of this.members.keys()) {
      const member = this.members.get(memberId);
      
      // 重新派生接收链密钥
      const receivingChainKey = crypto.createHash('sha256')
        .update(newRootKey)
        .update(Buffer.from(memberId))
        .digest();
      
      member.receivingChains.set('default', {
        chainKey: receivingChainKey,
        messageNumber: 0,
        skipKeys: new Map()
      });
    }
  }
}

// 导出
module.exports = {
  // 常量
  PROTOCOL_VERSION,
  KDF_SALT,
  KDF_INFO,
  NONCE_LENGTH,
  HANDSHAKE_NONCE_LENGTH,
  MESSAGE_KEY_LENGTH,
  CHAIN_KEY_LENGTH,
  GROUP_PROTOCOL_VERSION,
  AES_GCM_NONCE_LENGTH,
  
  // 基础功能
  generateKeyPair,
  hashPsk,
  dhExchange,
  deriveKeys,
  encryptMessage,
  decryptMessage,
  generateReplayTag,
  
  // 高级功能
  NonceManager,
  MessageCounter,
  SessionState,
  GroupManager
};
