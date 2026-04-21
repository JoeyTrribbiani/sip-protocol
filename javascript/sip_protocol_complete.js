// SIP协议完整实现 - 使用Node.js内置crypto模块（简化版）

const crypto = require('crypto');
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

// 密钥对生成（使用Node.js内置X25519）
function generateKeyPair() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('x25519');
  return { privateKey, publicKey };
}

// PSK 哈希（Argon2id）
async function hashPsk(psk, salt = null) {
  if (!salt) {
    salt = crypto.randomBytes(16);
  }
  
  const options = {
    type: argon2.argon2id,
    memoryCost: 65536,
    timeCost: 3,
    parallelism: 4,
    hashLength: 32,
    salt: salt,
    raw: true
  };
  
  const pskHash = await argon2.hash(psk, options);
  return { pskHash, salt };
}

// DH 密钥交换（使用Node.js内置X25519）
function dhExchange(privateKey, publicKey) {
  const sharedSecret = crypto.diffieHellman({
    privateKey,
    publicKey
  });
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
    96
  );
  const encryptionKey = kdf.slice(0, 32);
  const authKey = kdf.slice(32, 64);
  const replayKey = kdf.slice(64, 96);
  return { encryptionKey, authKey, replayKey };
}

// 加密消息（使用AES-256-GCM）
function encryptMessage(encryptionKey, plaintext, senderId, messageCounter) {
  const iv = crypto.randomBytes(AES_GCM_NONCE_LENGTH);
  const cipher = crypto.createCipheriv('aes-256-gcm', encryptionKey, iv);
  
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
  
  const message = {
    version: PROTOCOL_VERSION,
    type: 'encrypted_message',
    sender_id: senderId,
    message_counter: messageCounter,
    nonce: iv.toString('base64'),
    ciphertext: ciphertext.toString('base64'),
    auth_tag: authTag.toString('base64'),
    timestamp: Date.now()
  };
  
  return message;
}

// 解密消息
function decryptMessage(encryptionKey, message) {
  const iv = Buffer.from(message.nonce, 'base64');
  const ciphertext = Buffer.from(message.ciphertext, 'base64');
  const authTag = Buffer.from(message.auth_tag, 'base64');
  
  const decipher = crypto.createDecipheriv('aes-256-gcm', encryptionKey, iv);
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

// Nonce管理器
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
      this.counter = 0;
    }
    return this.counter;
  }
  
  get() {
    return this.counter;
  }
  
  validate(messageCounter) {
    return messageCounter > this.counter && 
           messageCounter <= (this.counter + 10000);
  }
}

// 会话状态
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

// 群组管理器
class GroupManager {
  constructor(groupId, rootKey) {
    this.groupId = groupId;
    this.rootKey = rootKey;
    this.members = new Map();
    this.sendingChains = new Map();
    this.receivingChains = new Map();
  }
  
  addMember(memberId, sendingChainKey) {
    this.members.set(memberId, {
      sendingChain: {
        chainKey: sendingChainKey,
        messageNumber: 0,
        skipKeys: new Map()
      }
    });
    
    const receivingChainKey = crypto.createHash('sha256')
      .update(this.rootKey)
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
    
    const messageKey = crypto.createHmac('sha256', member.sendingChain.chainKey)
      .update(Buffer.from('message-key'))
      .digest();
    
    const nextChainKey = crypto.createHmac('sha256', member.sendingChain.chainKey)
      .update(Buffer.from('chain-key'))
      .digest();
    
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
    
    member.sendingChain.chainKey = nextChainKey;
    member.sendingChain.messageNumber++;
    
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
    
    const receivingChain = this.receivingChains.get(memberId);
    const messageNumber = message.message_number;
    const expectedMsgNum = receivingChain.messageNumber;
    
    if (messageNumber > expectedMsgNum) {
      for (let i = expectedMsgNum; i < messageNumber; i++) {
        if (!receivingChain.skipKeys.has(i)) {
          const skippedKey = crypto.createHmac('sha256', receivingChain.chainKey)
            .update(Buffer.from('message-key'))
            .digest();
          receivingChain.skipKeys.set(i, skippedKey);
          
          const nextChainKey = crypto.createHmac('sha256', receivingChain.chainKey)
            .update(Buffer.from('chain-key'))
            .digest();
          receivingChain.chainKey = nextChainKey;
        }
      }
      
      const messageKey = receivingChain.skipKeys.get(messageNumber);
      receivingChain.skipKeys.delete(messageNumber);
      
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
      
      const nextChainKey = crypto.createHmac('sha256', receivingChain.chainKey)
        .update(Buffer.from('chain-key'))
        .digest();
      receivingChain.chainKey = nextChainKey;
      receivingChain.messageNumber = messageNumber + 1;
      
      return plaintext;
    } else {
      const messageKey = crypto.createHmac('sha256', receivingChain.chainKey)
        .update(Buffer.from('message-key'))
        .digest();
      
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
      
      const nextChainKey = crypto.createHmac('sha256', receivingChain.chainKey)
        .update(Buffer.from('chain-key'))
        .digest();
      receivingChain.chainKey = nextChainKey;
      receivingChain.messageNumber++;
      
      return plaintext;
    }
  }
  
  updateRootKey(newRootKey) {
    this.rootKey = newRootKey;
    
    for (const [memberId] of this.members.keys()) {
      const member = this.members.get(memberId);
      
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

module.exports = {
  PROTOCOL_VERSION,
  KDF_SALT,
  KDF_INFO,
  NONCE_LENGTH,
  HANDSHAKE_NONCE_LENGTH,
  MESSAGE_KEY_LENGTH,
  CHAIN_KEY_LENGTH,
  GROUP_PROTOCOL_VERSION,
  AES_GCM_NONCE_LENGTH,
  generateKeyPair,
  hashPsk,
  dhExchange,
  deriveKeys,
  encryptMessage,
  decryptMessage,
  generateReplayTag,
  NonceManager,
  MessageCounter,
  SessionState,
  GroupManager
};
