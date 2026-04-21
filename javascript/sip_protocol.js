import { xchacha20poly1305 } from '@noble/ciphers/chacha';

const key = new Uint8Array(32); // session_key
const nonce = new Uint8Array(24); // iv
const plaintext = new TextEncoder().encode('Hello, agent!');

const cipher = xchacha20poly1305(key, nonce);
const ciphertext = cipher.encrypt(plaintext);

// ciphertext 包含加密数据 + auth_tag


const crypto = require('crypto');

function serializeSessionState(state) {
  /**
   * 序列化会话状态为JSON字符串
   * 
   * Args:
   *   state: 会话状态对象
   *   
   * Returns:
   *   serialized: Base64编码的JSON字符串
   */
  const jsonStr = JSON.stringify(state);
  const serialized = Buffer.from(jsonStr).toString('base64');
  return serialized;
}

function deserializeSessionState(serialized) {
  /**
   * 反序列化会话状态
   * 
   * Args:
   *   serialized: Base64编码的JSON字符串
   *   
   * Returns:
   *   state: 会话状态对象
   */
  const jsonStr = Buffer.from(serialized, 'base64').toString();
  const state = JSON.parse(jsonStr);
  return state;
}


const crypto = require('crypto');
const { x25519 } = require('@noble/ciphers');

// 常量
const PROTOCOL_VERSION = 'SIP-1.0';
const KDF_SALT = Buffer.from('SIPHandshake');
const KDF_INFO = Buffer.from('session-keys');
const NONCE_LENGTH = 24;
const HANDSHAKE_NONCE_LENGTH = 16;

// 密钥对生成
function generateKeyPair() {
  const privateKey = crypto.randomBytes(32);
  const publicKey = x25519.getPublicKey(privateKey);
  return { privateKey, publicKey };
}

// PSK 哈希（Argon2id）
function hashPsk(psk, salt = null) {
  /**
   * 使用 Argon2id 哈希 PSK
   * 
   * Args:
   *   psk: 预共享密钥 (Buffer, 任意长度)
   *   salt: 盐（可选，如果为null则生成随机盐, 16 bytes）
   *   
   * Returns:
   *   { pskHash: 32 bytes 哈希值 (Buffer), salt: 16 bytes 盐 (Buffer) }
   *   
   * 需要安装: npm install argon2
   */
  const argon2 = require('argon2');
  
  // 如果没有提供盐，生成随机盐
  if (!salt) {
    salt = crypto.randomBytes(16);
  }
  
  // Argon2id 参数
  const options = {
    type: argon2.argon2id,
    memoryCost: 65536,  // 64MB (单位: KB)
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

// DH 密钥交换
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

// 加密消息
function encryptMessage(encryptionKey, plaintext) {
  const nonce = Buffer.alloc(NONCE_LENGTH, 0);
  const cipher = crypto.createCipheriv('chacha20-poly1305', encryptionKey, nonce);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return { nonce, ciphertext, authTag };
}

// 生成防重放标签
function generateReplayTag(replayKey, senderId, messageCounter) {
  const data = Buffer.concat([
    Buffer.from(senderId),
    Buffer.from(messageCounter.toString())
  ]);
  const tag = crypto.createHmac('sha256', replayKey).update(data).digest();
  return tag.toString('hex');
}
