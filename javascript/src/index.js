/**
 * SIP协议完整实现
 * 统一导出所有模块
 */

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

// Crypto模块
const { generateKeyPair, dhExchange } = require('./crypto/dh');
const { hkdf, deriveKeys } = require('./crypto/hkdf');
const { hashPsk } = require('./crypto/argon2');
const { encryptAESGCM, decryptAESGCM } = require('./crypto/aes-gcm');

// Protocol模块
const {
  initiateHandshake,
  respondHandshake,
  completeHandshake
} = require('./protocol/handshake');
const {
  encryptMessage,
  decryptMessage,
  generateReplayTag,
  verifyReplayTag
} = require('./protocol/message');
const { GroupManager } = require('./protocol/group');

// Managers模块
const { NonceManager } = require('./managers/nonce');
const { SessionState } = require('./managers/session');

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

  // Crypto模块
  generateKeyPair,
  dhExchange,
  hkdf,
  deriveKeys,
  hashPsk,
  encryptAESGCM,
  decryptAESGCM,

  // Protocol模块
  initiateHandshake,
  respondHandshake,
  completeHandshake,
  encryptMessage,
  decryptMessage,
  generateReplayTag,
  verifyReplayTag,

  // Managers模块
  NonceManager,
  SessionState,
  GroupManager
};
