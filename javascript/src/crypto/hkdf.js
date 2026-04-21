/**
 * HKDF密钥派生模块
 * 实现基于SHA256的HKDF密钥派生函数
 */

const crypto = require('crypto');

// HKDF 常量
const KDF_TOTAL_LENGTH = 96;  // 3 × 32 bytes
const KDF_KEY_LENGTH = 32;   // 单个密钥长度（字节）
const KDF_AUTH_KEY_OFFSET = 32;
const KDF_REPLAY_KEY_OFFSET = 64;

/**
 * HKDF密钥派生
 * @param {Buffer} ikm - 输入密钥材料
 * @param {Buffer} salt - 盐
 * @param {Buffer} info - 上下文信息
 * @param {Number} length - 输出密钥长度（字节）
 * @returns {Buffer} 派生的密钥
 */
function hkdf(ikm, salt, info, length) {
  const result = crypto.hkdfSync('sha256', ikm, salt, info, length);
  // hkdfSync返回Buffer，但在某些情况下可能是ArrayBuffer
  return Buffer.isBuffer(result) ? result : Buffer.from(result);
}

/**
 * HKDF密钥派生（用于握手，三重DH）
 * @param {Buffer} shared1 - DH共享密钥1 (identity_local × remote_ephemeral)
 * @param {Buffer} shared2 - DH共享密钥2 (ephemeral_local × remote_identity)
 * @param {Buffer} shared3 - DH共享密钥3 (ephemeral_local × remote_ephemeral)
 * @param {Buffer} pskHash - PSK哈希
 * @param {Buffer} nonceA - 发起方Nonce
 * @param {Buffer} nonceB - 响应方Nonce
 * @returns {Object} { encryptionKey, authKey, replayKey }
 */
function deriveKeysTripleDH(shared1, shared2, shared3, pskHash, nonceA, nonceB) {
  const KDF_SALT = Buffer.from('SIPHandshake');
  const KDF_INFO = Buffer.from('session-keys');
  
  const ikm = Buffer.concat([shared1, shared2, shared3, pskHash, nonceA, nonceB]);
  const kdf = hkdf(ikm, KDF_SALT, KDF_INFO, KDF_TOTAL_LENGTH);
  
  return {
    encryptionKey: kdf.slice(0, KDF_KEY_LENGTH),
    authKey: kdf.slice(KDF_AUTH_KEY_OFFSET, KDF_REPLAY_KEY_OFFSET),
    replayKey: kdf.slice(KDF_REPLAY_KEY_OFFSET, KDF_TOTAL_LENGTH)
  };
}

/**
 * HKDF密钥派生（用于握手，单次DH - 保留兼容性）
 * @param {Buffer} sharedSecret - DH共享密钥
 * @param {Buffer} pskHash - PSK哈希
 * @param {Buffer} nonceA - 发起方Nonce
 * @param {Buffer} nonceB - 响应方Nonce
 * @returns {Object} { encryptionKey, authKey, replayKey }
 */
function deriveKeys(sharedSecret, pskHash, nonceA, nonceB) {
  const KDF_SALT = Buffer.from('SIPHandshake');
  const KDF_INFO = Buffer.from('session-keys');
  
  const ikm = Buffer.concat([sharedSecret, pskHash, nonceA, nonceB]);
  const kdf = hkdf(ikm, KDF_SALT, KDF_INFO, KDF_TOTAL_LENGTH);
  
  return {
    encryptionKey: kdf.slice(0, KDF_KEY_LENGTH),
    authKey: kdf.slice(KDF_AUTH_KEY_OFFSET, KDF_REPLAY_KEY_OFFSET),
    replayKey: kdf.slice(KDF_REPLAY_KEY_OFFSET, KDF_TOTAL_LENGTH)
  };
}

module.exports = {
  hkdf,
  deriveKeys,
  deriveKeysTripleDH
};
