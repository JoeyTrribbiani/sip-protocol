/**
 * HKDF密钥派生模块
 * 实现基于SHA256的HKDF密钥派生函数
 */

const crypto = require('crypto');

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
 * HKDF密钥派生（用于握手）
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
  const kdf = hkdf(ikm, KDF_SALT, KDF_INFO, 96);
  
  return {
    encryptionKey: kdf.slice(0, 32),
    authKey: kdf.slice(32, 64),
    replayKey: kdf.slice(64, 96)
  };
}

module.exports = {
  hkdf,
  deriveKeys
};
