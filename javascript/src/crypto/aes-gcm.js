/**
 * AES-GCM加密模块
 * 实现AES-256-GCM加密和解密
 */

const crypto = require('crypto');

const AES_GCM_NONCE_LENGTH = 12;

/**
 * AES-GCM加密
 * @param {Buffer} key - 加密密钥（32字节）
 * @param {Buffer} plaintext - 明文
 * @param {Buffer} iv - 初始化向量（12字节）
 * @returns {Object} { ciphertext, authTag }
 */
function encryptAESGCM(key, plaintext, iv) {
  const aesgcm = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([
    aesgcm.update(plaintext),
    aesgcm.final()
  ]);
  
  // Node.js的AES-GCM：final()返回纯密文，认证标签需要单独获取
  const authTag = aesgcm.getAuthTag();
  
  return { ciphertext, authTag };
}

/**
 * AES-GCM解密
 * @param {Buffer} key - 解密密钥（32字节）
 * @param {Buffer} ciphertext - 密文
 * @param {Buffer} iv - 初始化向量（12字节）
 * @param {Buffer} authTag - 认证标签（16字节）
 * @returns {Buffer} 明文
 */
function decryptAESGCM(key, ciphertext, iv, authTag) {
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(authTag);
  
  const plaintext = Buffer.concat([
    decipher.update(ciphertext),
    decipher.final()
  ]);
  
  return plaintext;
}

module.exports = {
  AES_GCM_NONCE_LENGTH,
  encryptAESGCM,
  decryptAESGCM
};
