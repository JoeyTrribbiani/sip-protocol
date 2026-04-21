/**
 * PSK哈希模块
 * 实现基于Argon2id的PSK哈希
 */

const argon2 = require('argon2');
const crypto = require('crypto');

/**
 * 哈希PSK（Argon2id）
 * @param {Buffer|String} psk - 预共享密钥
 * @param {Buffer|null} salt - 盐（如果为null则生成随机盐）
 * @returns {Promise<Object>} { pskHash, salt }
 */
async function hashPsk(psk, salt = null) {
  if (!salt) {
    salt = crypto.randomBytes(16);
  }
  
  const options = {
    type: argon2.argon2id,
    memoryCost: 65536,     // 64MB
    timeCost: 3,
    parallelism: 4,
    hashLength: 32,
    salt: salt,
    raw: true
  };
  
  const pskHash = await argon2.hash(psk, options);
  return { pskHash, salt };
}

module.exports = {
  hashPsk
};
