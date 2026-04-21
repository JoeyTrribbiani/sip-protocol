/**
 * PSK哈希模块
 * 实现基于Argon2id的PSK哈希
 */

const argon2 = require('argon2');
const crypto = require('crypto');

// Argon2id 常量
const ARGON2_SALT_LENGTH = 16;
const ARGON2_MEMORY_COST = 65536;  // 64MB
const ARGON2_TIME_COST = 3;
const ARGON2_PARALLELISM = 4;
const ARGON2_HASH_LENGTH = 32;

/**
 * 哈希PSK（Argon2id）
 * @param {Buffer|String} psk - 预共享密钥
 * @param {Buffer|null} salt - 盐（如果为null则生成随机盐）
 * @returns {Promise<Object>} { pskHash, salt }
 */
async function hashPsk(psk, salt = null) {
  if (!salt) {
    salt = crypto.randomBytes(ARGON2_SALT_LENGTH);
  }
  
  const options = {
    type: argon2.argon2id,
    memoryCost: ARGON2_MEMORY_COST,
    timeCost: ARGON2_TIME_COST,
    parallelism: ARGON2_PARALLELISM,
    hashLength: ARGON2_HASH_LENGTH,
    salt: salt,
    raw: true
  };
  
  const pskHash = await argon2.hash(psk, options);
  return { pskHash, salt };
}

module.exports = {
  hashPsk
};
