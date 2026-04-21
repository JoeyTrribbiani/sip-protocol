/**
 * DH密钥交换模块
 * 实现X25519 ECDH密钥交换
 */

const crypto = require('crypto');

/**
 * 生成X25519密钥对
 * @returns {Object} { privateKey, publicKey }
 */
function generateKeyPair() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('x25519');
  return { privateKey, publicKey };
}

/**
 * DH密钥交换
 * @param {KeyObject} privateKey - 本地私钥
 * @param {KeyObject} publicKey - 远程公钥
 * @returns {Buffer} 共享密钥
 */
function dhExchange(privateKey, publicKey) {
  const sharedSecret = crypto.diffieHellman({
    privateKey,
    publicKey
  });
  return sharedSecret;
}

module.exports = {
  generateKeyPair,
  dhExchange
};
