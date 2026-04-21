/**
 * Nonce管理器模块
 * 防止重放攻击
 */

const crypto = require('crypto');

const NONCE_LENGTH = 24;

/**
 * Nonce管理器
 */
class NonceManager {
  constructor() {
    this.usedNonces = new Set();
  }

  /**
   * 生成新的Nonce
   * @returns {Buffer} 新的Nonce
   */
  generateNonce() {
    let nonce;
    do {
      nonce = crypto.randomBytes(NONCE_LENGTH);
    } while (this.usedNonces.has(nonce.toString('hex')));

    this.usedNonces.add(nonce.toString('hex'));
    return nonce;
  }

  /**
   * 验证Nonce是否已使用
   * @param {Buffer} nonce - 要验证的Nonce
   * @returns {Boolean} 是否有效（未使用）
   */
  validateNonce(nonce) {
    return !this.usedNonces.has(nonce.toString('hex'));
  }
}

module.exports = {
  NONCE_LENGTH,
  NonceManager
};
