/**
 * XChaCha20-Poly1305加密模块
 * 实现XChaCha20-Poly1305加密和解密
 *
 * 注意：@noble/ciphers返回Uint8Array，需要转换为Buffer
 */

const crypto = require('crypto');
const { xchacha20poly1305 } = require('@noble/ciphers/chacha');

const NONCE_LENGTH = 24;

/**
 * XChaCha20-Poly1305加密
 * @param {Buffer} key - 加密密钥（32字节）
 * @param {Buffer} plaintext - 明文
 * @param {Buffer} nonce - 初始化向量（24字节）
 * @returns {Object} { ciphertext, authTag }
 */
function _toUint8Array(buf) {
  // @noble/ciphers 要求纯 Uint8Array，不能是 Buffer（Buffer 的 .buffer 可能是共享的 ArrayBuffer）
  return new Uint8Array(buf.buffer, buf.byteOffset, buf.length);
}

function encryptXChaCha20Poly1305(key, plaintext, nonce) {
  const cipher = xchacha20poly1305(_toUint8Array(key), _toUint8Array(nonce));
  const ciphertextUint8 = cipher.encrypt(_toUint8Array(plaintext));

  const ciphertext = Buffer.from(ciphertextUint8);

  // XChaCha20-Poly1305: 最后16字节是认证标签
  const ciphertextOnly = ciphertext.slice(0, plaintext.length);
  const authTag = ciphertext.slice(plaintext.length);

  return { ciphertext: ciphertextOnly, authTag };
}

/**
 * XChaCha20-Poly1305解密
 * @param {Buffer} key - 解密密钥（32字节）
 * @param {Buffer} ciphertext - 密文
 * @param {Buffer} nonce - 初始化向量（24字节）
 * @param {Buffer} authTag - 认证标签（16字节）
 * @returns {Buffer} 明文
 */
function decryptXChaCha20Poly1305(key, ciphertext, nonce, authTag) {
  const ciphertextWithTag = Buffer.concat([ciphertext, authTag]);

  const cipher = xchacha20poly1305(_toUint8Array(key), _toUint8Array(nonce));
  const plaintextUint8 = cipher.decrypt(_toUint8Array(ciphertextWithTag));

  return Buffer.from(plaintextUint8);
}

/**
 * 生成随机nonce
 * @returns {Buffer} 24字节随机nonce
 */
function generateNonce() {
  return crypto.randomBytes(NONCE_LENGTH);
}

module.exports = {
  NONCE_LENGTH,
  encryptXChaCha20Poly1305,
  decryptXChaCha20Poly1305,
  generateNonce
};
