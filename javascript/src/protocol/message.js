/**
 * 消息加密模块
 * 实现消息加密和解密
 */

const { encryptAESGCM, decryptAESGCM } = require('../crypto/aes-gcm');
const crypto = require('crypto');

const PROTOCOL_VERSION = 'SIP-1.0';
const AES_GCM_NONCE_LENGTH = 12;

/**
 * 加密消息
 * @param {Buffer} encryptionKey - 加密密钥
 * @param {String} plaintext - 明文消息
 * @param {String} senderId - 发送方ID
 * @param {Number} messageCounter - 消息计数器
 * @returns {Object} 加密后的消息
 */
function encryptMessage(encryptionKey, plaintext, senderId, messageCounter) {
  const iv = crypto.randomBytes(AES_GCM_NONCE_LENGTH);
  const { ciphertext, authTag } = encryptAESGCM(
    encryptionKey,
    Buffer.from(plaintext),
    iv
  );
  
  const message = {
    version: PROTOCOL_VERSION,
    type: 'encrypted_message',
    sender_id: senderId,
    message_counter: messageCounter,
    nonce: iv.toString('base64'),
    ciphertext: ciphertext.toString('base64'),
    auth_tag: authTag.toString('base64'),
    timestamp: Date.now()
  };
  
  return message;
}

/**
 * 解密消息
 * @param {Buffer} encryptionKey - 解密密钥
 * @param {Object} message - 加密的消息
 * @returns {String} 明文消息
 * @throws {Error} 解密失败时抛出异常
 */
function decryptMessage(encryptionKey, message) {
  const iv = Buffer.from(message.nonce, 'base64');
  const ciphertext = Buffer.from(message.ciphertext, 'base64');
  const authTag = Buffer.from(message.auth_tag, 'base64');
  
  try {
    const plaintext = decryptAESGCM(
      encryptionKey,
      ciphertext,
      iv,
      authTag
    );
    
    return plaintext.toString('utf8');
  } catch (error) {
    throw new Error('解密失败：' + error.message);
  }
}

/**
 * 生成防重放标签
 * @param {Buffer} replayKey - 防重放密钥
 * @param {String} senderId - 发送方ID
 * @param {Number} messageCounter - 消息计数器
 * @returns {String} 防重放标签（十六进制）
 */
function generateReplayTag(replayKey, senderId, messageCounter) {
  const data = Buffer.concat([
    Buffer.from(senderId),
    Buffer.from(messageCounter.toString())
  ]);
  
  const replayTag = crypto.createHmac('sha256', replayKey)
    .update(data)
    .digest('hex');
  
  return replayTag;
}

/**
 * 验证防重放标签
 * @param {Buffer} replayKey - 防重放密钥
 * @param {String} senderId - 发送方ID
 * @param {Number} messageCounter - 消息计数器
 * @param {String} replayTag - 防重放标签
 * @returns {Boolean} 是否有效
 */
function verifyReplayTag(replayKey, senderId, messageCounter, replayTag) {
  const expectedTag = generateReplayTag(replayKey, senderId, messageCounter);
  return crypto.timingSafeEqual(
    Buffer.from(expectedTag, 'hex'),
    Buffer.from(replayTag, 'hex')
  );
}

module.exports = {
  PROTOCOL_VERSION,
  AES_GCM_NONCE_LENGTH,
  encryptMessage,
  decryptMessage,
  generateReplayTag,
  verifyReplayTag
};
