/**
 * 消息加密模块
 * 实现消息加密和解密（XChaCha20-Poly1305）
 */

const {
  encryptXChaCha20Poly1305,
  decryptXChaCha20Poly1305,
  generateNonce
} = require('../crypto/xchacha20-poly1305');
const crypto = require('crypto');

const PROTOCOL_VERSION = 'SIP-1.0';

/**
 * 加密消息（XChaCha20-Poly1305）
 * @param {Buffer} encryptionKey - 加密密钥
 * @param {String} plaintext - 明文消息
 * @param {String} senderId - 发送方ID
 * @param {String} recipientId - 接收方ID
 * @param {Number} messageCounter - 消息计数器
 * @param {Buffer} replayKey - 防重放密钥（可选，用于生成replay_tag）
 * @returns {Object} 加密后的消息
 */
function encryptMessage(encryptionKey, plaintext, senderId, recipientId, messageCounter, replayKey = null) {
  const iv = generateNonce();
  const { ciphertext, authTag } = encryptXChaCha20Poly1305(
    encryptionKey,
    Buffer.from(plaintext),
    iv
  );

  // 生成replay_tag（如果提供了replay_key）
  let replayTag = null;
  if (replayKey !== null) {
    replayTag = generateReplayTag(replayKey, senderId, messageCounter);
  }

  const message = {
    version: PROTOCOL_VERSION,
    type: 'message',  // 修改为文档要求的类型
    timestamp: Date.now(),
    sender_id: senderId,
    recipient_id: recipientId,  // 添加recipient_id字段
    message_counter: messageCounter,
    iv: iv.toString('base64'),
    payload: ciphertext.toString('base64'),  // 修改为payload（符合文档）
    auth_tag: authTag.toString('base64')
  };

  // 添加replay_tag字段（如果生成了）
  if (replayTag !== null) {
    message.replay_tag = replayTag;
  }

  return message;
}

/**
 * 解密消息（XChaCha20-Poly1305）
 * @param {Buffer} encryptionKey - 解密密钥
 * @param {Object} message - 加密的消息
 * @returns {String} 明文消息
 * @throws {Error} 解密失败时抛出异常
 */
function decryptMessage(encryptionKey, message) {
  const iv = Buffer.from(message.iv, 'base64');
  const ciphertext = Buffer.from(message.payload, 'base64');  // 修改为payload（符合文档）
  const authTag = Buffer.from(message.auth_tag, 'base64');

  try {
    const plaintext = decryptXChaCha20Poly1305(
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
  encryptMessage,
  decryptMessage,
  generateReplayTag,
  verifyReplayTag
};
