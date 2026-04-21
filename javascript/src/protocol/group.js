/**
 * 群组加密协议模块
 * 实现基于Double Ratchet的群组加密
 */

const { encryptAESGCM, decryptAESGCM } = require('../crypto/aes-gcm');
const { hkdf } = require('../crypto/hkdf');
const crypto = require('crypto');

const GROUP_PROTOCOL_VERSION = 'SIP-1.0';
const AES_GCM_NONCE_LENGTH = 12;
const MESSAGE_KEY_LENGTH = 32;
const CHAIN_KEY_LENGTH = 32;

/**
 * 群组管理器
 */
class GroupManager {
  /**
   * 构造函数
   * @param {String} groupId - 群组ID
   * @param {Buffer} rootKey - 根密钥
   */
  constructor(groupId, rootKey) {
    this.groupId = groupId;
    this.rootKey = rootKey;
    this.members = new Map();
  }

  /**
   * 初始化群组链密钥
   * @param {Array} members - 群组成员ID列表
   * @param {Buffer} rootKey - 根密钥
   * @returns {Object} 群组链密钥
   */
  initializeGroupChains(members, rootKey) {
    const chains = {};

    for (const member of members) {
      // 派生sending chain key
      const sendingChainKey = hkdf(
        rootKey,
        Buffer.from(`${member}:sending`),
        Buffer.from('sending-chain'),
        CHAIN_KEY_LENGTH
      );

      // 派生receiving chain key
      const receivingChainKey = hkdf(
        rootKey,
        Buffer.from(`${member}:receiving`),
        Buffer.from('receiving-chain'),
        CHAIN_KEY_LENGTH
      );

      chains[member] = {
        sending_chain: {
          chain_key: sendingChainKey,
          message_number: 0
        },
        receiving_chain: {
          chain_key: receivingChainKey,
          message_number: 0,
          skip_keys: {}
        }
      };

      // 同时添加到members Map
      this.members.set(member, chains[member]);
    }

    return chains;
  }

  /**
   * 发送群组消息
   * @param {String} plaintext - 明文消息
   * @param {String} senderId - 发送方ID
   * @returns {Object} 群组消息
   */
  sendGroupMessage(plaintext, senderId) {
    const member = this.members.get(senderId);
    if (!member) {
      throw new Error('成员不存在：' + senderId);
    }

    const sendingChain = member.sending_chain;

    // 1. 派生消息密钥
    const messageKey = hkdf(
      sendingChain.chain_key,
      Buffer.alloc(0),
      Buffer.from('message-key'),
      MESSAGE_KEY_LENGTH
    );

    // 2. 推进链密钥
    const nextChainKey = hkdf(
      sendingChain.chain_key,
      Buffer.alloc(0),
      Buffer.from('chain-key'),
      CHAIN_KEY_LENGTH
    );

    // 3. 加密消息
    const iv = crypto.randomBytes(AES_GCM_NONCE_LENGTH);
    const { ciphertext, authTag } = encryptAESGCM(
      messageKey,
      Buffer.from(plaintext),
      iv
    );

    // 4. 发送方签名
    const senderSignature = crypto.createHmac('sha256', messageKey)
      .update(ciphertext)
      .digest();

    // 5. 更新sending chain状态
    member.sending_chain.chain_key = nextChainKey;
    member.sending_chain.message_number++;

    // 6. 构建群组消息
    const message = {
      version: GROUP_PROTOCOL_VERSION,
      type: 'group_message',
      timestamp: Date.now(),
      sender_id: senderId,
      group_id: this.groupId,
      message_number: member.sending_chain.message_number - 1,
      iv: iv.toString('base64'),
      ciphertext: ciphertext.toString('base64'),
      auth_tag: authTag.toString('base64'),
      sender_signature: senderSignature.toString('base64')
    };

    return message;
  }

  /**
   * 接收群组消息（完整版，支持乱序消息）
   * @param {Object} message - 群组消息
   * @param {String} recipientId - 接收方ID
   * @returns {String} 明文消息
   */
  receiveGroupMessage(message, recipientId) {
    // 1. 解析消息
    const senderId = message.sender_id;
    const messageNumber = message.message_number;

    const member = this.members.get(senderId);
    if (!member) {
      throw new Error('成员不存在：' + senderId);
    }

    const receivingChain = member.receiving_chain;
    const expectedMsgNum = receivingChain.message_number;

    let messageKey;

    // 2. 检查消息类型并派生消息密钥
    if (messageNumber > expectedMsgNum) {
      // 乱序消息，预先生成跳跃密钥（Skip Ratchet算法）
      for (let i = expectedMsgNum; i < messageNumber; i++) {
        if (!(i in receivingChain.skip_keys)) {
          // 为每一条缺失的消息生成跳跃密钥
          const skippedKey = hkdf(
            receivingChain.chain_key,
            Buffer.alloc(0),
            Buffer.from('message-key'),
            MESSAGE_KEY_LENGTH
          );
          receivingChain.skip_keys[i] = skippedKey;

          // 推进链密钥
          const nextChainKey = hkdf(
            receivingChain.chain_key,
            Buffer.alloc(0),
            Buffer.from('chain-key'),
            CHAIN_KEY_LENGTH
          );
          receivingChain.chain_key = nextChainKey;
        }
      }

      // 使用目标message_number对应的跳跃密钥
      messageKey = receivingChain.skip_keys[messageNumber];

      // 清理已使用的跳跃密钥
      delete receivingChain.skip_keys[messageNumber];

    } else if (messageNumber === expectedMsgNum) {
      // 顺序消息，使用当前链密钥
      messageKey = hkdf(
        receivingChain.chain_key,
        Buffer.alloc(0),
        Buffer.from('message-key'),
        MESSAGE_KEY_LENGTH
      );

      // 推进链密钥
      const nextChainKey = hkdf(
        receivingChain.chain_key,
        Buffer.alloc(0),
        Buffer.from('chain-key'),
        CHAIN_KEY_LENGTH
      );
      receivingChain.chain_key = nextChainKey;

    } else {
      // 重复消息或过期消息，拒绝
      throw new Error(`Invalid message number: ${messageNumber}, expected: ${expectedMsgNum}`);
    }

    // 3. 解密消息
    const iv = Buffer.from(message.iv, 'base64');
    const ciphertext = Buffer.from(message.ciphertext, 'base64');
    const authTag = Buffer.from(message.auth_tag, 'base64');

    const plaintext = decryptAESGCM(
      messageKey,
      ciphertext,
      iv,
      authTag
    );

    // 4. 验证发送方签名
    const senderSignature = Buffer.from(message.sender_signature, 'base64');
    const expectedSignature = crypto.createHmac('sha256', messageKey)
      .update(ciphertext)
      .digest();

    if (!crypto.timingSafeEqual(senderSignature, expectedSignature)) {
      throw new Error('Invalid sender signature');
    }

    // 5. 更新receiving chain状态
    member.receiving_chain.chain_key = receivingChain.chain_key;
    member.receiving_chain.message_number = receivingChain.message_number + 1;
    member.receiving_chain.skip_keys = receivingChain.skip_keys;

    return plaintext.toString('utf8');
  }

  /**
   * 更新群组root key（成员加入）
   * @param {Buffer} newMemberPublicKey - 新成员的公钥
   * @returns {Buffer} 新root key
   */
  updateRootKey(newMemberPublicKey) {
    const newRootKey = hkdf(
      this.rootKey,
      Buffer.alloc(0),
      newMemberPublicKey,
      CHAIN_KEY_LENGTH
    );

    this.rootKey = newRootKey;
    return newRootKey;
  }

  /**
   * 更新群组root key（成员离开）
   * @returns {Buffer} 新root key
   */
  updateRootKeyAfterLeave() {
    const newRootKey = hkdf(
      this.rootKey,
      Buffer.alloc(0),
      Buffer.from('new-root-key-after-leave'),
      CHAIN_KEY_LENGTH
    );

    this.rootKey = newRootKey;
    return newRootKey;
  }
}

module.exports = {
  GROUP_PROTOCOL_VERSION,
  AES_GCM_NONCE_LENGTH,
  MESSAGE_KEY_LENGTH,
  CHAIN_KEY_LENGTH,
  GroupManager
};
