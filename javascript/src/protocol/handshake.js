/**
 * 握手协议模块
 * 实现SIP握手流程
 */

const { generateKeyPair, dhExchange } = require('../crypto/dh');
const { hashPsk } = require('../crypto/argon2');
const { deriveKeys } = require('../crypto/hkdf');
const crypto = require('crypto');

const HANDSHAKE_NONCE_LENGTH = 16;
const PROTOCOL_VERSION = 'SIP-1.0';

/**
 * 发起握手
 * @param {Buffer} psk - 预共享密钥
 * @returns {Object} { handshakeHello, agentState }
 */
async function initiateHandshake(psk) {
  // 生成密钥对
  const { privateKey, publicKey } = generateKeyPair();
  
  // 生成Nonce
  const nonce = crypto.randomBytes(HANDSHAKE_NONCE_LENGTH);
  
  // 构建Handshake_Hello消息
  const handshakeHello = {
    version: PROTOCOL_VERSION,
    type: 'handshake_hello',
    ephemeral_public_key: publicKey.export({ type: 'spki', format: 'pem' }),
    nonce: nonce.toString('hex')
  };
  
  // 保存Agent状态
  const agentState = {
    privateKey,
    psk,
    nonce
  };
  
  return { handshakeHello, agentState };
}

/**
 * 响应握手
 * @param {Object} handshakeHello - Handshake_Hello消息
 * @param {Buffer} psk - 预共享密钥
 * @returns {Object} { handshakeAuth, agentState, sessionKeys }
 */
async function respondHandshake(handshakeHello, psk) {
  // 解析Handshake_Hello
  const ephemeralPublicKey = crypto.createPublicKey(
    handshakeHello.ephemeral_public_key
  );
  const remoteNonce = Buffer.from(handshakeHello.nonce, 'hex');
  
  // 生成密钥对和Nonce
  const { privateKey, publicKey } = generateKeyPair();
  const nonce = crypto.randomBytes(HANDSHAKE_NONCE_LENGTH);
  
  // DH密钥交换
  const sharedSecret = dhExchange(privateKey, ephemeralPublicKey);
  
  // PSK哈希
  const { pskHash } = await hashPsk(psk);
  
  // 派生会话密钥
  const sessionKeys = deriveKeys(sharedSecret, pskHash, nonce, remoteNonce);
  
  // 构建Handshake_Auth消息
  const handshakeAuth = {
    version: PROTOCOL_VERSION,
    type: 'handshake_auth',
    ephemeral_public_key: publicKey.export({ type: 'spki', format: 'pem' }),
    nonce: nonce.toString('hex')
  };
  
  // 保存Agent状态
  const agentState = {
    privateKey,
    psk,
    nonce,
    remoteEphemeralPublicKey: ephemeralPublicKey
  };
  
  return { handshakeAuth, agentState, sessionKeys };
}

/**
 * 完成握手
 * @param {Object} handshakeAuth - Handshake_Auth消息
 * @param {Object} agentState - Agent状态
 * @returns {Object} { sessionKeys, sessionState }
 */
async function completeHandshake(handshakeAuth, agentState) {
  // 解析Handshake_Auth
  const ephemeralPublicKey = crypto.createPublicKey(
    handshakeAuth.ephemeral_public_key
  );
  const remoteNonce = Buffer.from(handshakeAuth.nonce, 'hex');
  
  // DH密钥交换
  const sharedSecret = dhExchange(agentState.privateKey, ephemeralPublicKey);
  
  // PSK哈希
  const { pskHash } = await hashPsk(agentState.psk);
  
  // 派生会话密钥
  const sessionKeys = deriveKeys(sharedSecret, pskHash, agentState.nonce, remoteNonce);
  
  // 构建会话状态
  const sessionState = {
    version: PROTOCOL_VERSION,
    encryptionKey: sessionKeys.encryptionKey,
    authKey: sessionKeys.authKey,
    replayKey: sessionKeys.replayKey,
    createdAt: Date.now()
  };
  
  return { sessionKeys, sessionState };
}

module.exports = {
  HANDSHAKE_NONCE_LENGTH,
  PROTOCOL_VERSION,
  initiateHandshake,
  respondHandshake,
  completeHandshake
};
