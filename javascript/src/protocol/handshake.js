/**
 * 握手协议模块
 * 实现SIP握手流程（三重DH + HMAC签名）
 */

const { generateKeyPair, dhExchange } = require('../crypto/dh');
const { hashPsk, deriveKeysTripleDH } = require('../crypto/hkdf');
const crypto = require('crypto');

const HANDSHAKE_NONCE_LENGTH = 16;
const PROTOCOL_VERSION = 'SIP-1.0';

/**
 * 发起握手（三重DH + 身份密钥对）
 * @param {Buffer} psk - 预共享密钥
 * @param {Object} identityPrivateKey - 身份私钥（可选，用于持久化）
 * @param {Object} identityPublicKey - 身份公钥（可选，用于持久化）
 * @returns {Object} { handshakeHello, agentState }
 */
async function initiateHandshake(psk, identityPrivateKey = null, identityPublicKey = null) {
  // 生成或使用身份密钥对（持久化）
  if (!identityPrivateKey || !identityPublicKey) {
    const identityKeyPair = generateKeyPair();
    identityPrivateKey = identityKeyPair.privateKey;
    identityPublicKey = identityKeyPair.publicKey;
  }

  // 生成临时密钥对（每次握手不同）
  const { privateKey: ephemeralPrivateKey, publicKey: ephemeralPublicKey } = generateKeyPair();

  // 生成Nonce
  const nonce = crypto.randomBytes(HANDSHAKE_NONCE_LENGTH);

  // 序列化公钥（Raw格式）
  const identityPubBytes = identityPublicKey.export({ type: 'spki', format: 'der' });
  const ephemeralPubBytes = ephemeralPublicKey.export({ type: 'spki', format: 'der' });

  // 构建Handshake_Hello消息
  const handshakeHello = {
    version: PROTOCOL_VERSION,
    type: 'handshake',
    step: 'hello',
    timestamp: Date.now(),
    identity_pub: identityPubBytes.toString('hex'),
    ephemeral_pub: ephemeralPubBytes.toString('hex'),
    nonce: nonce.toString('hex')
  };

  // 保存Agent状态
  const agentState = {
    identityPrivateKey,
    identityPublicKey,
    ephemeralPrivateKey,
    ephemeralPublicKey,
    psk,
    nonce,
    role: 'initiator'
  };

  return { handshakeHello, agentState };
}

/**
 * 响应握手（三重DH + HMAC签名）
 * @param {Object} handshakeHello - Handshake_Hello消息
 * @param {Buffer} psk - 预共享密钥
 * @param {Object} identityPrivateKey - 身份私钥（可选，用于持久化）
 * @param {Object} identityPublicKey - 身份公钥（可选，用于持久化）
 * @returns {Object} { handshakeAuth, agentState, sessionKeys }
 */
async function respondHandshake(handshakeHello, psk, identityPrivateKey = null, identityPublicKey = null) {
  // 验证时间戳（±5分钟）
  const currentTime = Date.now();
  const helloTime = handshakeHello.timestamp;
  if (Math.abs(currentTime - helloTime) > 5 * 60 * 1000) {
    throw new Error('时间戳验证失败：消息过期');
  }

  // 解析Handshake_Hello
  const remoteIdentityPub = crypto.createPublicKey({
    key: Buffer.from(handshakeHello.identity_pub, 'hex'),
    format: 'der',
    type: 'spki'
  });
  const remoteEphemeralPub = crypto.createPublicKey({
    key: Buffer.from(handshakeHello.ephemeral_pub, 'hex'),
    format: 'der',
    type: 'spki'
  });
  const remoteNonce = Buffer.from(handshakeHello.nonce, 'hex');

  // 生成或使用身份密钥对（持久化）
  if (!identityPrivateKey || !identityPublicKey) {
    const identityKeyPair = generateKeyPair();
    identityPrivateKey = identityKeyPair.privateKey;
    identityPublicKey = identityKeyPair.publicKey;
  }

  // 生成临时密钥对（每次握手不同）
  const { privateKey: ephemeralPrivateKey, publicKey: ephemeralPublicKey } = generateKeyPair();
  const nonce = crypto.randomBytes(HANDSHAKE_NONCE_LENGTH);

  // 序列化本地公钥（Raw格式）
  const ephemeralPubBytes = ephemeralPublicKey.export({ type: 'spki', format: 'der' });

  // 三重DH密钥交换（响应方视角）
  // shared_1: identity_local × remote_ephemeral
  const shared1 = dhExchange(identityPrivateKey, remoteEphemeralPub);
  // shared_2: ephemeral_local × remote_identity
  const shared2 = dhExchange(ephemeralPrivateKey, remoteIdentityPub);
  // shared_3: ephemeral_local × remote_ephemeral
  const shared3 = dhExchange(ephemeralPrivateKey, remoteEphemeralPub);

  // PSK哈希
  const { pskHash } = await hashPsk(psk);

  // 派生会话密钥（三重DH）
  // 注意：由于X25519的对称性，shared_1和shared_2在双方视角下是交换的。
  // 为了派生相同的会话密钥，响应方需要交换shared_1和shared_2的顺序，以匹配发起方的视角。
  // 发起方（A）计算：shared_1 (identity_a × eph_b), shared_2 (eph_a × identity_b), shared_3 (eph_a × eph_b)
  // 响应方（B）计算：shared_1 (identity_b × eph_a), shared_2 (eph_b × identity_a), shared_3 (eph_b × eph_a)
  // 由于identity_b × eph_a = eph_a × identity_b，所以shared_1和shared_2在双方是交换的。
  // 响应方需要按照发起方的视角重新排列：shared_1'=shared_2, shared_2'=shared_1, shared_3'=shared_3
  const sessionKeys = deriveKeysTripleDH(shared2, shared1, shared3, pskHash, remoteNonce, nonce);

  // 生成HMAC签名
  const authData = {
    ephemeral_pub: ephemeralPubBytes.toString('hex'),
    nonce: nonce.toString('hex'),
    timestamp: Date.now()
  };
  const authJson = JSON.stringify(authData);
  const signature = crypto.createHmac('sha256', sessionKeys.authKey)
    .update(authJson)
    .digest();

  // 构建Handshake_Auth消息
  const handshakeAuth = {
    version: PROTOCOL_VERSION,
    type: 'handshake',
    step: 'auth',
    timestamp: Date.now(),
    auth_data: {
      ephemeral_pub: ephemeralPubBytes.toString('hex'),
      nonce: nonce.toString('hex')
    },
    signature: signature.toString('base64')
  };

  // 保存Agent状态
  const agentState = {
    identityPrivateKey,
    identityPublicKey,
    ephemeralPrivateKey,
    ephemeralPublicKey,
    psk,
    nonce,
    remoteIdentityPub,
    remoteEphemeralPub,
    remoteNonce,
    role: 'responder'
  };

  return { handshakeAuth, agentState, sessionKeys };
}

/**
 * 完成握手（三重DH + HMAC验证）
 * @param {Object} handshakeAuth - Handshake_Auth消息
 * @param {Object} agentState - Agent状态
 * @returns {Object} { sessionKeys, sessionState }
 */
async function completeHandshake(handshakeAuth, agentState) {
  // 验证时间戳（±5分钟）
  const currentTime = Date.now();
  const authTime = handshakeAuth.timestamp;
  if (Math.abs(currentTime - authTime) > 5 * 60 * 1000) {
    throw new Error('时间戳验证失败：消息过期');
  }

  // 解析Handshake_Auth
  const remoteEphemeralPub = crypto.createPublicKey({
    key: Buffer.from(handshakeAuth.auth_data.ephemeral_pub, 'hex'),
    format: 'der',
    type: 'spki'
  });
  const remoteNonce = Buffer.from(handshakeAuth.auth_data.nonce, 'hex');
  const signature = Buffer.from(handshakeAuth.signature, 'base64');

  // 三重DH密钥交换（发起方视角）
  // shared_1: identity_local × remote_ephemeral
  const shared1 = dhExchange(agentState.identityPrivateKey, remoteEphemeralPub);
  // shared_2: ephemeral_local × remote_identity
  const shared2 = dhExchange(agentState.ephemeralPrivateKey, agentState.remoteIdentityPub);
  // shared_3: ephemeral_local × remote_ephemeral
  const shared3 = dhExchange(agentState.ephemeralPrivateKey, remoteEphemeralPub);

  // PSK哈希
  const { pskHash } = await hashPsk(agentState.psk);

  // 派生会话密钥（三重DH）
  const sessionKeys = deriveKeysTripleDH(
    shared1,
    shared2,
    shared3,
    pskHash,
    agentState.nonce,
    remoteNonce
  );

  // 验证HMAC签名
  const authData = {
    ephemeral_pub: handshakeAuth.auth_data.ephemeral_pub,
    nonce: handshakeAuth.auth_data.nonce,
    timestamp: handshakeAuth.timestamp
  };
  const authJson = JSON.stringify(authData);
  const expectedSignature = crypto.createHmac('sha256', sessionKeys.authKey)
    .update(authJson)
    .digest();

  if (!crypto.timingSafeEqual(signature, expectedSignature)) {
    throw new Error('HMAC签名验证失败');
  }

  // 生成Handshake_Complete消息
  const completeAuthData = { status: 'verified' };
  const completeAuthJson = JSON.stringify(completeAuthData);
  const completeSignature = crypto.createHmac('sha256', sessionKeys.authKey)
    .update(completeAuthJson)
    .digest();

  const handshakeComplete = {
    version: PROTOCOL_VERSION,
    type: 'handshake',
    step: 'complete',
    timestamp: Date.now(),
    auth_data: completeAuthData,
    signature: completeSignature.toString('base64')
  };

  // 构建会话状态
  const sessionState = {
    version: PROTOCOL_VERSION,
    encryptionKey: sessionKeys.encryptionKey,
    authKey: sessionKeys.authKey,
    replayKey: sessionKeys.replayKey,
    createdAt: Date.now(),
    handshakeComplete: handshakeComplete
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
