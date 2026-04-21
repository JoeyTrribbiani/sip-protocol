// SIP协议完整握手示例
const crypto = require('crypto');
const { x25519 } = require('@noble/ciphers');
const argon2 = require('argon2');

// 导入完整实现
const {
  generateKeyPair,
  hashPsk,
  dhExchange,
  deriveKeys,
  encryptMessage,
  decryptMessage,
  SessionState
} = require('../sip_protocol_complete.js');

// 常量
const NONCE_LENGTH = 16;
const KDF_SALT = Buffer.from('SIPHandshake');
const KDF_INFO = Buffer.from('session-keys');

function agentAInit() {
  console.log('=== Agent A初始化 ===');
  
  // 生成密钥对
  const { privateKey: privA, publicKey: pubA } = generateKeyPair();
  console.log('Agent A公钥：', pubA.toString('hex').substring(0, 32) + '...');
  
  // 生成PSK（可选）
  const psk = Buffer.from('shared-secret-key-12345678');
  const { pskHash: pskHashA, salt: saltA } = hashPsk(psk);
  console.log('PSK哈希：', pskHashA.toString('hex').substring(0, 32) + '...');
  
  // 生成nonce
  const nonceA = crypto.randomBytes(NONCE_LENGTH);
  console.log('Nonce A：', nonceA.toString('hex'));
  
  return { privA, pubA, pskHashA, saltA, nonceA };
}

function agentBInit(saltA) {
  console.log('\n=== Agent B初始化 ===');
  
  // 生成密钥对
  const { privateKey: privB, publicKey: pubB } = generateKeyPair();
  console.log('Agent B公钥：', pubB.toString('hex').substring(0, 32) + '...');
  
  // 使用相同的PSK和salt
  const psk = Buffer.from('shared-secret-key-12345678');
  const { pskHash: pskHashB } = hashPsk(psk, saltA);
  console.log('PSK哈希：', pskHashB.toString('hex').substring(0, 32) + '...');
  
  // 生成nonce
  const nonceB = crypto.randomBytes(NONCE_LENGTH);
  console.log('Nonce B：', nonceB.toString('hex'));
  
  return { privB, pubB, pskHashB, nonceB };
}

function handshakeComplete() {
  console.log('\n=== 握手流程 ===');
  
  // Agent A初始化
  const { privA, pubA, pskHashA, saltA, nonceA } = agentAInit();
  
  // Agent B初始化
  const { privB, pubB, pskHashB, nonceB } = agentBInit(saltA);
  
  // DH密钥交换（三重DH）
  console.log('\n=== DH密钥交换（三重DH）===');
  
  // Agent A计算DH
  const dhAB = dhExchange(privA, pubB);
  const dhAAA = dhExchange(privA, pubA);  // 自DH
  console.log('DH AB：', dhAB.toString('hex').substring(0, 32) + '...');
  console.log('DH AAA：', dhAAA.toString('hex').substring(0, 32) + '...');
  
  // Agent B计算DH
  const dhBA = dhExchange(privB, pubA);
  const dhBBB = dhExchange(privB, pubB);  // 自DH
  console.log('DH BA：', dhBA.toString('hex').substring(0, 32) + '...');
  console.log('DH BBB：', dhBBB.toString('hex').substring(0, 32) + '...');
  
  // 派生密钥
  console.log('\n=== 派生会话密钥 ===');
  
  // Agent A派生
  const ikmA = Buffer.concat([dhAB, dhAAA, pskHashA, nonceA, nonceB]);
  const kdfA = crypto.hkdfSync('sha256', ikmA, KDF_SALT, KDF_INFO, 96);
  const encKeyA = kdfA.subarray(0, 32);
  const authKeyA = kdfA.subarray(32, 64);
  const replayKeyA = kdfA.subarray(64, 96);
  
  console.log('Agent A加密密钥：', encKeyA.toString('hex').substring(0, 32) + '...');
  console.log('Agent A认证密钥：', authKeyA.toString('hex').substring(0, 32) + '...');
  console.log('Agent A防重放密钥：', replayKeyA.toString('hex').substring(0, 32) + '...');
  
  // Agent B派生
  const ikmB = Buffer.concat([dhBA, dhBBB, pskHashB, nonceA, nonceB]);
  const kdfB = crypto.hkdfSync('sha256', ikmB, KDF_SALT, KDF_INFO, 96);
  const encKeyB = kdfB.subarray(0, 32);
  const authKeyB = kdfB.subarray(32, 64);
  const replayKeyB = kdfB.subarray(64, 96);
  
  console.log('Agent B加密密钥：', encKeyB.toString('hex').substring(0, 32) + '...');
  console.log('Agent B认证密钥：', authKeyB.toString('hex').substring(0, 32) + '...');
  console.log('Agent B防重放密钥：', replayKeyB.toString('hex').substring(0, 32) + '...');
  
  // 验证密钥一致
  console.log('\n=== 验证密钥 ===');
  console.log('加密密钥一致：', encKeyA.toString('hex') === encKeyB.toString('hex'));
  console.log('认证密钥一致：', authKeyA.toString('hex') === authKeyB.toString('hex'));
  console.log('防重放密钥一致：', replayKeyA.toString('hex') === replayKeyB.toString('hex'));
  
  // 发送第一条消息
  console.log('\n=== 发送第一条消息 ===');
  
  const plaintext = 'Hello, Agent B! This is a secure E2EE message.';
  const message = encryptMessage(encKeyA, plaintext, 'agent-a', 1);
  
  console.log('明文：', plaintext);
  console.log('密文：', message.ciphertext.substring(0, 32) + '...');
  console.log('Nonce：', message.nonce.substring(0, 16) + '...');
  
  // 解密消息（Agent B）
  const decrypted = decryptMessage(encKeyB, message);
  
  console.log('解密：', decrypted === plaintext ? '成功' : '失败');
  console.log('解密文本：', decrypted);
  
  // 保存会话状态
  const sessionState = new SessionState();
  sessionState.agentId = 'agent-a';
  sessionState.remoteAgentId = 'agent-b';
  sessionState.remotePublicKey = pubB.toString('hex');
  sessionState.encryptionKey = encKeyA.toString('hex');
  sessionState.authKey = authKeyA.toString('hex');
  sessionState.replayKey = replayKeyA.toString('hex');
  sessionState.messageCounter = 1;
  sessionState.pskHash = pskHashA.toString('hex');
  sessionState.salt = saltA.toString('hex');
  sessionState.localNonce = nonceA.toString('hex');
  sessionState.remoteNonce = nonceB.toString('hex');
  
  console.log('\n=== 会话状态 ===');
  console.log(JSON.stringify(sessionState, null, 2));
  
  console.log('\n✅ 握手完成！Agent A和Agent B已建立安全通道！');
  console.log('✅ 现在可以使用加密通道进行通信！');
}

function main() {
  console.log('');
  console.log('='.repeat(60));
  console.log('SIP协议完整握手示例 v1.0');
  console.log('='.repeat(60));
  console.log('');
  
  try {
    handshakeComplete();
  } catch (error) {
    console.log('\n❌ 握手失败：', error.message);
    console.error(error);
    process.exit(1);
  }
}

// 运行示例
if (require.main === module) {
  main();
}
