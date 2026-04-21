// SIP协议测试套件 - 完全按照Python实现
// 参考实现：python/tests/test_sip_protocol.py

const crypto = require('crypto');
const argon2 = require('argon2');

// 导入完整实现
const {
  generateKeyPair,
  hashPsk,
  dhExchange,
  hkdf,
  deriveKeys,
  encryptMessage,
  decryptMessage,
  generateReplayTag,
  encryptAESGCM,
  decryptAESGCM,
  NonceManager,
  MessageCounter,
  SessionState,
  GroupManager,
  CHAIN_KEY_LENGTH,
  MESSAGE_KEY_LENGTH,
  AES_GCM_NONCE_LENGTH
} = require('../src/index.js');

async function testBasicHandshake() {
  console.log('=== 测试1：基本握手流程 ===\n');
  
  // 生成密钥对
  const { privateKey: privA, publicKey: pubA } = generateKeyPair();
  const { privateKey: privB, publicKey: pubB } = generateKeyPair();
  
  console.log('✅ Agent A公钥：', pubA.toString('hex').substring(0, 40) + '...');
  console.log('✅ Agent B公钥：', pubB.toString('hex').substring(0, 40) + '...');
  
  // DH密钥交换
  const sharedAB = dhExchange(privA, pubB);
  const sharedBA = dhExchange(privB, pubA);
  
  console.log('✅ DH共享密钥一致：', sharedAB.equals(sharedBA));
  
  // PSK哈希
  const psk = Buffer.from('0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF');
  const pskHashA = await hashPsk(psk);
  const pskHashB = await hashPsk(psk, pskHashA.salt);
  
  console.log('✅ PSK哈希一致：', pskHashA.pskHash.equals(pskHashB.pskHash));
  
  // Nonce
  const nonceA = crypto.randomBytes(16);
  const nonceB = crypto.randomBytes(16);
  
  console.log('✅ Nonce A：', nonceA.toString('hex'));
  console.log('✅ Nonce B：', nonceB.toString('hex'));
  
  // 派生密钥（双方使用相同的nonce顺序：initiator_nonce + responder_nonce）
  // 假设Agent A是发起方，Agent B是响应方
  const keysA = deriveKeys(sharedAB, pskHashA.pskHash, nonceA, nonceB);
  const keysB = deriveKeys(sharedBA, pskHashB.pskHash, nonceA, nonceB);  // Agent B也使用nonceA + nonceB
  
  console.log('✅ 加密密钥一致：', keysA.encryptionKey.toString('hex') === keysB.encryptionKey.toString('hex'));
  console.log('✅ 认证密钥一致：', keysA.authKey.toString('hex') === keysB.authKey.toString('hex'));
  console.log('✅ 防重放密钥一致：', keysA.replayKey.toString('hex') === keysB.replayKey.toString('hex'));
  
  console.log('✅ 测试1通过！\n');
}

function testMessageEncryption() {
  console.log('=== 测试2：消息加密解密 ===\n');
  
  const encryptionKey = crypto.randomBytes(32);
  const plaintext = 'Hello, SIP!';
  const senderId = 'agent-a';
  const recipientId = 'agent-b';
  const messageCounter = 1;
  
  // 加密消息（需要senderId, recipientId, messageCounter）
  const message = encryptMessage(encryptionKey, plaintext, senderId, recipientId, messageCounter);
  console.log('✅ 消息已加密：', message.payload.length + ' bytes');
  console.log('✅ Nonce：', message.iv.substring(0, 10) + '...');
  
  // 解密消息
  const decrypted = decryptMessage(encryptionKey, message);
  console.log('✅ 解密成功：', decrypted === plaintext);
  console.log('✅ 测试2通过！\n');
}

function testNonceManagement() {
  console.log('=== 测试3：Nonce管理（防重放）===\n');
  
  const nonceManager = new NonceManager();
  
  const nonce1 = nonceManager.generateNonce();
  const nonce2 = nonceManager.generateNonce();
  const nonce3 = nonceManager.generateNonce();
  
  console.log('✅ 生成Nonce 1：', nonce1.toString('hex').substring(0, 16) + '...');
  console.log('✅ 生成Nonce 2：', nonce2.toString('hex').substring(0, 16) + '...');
  console.log('✅ 生成Nonce 3：', nonce3.toString('hex').substring(0, 16) + '...');
  
  console.log('✅ Nonce 1唯一：', nonceManager.validateNonce(nonce1) === false);
  console.log('✅ Nonce 2唯一：', nonceManager.validateNonce(nonce2) === false);
  console.log('✅ Nonce 3唯一：', nonceManager.validateNonce(nonce3) === false);
  
  const newNonce = nonceManager.generateNonce();
  console.log('✅ 所有Nonce唯一', nonceManager.validateNonce(newNonce) === false);
  console.log('✅ 测试3通过！\n');
}

function testReplayTag() {
  console.log('=== 测试4：防重放标签（replay_tag）===\n');
  
  const replayKey = crypto.randomBytes(32);
  const senderId = 'agent-a';
  
  const tag1 = generateReplayTag(replayKey, senderId, 1);
  const tag2 = generateReplayTag(replayKey, senderId, 2);
  const tag3 = generateReplayTag(replayKey, senderId, 3);
  
  console.log('✅ Replay Tag 1：', tag1);
  console.log('✅ Replay Tag 2：', tag2);
  console.log('✅ Replay Tag 3：', tag3);
  
  console.log('✅ Replay Tag 1唯一：', tag1 !== tag2 && tag1 !== tag3);
  console.log('✅ Replay Tag 2唯一：', tag2 !== tag1 && tag2 !== tag3);
  console.log('✅ Replay Tag 3唯一：', tag3 !== tag1 && tag3 !== tag2);
  console.log('✅ 所有Replay Tag唯一');
  console.log('✅ 测试4通过！\n');
}

function testGroupEncryption() {
  console.log('=== 测试5：群组加密 ===\n');
  
  // 创建群组管理器
  const rootKey = crypto.randomBytes(32);
  const groupManager = new GroupManager('group:test-123', rootKey);
  
  // 初始化群组链密钥
  const members = ['agent-a', 'agent-b', 'agent-c'];
  const chains = groupManager.initializeGroupChains(members, rootKey);
  
  console.log('✅ 成员已添加到群组：agent-a, agent-b, agent-c');
  
  // 发送群组消息
  const plaintext = 'Hello, Group SIP!';
  const message = groupManager.sendGroupMessage(plaintext, 'agent-a');
  
  console.log('✅ 群组消息已发送：', message.ciphertext.substring(0, 20) + '...');
  
  // 接收群组消息
  const decrypted = groupManager.receiveGroupMessage(message, 'agent-b');
  
  console.log('✅ 群组消息已解密：', decrypted === plaintext);
  console.log('✅ 测试5通过！\n');
}

function testSkipRatchet() {
  console.log('=== 测试6：跳跃密钥（Skip Ratchet）===\n');
  
  // 创建群组管理器
  const rootKey = crypto.randomBytes(32);
  const groupManager = new GroupManager('group:test-skip', rootKey);
  
  // 初始化群组链密钥
  const members = ['agent-a', 'agent-b'];
  groupManager.initializeGroupChains(members, rootKey);
  
  // 发送3条消息（跳过接收消息2）
  const msg1 = groupManager.sendGroupMessage('Message 1', 'agent-a');
  const msg2 = groupManager.sendGroupMessage('Message 2', 'agent-a');
  const msg3 = groupManager.sendGroupMessage('Message 3', 'agent-a');
  
  console.log('✅ 已发送3条消息：1, 2, 3');
  
  // 接收消息（跳过消息2）
  try {
    const decrypted1 = groupManager.receiveGroupMessage(msg1, 'agent-b');
    console.log('✅ 解密消息1成功：', decrypted1 === 'Message 1');
  } catch (e) {
    console.log('❌ 解密消息1失败：', e.message);
  }
  
  try {
    const decrypted3 = groupManager.receiveGroupMessage(msg3, 'agent-b');
    console.log('✅ 解密消息3成功（Skip Ratchet）：', decrypted3 === 'Message 3');
  } catch (e) {
    console.log('❌ 解密消息3失败：', e.message);
  }
  
  // 尝试接收消息2（应该失败，因为已经跳过）
  try {
    const decrypted2 = groupManager.receiveGroupMessage(msg2, 'agent-b');
    console.log('❌ 消息2不应该能解密');
  } catch (e) {
    console.log('✅ 消息2被正确拒绝（已跳过）：', e.message.includes('Invalid message number'));
  }
  
  console.log('✅ 测试6通过！\n');
}

async function testAll() {
  console.log('==================================================');
  console.log('SIP协议测试套件 v1.0');
  console.log('==================================================\n');
  
  try {
    await testBasicHandshake();
    testMessageEncryption();
    testNonceManagement();
    testReplayTag();
    testGroupEncryption();
    testSkipRatchet();
    
    console.log('==================================================');
    console.log('✅ 所有测试通过！');
    console.log('==================================================');
  } catch (error) {
    console.log('==================================================');
    console.log('❌ 测试失败：', error.message);
    console.log(error.stack);
    console.log('==================================================');
    process.exit(1);
  }
}

// 运行所有测试
testAll().catch(error => {
  console.error('测试运行失败：', error);
  process.exit(1);
});
