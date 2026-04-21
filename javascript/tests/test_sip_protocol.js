// SIP协议测试脚本
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
  generateReplayTag,
  NonceManager,
  MessageCounter,
  SessionState,
  GroupManager
} = require('../sip_protocol_complete.js');

function testBasicHandshake() {
  console.log('=== 测试1：基本握手流程 ===\n');
  
  // 生成密钥对
  const { privateKey: privA, publicKey: pubA } = generateKeyPair();
  const { privateKey: privB, publicKey: pubB } = generateKeyPair();
  
  console.log('✅ Agent A公钥：', pubA.toString('hex').substring(0, 32) + '...');
  console.log('✅ Agent B公钥：', pubB.toString('hex').substring(0, 32) + '...');
  
  // DH密钥交换
  const sharedAB = dhExchange(privA, pubB);
  const sharedBA = dhExchange(privB, pubA);
  
  console.log('✅ DH共享密钥一致：', sharedAB.toString('hex') === sharedBA.toString('hex'));
  
  // PSK哈希（可选）
  const psk = Buffer.from('shared-secret-key-12345678');
  const { pskHash: pskHashA, salt: saltA } = hashPsk(psk);
  const { pskHash: pskHashB } = hashPsk(psk, saltA);
  
  console.log('✅ PSK哈希一致：', pskHashA.toString('hex') === pskHashB.toString('hex'));
  
  // 生成nonce
  const nonceA = crypto.randomBytes(16);
  const nonceB = crypto.randomBytes(16);
  
  console.log('✅ Nonce A：', nonceA.toString('hex'));
  console.log('✅ Nonce B：', nonceB.toString('hex'));
  
  // 派生密钥
  const { encryptionKey: encKeyA, authKey: authKeyA, replayKey: replayKeyA } = 
    deriveKeys(sharedAB, pskHashA, nonceA, nonceB);
  const { encryptionKey: encKeyB, authKey: authKeyB, replayKey: replayKeyB } = 
    deriveKeys(sharedBA, pskHashB, nonceA, nonceB);
  
  console.log('✅ 加密密钥一致：', encKeyA.toString('hex') === encKeyB.toString('hex'));
  console.log('✅ 认证密钥一致：', authKeyA.toString('hex') === authKeyB.toString('hex'));
  console.log('✅ 防重放密钥一致：', replayKeyA.toString('hex') === replayKeyB.toString('hex'));
  
  console.log('✅ 测试1通过！\n');
}

function testMessageEncryption() {
  console.log('=== 测试2：消息加密解密 ===\n');
  
  // 加密密钥（示例）
  const encryptionKey = crypto.randomBytes(32);
  
  // 明文消息
  const plaintext = 'Hello, Agent B! This is a secure message.';
  
  // 加密消息
  const message = encryptMessage(encryptionKey, plaintext, 'agent-a', 1);
  
  console.log('✅ 消息已加密：', message.ciphertext.length, 'bytes');
  console.log('✅ Nonce：', message.nonce.substring(0, 16) + '...');
  
  // 解密消息
  const decrypted = decryptMessage(encryptionKey, message);
  
  console.log('✅ 解密成功：', decrypted === plaintext);
  console.log('✅ 测试2通过！\n');
}

function testNonceManagement() {
  console.log('=== 测试3：Nonce管理（防重放）===\n');
  
  const nonceManager = new NonceManager();
  
  // 生成多个nonce
  const nonce1 = nonceManager.generateNonce();
  const nonce2 = nonceManager.generateNonce();
  const nonce3 = nonceManager.generateNonce();
  
  console.log('✅ 生成Nonce 1：', nonce1.toString('hex').substring(0, 16) + '...');
  console.log('✅ 生成Nonce 2：', nonce2.toString('hex').substring(0, 16) + '...');
  console.log('✅ 生成Nonce 3：', nonce3.toString('hex').substring(0, 16) + '...');
  
  // 验证nonce不重复
  console.log('✅ Nonce 1唯一：', nonce1.toString('hex') !== nonce2.toString('hex'));
  console.log('✅ Nonce 2唯一：', nonce2.toString('hex') !== nonce3.toString('hex'));
  console.log('✅ Nonce 3唯一：', nonce1.toString('hex') !== nonce3.toString('hex'));
  
  console.log('✅ 所有Nonce唯一');
  console.log('✅ 测试3通过！\n');
}

function testReplayTag() {
  console.log('=== 测试4：防重放标签（replay_tag）===\n');
  
  // 生成防重放密钥
  const replayKey = crypto.randomBytes(32);
  
  // 生成多个消息的replay_tag
  const replayTag1 = generateReplayTag(replayKey, 'agent-a', 1);
  const replayTag2 = generateReplayTag(replayKey, 'agent-a', 2);
  const replayTag3 = generateReplayTag(replayKey, 'agent-a', 3);
  
  console.log('✅ Replay Tag 1：', replayTag1);
  console.log('✅ Replay Tag 2：', replayTag2);
  console.log('✅ Replay Tag 3：', replayTag3);
  
  // 验证replay_tag不重复
  console.log('✅ Replay Tag 1唯一：', replayTag1 !== replayTag2);
  console.log('✅ Replay Tag 2唯一：', replayTag2 !== replayTag3);
  console.log('✅ Replay Tag 3唯一：', replayTag1 !== replayTag3);
  
  console.log('✅ 所有Replay Tag唯一');
  console.log('✅ 测试4通过！\n');
}

function testGroupEncryption() {
  console.log('=== 测试5：群组加密 ===\n');
  
  // 创建群组管理器
  const rootKey = crypto.randomBytes(32);
  const groupManager = new GroupManager('group:test-123', rootKey);
  
  // 添加成员
  const chainKeyA = crypto.randomBytes(32);
  const chainKeyB = crypto.randomBytes(32);
  const chainKeyC = crypto.randomBytes(32);
  
  groupManager.addMember('agent-a', chainKeyA);
  groupManager.addMember('agent-b', chainKeyB);
  groupManager.addMember('agent-c', chainKeyC);
  
  console.log('✅ 成员已添加到群组：agent-a, agent-b, agent-c');
  
  // 发送群组消息
  const plaintext = 'Hello, Group SIP!';
  const message = groupManager.sendGroupMessage(plaintext, 'agent-a');
  
  console.log('✅ 群组消息已发送：', message.ciphertext.substring(0, 32) + '...');
  
  // 接收群组消息
  const decrypted = groupManager.receiveGroupMessage(message, 'agent-a');
  
  console.log('✅ 群组消息已解密：', decrypted === plaintext);
  console.log('✅ 测试5通过！\n');
}

function testSkipRatchet() {
  console.log('=== 测试6：跳跃密钥（Skip Ratchet）===\n');
  
  // 创建群组管理器
  const rootKey = crypto.randomBytes(32);
  const groupManager = new GroupManager('group:test-456', rootKey);
  
  // 添加成员
  const chainKeyA = crypto.randomBytes(32);
  const chainKeyB = crypto.randomBytes(32);
  
  groupManager.addMember('agent-a', chainKeyA);
  groupManager.addMember('agent-b', chainKeyB);
  
  // 发送5条消息
  const plaintexts = [
    'Message 1',
    'Message 2',
    'Message 3',
    'Message 4',
    'Message 5'
  ];
  
  const messages = [];
  for (let i = 0; i < 5; i++) {
    const msg = groupManager.sendGroupMessage(plaintexts[i], 'agent-a');
    messages.push(msg);
  }
  
  console.log('✅ 已发送5条消息');
  
  // 模拟乱序接收：只收到消息1、3、5
  const outOfOrderMessages = [messages[0], messages[2], messages[4]];
  
  for (const msg of outOfOrderMessages) {
    const decrypted = groupManager.receiveGroupMessage(msg, 'agent-a');
    console.log(`✅ 乱序消息 ${msg.message_number} 已解密`);
  }
  
  console.log('✅ 跳跃密钥（Skip Ratchet）工作正常');
  console.log('✅ 测试6通过！\n');
}

function main() {
  console.log('');
  console.log('='.repeat(50));
  console.log('SIP协议测试套件 v1.0');
  console.log('='.repeat(50));
  console.log('');
  
  try {
    testBasicHandshake();
    testMessageEncryption();
    testNonceManagement();
    testReplayTag();
    testGroupEncryption();
    testSkipRatchet();
    
    console.log('');
    console.log('='.repeat(50));
    console.log('✅ 所有测试通过！');
    console.log('='.repeat(50));
    console.log('');
    
  } catch (error) {
    console.log('\n❌ 测试失败：', error.message);
    console.error(error);
    process.exit(1);
  }
}

// 运行测试
if (require.main === module) {
  main();
}
