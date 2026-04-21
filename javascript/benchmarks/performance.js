/**
 * 性能基准测试
 * 验证性能要求是否达标
 */

const {
  generateKeyPair,
  dhExchange,
  hkdf,
  encryptAESGCM,
  decryptAESGCM
} = require('../src/index.js');
const crypto = require('crypto');

function benchmark(name, fn, iterations = 1000) {
  const start = process.hrtime.bigint();
  for (let i = 0; i < iterations; i++) {
    fn();
  }
  const end = process.hrtime.bigint();
  const duration = Number(end - start) / 1000000; // 纳秒转毫秒
  const avg = duration / iterations;
  return avg;
}

console.log('====================================');
console.log('SIP协议性能基准测试');
console.log('====================================\n');

// 1. DH密钥交换
console.log('1. DH密钥交换');
const { privateKey: privA, publicKey: pubA } = generateKeyPair();
const { privateKey: privB, publicKey: pubB } = generateKeyPair();
const dhTime = benchmark('DH密钥交换', () => {
  dhExchange(privA, pubB);
});
console.log(`   平均时间：${dhTime.toFixed(3)}ms`);
console.log(`   要求：< 10ms`);
console.log(`   状态：${dhTime < 10 ? '✅ 通过' : '❌ 失败'}\n`);

// 2. HKDF密钥派生
console.log('2. HKDF密钥派生');
const ikm = crypto.randomBytes(32);
const salt = Buffer.alloc(0);
const info = Buffer.from('message-key');
const hkdfTime = benchmark('HKDF密钥派生', () => {
  hkdf(ikm, salt, info, 32);
});
console.log(`   平均时间：${hkdfTime.toFixed(3)}ms`);
console.log(`   要求：< 5ms`);
console.log(`   状态：${hkdfTime < 5 ? '✅ 通过' : '❌ 失败'}\n`);

// 3. AES-GCM加密（1KB）
console.log('3. AES-GCM加密（1KB）');
const key = crypto.randomBytes(32);
const plaintext = Buffer.alloc(1024, 'x');
const iv = crypto.randomBytes(12);
const aesTime = benchmark('AES-GCM加密（1KB）', () => {
  encryptAESGCM(key, plaintext, iv);
});
console.log(`   平均时间：${aesTime.toFixed(3)}ms`);
console.log(`   要求：< 1ms`);
console.log(`   状态：${aesTime < 1 ? '✅ 通过' : '❌ 失败'}\n`);

// 4. 群组加密（顺序）
console.log('4. 群组加密（顺序）');
const chainKey = crypto.randomBytes(32);
const groupInOrderTime = benchmark('群组加密（顺序）', () => {
  hkdf(chainKey, Buffer.alloc(0), Buffer.from('message-key'), 32);
});
console.log(`   平均时间：${groupInOrderTime.toFixed(3)}ms`);
console.log(`   要求：< 0.5ms`);
console.log(`   状态：${groupInOrderTime < 0.5 ? '✅ 通过' : '❌ 失败'}\n`);

// 5. 群组加密（乱序，需要预生成3个跳跃密钥）
console.log('5. 群组加密（乱序）');
let currentKey = chainKey;
const groupOutOfOrderTime = benchmark('群组加密（乱序）', () => {
  for (let i = 0; i < 3; i++) {
    hkdf(currentKey, Buffer.alloc(0), Buffer.from('message-key'), 32);
    currentKey = hkdf(currentKey, Buffer.alloc(0), Buffer.from('chain-key'), 32);
  }
});
console.log(`   平均时间：${groupOutOfOrderTime.toFixed(3)}ms`);
console.log(`   要求：< 2ms`);
console.log(`   状态：${groupOutOfOrderTime < 2 ? '✅ 通过' : '❌ 失败'}\n`);

// 汇总结果
const results = {
  dh: dhTime.toFixed(3),
  hkdf: hkdfTime.toFixed(3),
  aes: aesTime.toFixed(3),
  group_in_order: groupInOrderTime.toFixed(3),
  group_out_of_order: groupOutOfOrderTime.toFixed(3)
};

// 保存结果
const fs = require('fs');
fs.writeFileSync(
  'benchmarks/results.json',
  JSON.stringify(results, null, 2)
);

console.log('====================================');
console.log('性能测试完成！');
console.log('====================================');
console.log(`\n所有测试通过：${[
  dhTime < 10,
  hkdfTime < 5,
  aesTime < 1,
  groupInOrderTime < 0.5,
  groupOutOfOrderTime < 2
].every(Boolean) ? '✅ 是' : '❌ 否'}`);
