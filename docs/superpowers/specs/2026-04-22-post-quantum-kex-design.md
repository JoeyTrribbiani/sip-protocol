# 抗量子密钥交换设计文档

> 版本: v1.0
> 日期: 2026-04-22
> 状态: 概念设计（暂不实现）
> 关联: L6 (sip-protocol-report.md Section 8.5.3 L6)

## 1. 问题陈述

当前SIP使用X25519（ECDH），在量子计算机面前不安全（Shor算法可破解椭圆曲线）。需要研究抗量子密钥交换算法。

## 2. 候选算法

| 算法 | 类型 | NIST状态 | 密钥大小 | 速度 |
|------|------|---------|---------|------|
| CRYSTALS-Kyber | KEM（密钥封装） | ✅ 标准化 | 768/1024/1568 bytes | 快 |
| CRYSTALS-Dilithium | 数字签名 | ✅ 标准化 | 1312/1952/2592 bytes | 中 |
| SPHINCS+ | 哈希签名 | ✅ 标准化 | 32/64/128 bytes | 慢 |

## 3. 混合方案（推荐）

```
当前: X25519 (ECDH)
未来: X25519 + CRYSTALS-Kyber (Hybrid KEM)

握手流程:
1. Agent A 生成 X25519 + Kyber 公钥对
2. Agent B 生成 X25519 + Kyber 公钥对
3. 双方交换公钥
4. 每方计算:
   - shared_secret_1 = X25519(priv_A, pub_B)
   - shared_secret_2 = Kyber.Encaps(priv_A, pub_B)
   - final_secret = HKDF(shared_secret_1 || shared_secret_2)
```

**优势**：只要X25519或Kyber其中一个不被破解，密钥就是安全的。

## 4. 对现有协议的影响

- Triple DH握手 → Triple Hybrid DH（每次DH增加一次Kyber操作）
- 消息格式 → 公钥大小增加（X25519 32字节 → Kyber-768 768字节）
- 性能 → Kyber操作比X25519慢10-100倍（仍在毫秒级）
- 密钥存储 → 密钥体积增大3-5倍

## 5. 实现路径

```
Phase 1 (准备):
  - 评估 Python Kyber 库（首选：`liboqs-python`，Open Quantum Safe项目的参考实现；备选：pycryptodome）
  - 确认 CI 环境（Python 3.11）兼容性

Phase 2 (PoC):
  - 实现 Hybrid KEM 函数
  - 修改 handshake.py 支持混合握手
  - 性能基准测试

Phase 3 (生产):
  - 协议版本协商（SIP-2.0 = hybrid, SIP-1.x = classical）
  - 默认启用混合模式
```

## 6. 实现前置条件

| 前置 | 状态 |
|------|------|
| Python Kyber 库评估 | ❌ |
| 有抗量子合规需求 | ❌ |
| NIST后量子标准最终化 | ✅ (FIPS 203/204/205) |

## 7. 模块位置（预留）

```
python/src/sip_protocol/
├── crypto/
│   ├── kyber.py          # CRYSTALS-Kyber KEM（待实现）
│   └── hybrid_kem.py     # X25519 + Kyber 混合KEM（待实现）
```
