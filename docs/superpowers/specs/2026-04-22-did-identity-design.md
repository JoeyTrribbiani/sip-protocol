# DID 去中心化身份设计文档

> 版本: v1.0
> 日期: 2026-04-22
> 状态: 概念设计（暂不实现）
> 关联: L4 (sip-protocol-report.md Section 8.5.3 L1)

## 1. 问题陈述

当前SIP使用PSK，需要预共享密钥。无法支持动态Agent网络的信任建立。

## 2. DID 方案概述

基于W3C DID (Decentralized Identifier) 规范，让每个Agent拥有一个去中心化身份。

### 2.1 DID Document

```json
{
  "@context": "https://www.w3.org/ns/did/v1",
  "id": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
  "verificationMethod": [{
    "id": "key-1",
    "type": "Ed25519VerificationKey2020",
    "controller": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
    "publicKeyMultibase": "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
  }],
  "authentication": ["key-1"],
  "service": [{
    "id": "sip-endpoint",
    "type": "SIPProtocol",
    "serviceEndpoint": "https://agent.example.com/sip"
  }]
}
```

### 2.2 认证流程

```
1. Agent A 展示 DID → Agent B 验证 DID Document 签名
2. Agent B 生成挑战 nonce → Agent A 用私钥签名
3. Agent B 验证签名 → 信任建立
4. 进入 SIP Triple DH 握手
```

## 3. 与现有PSK的关系

DID不替代PSK，而是提供更灵活的信任建立方式：
- PSK → 适合固定Agent网络（简单、零配置）
- DID → 适合动态Agent网络（灵活、无需预共享）
- 两者可以共存

## 4. 实现前置条件

| 前置 | 状态 |
|------|------|
| M4 认证集成 | 未实现 |
| DID库选择 | 待评估 — `python-did`和`did-peer`均不成熟，建议评估libp2p的Python绑定或自实现轻量DID解析器（仅支持`did:key`方法） |
| 有动态Agent网络需求 | ❌ |

## 5. 模块位置（预留）

```
python/src/sip_protocol/
├── identity/
│   ├── __init__.py
│   ├── did.py             # DID Document 管理器
│   ├── did_auth.py        # DID认证处理器
│   └── keypair.py         # DID密钥对管理
```
