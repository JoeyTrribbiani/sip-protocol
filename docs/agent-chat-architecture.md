# Agent 群智协同架构

> 基于蜂群效应的多Agent协同系统
> 支持多方通信、集体决策和群组会话
> 最后更新：2026-04-22

## 📋 当前进度

### Phase 1: 本地多Agent互通 ✅ (大部分完成)

```
┌─────────────────────────────────────────────────────────────────────┐
│                    本地 Agent 互通架构                          │
└─────────────────────────────────────────────────────────────────────┘

                    ┌──────────────┐
                    │ Agent A      │
                    │ (决策型)     │
                    │  例如：Hermes│
                    └──────┬───────┘
                           │
                ┌──────────┼──────────┐
                │          │          │
           MCP双向   适配器    记忆同步
                │          │          │
                ▼          ▼          ▼
    ┌─────────────────────┐   ┌──────────────┐
    │ Agent B            │   │ Agent C      │
    │ (调度型)           │   │ (执行型)     │
    │ 例如：OpenClaw     │   │ 例如：Claude  │
    └─────────┬───────────┘   └──────┬───────┘

              │                       │
              │  sessions_spawn       │
              │──────────────────────>│
              │   ACP协议调用         │
              │                       │
              ▼                       ▼
    ┌───────────────────────────────────────┐
    │          微信通道                      │
    │  openclaw-weixin (552d3101d303)       │
    └───────────────────────────────────────┘

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

连接方式:
✅ Agent A (决策型) ↔ Agent B (调度型): MCP双向
✅ Agent B (调度型) → Agent C (执行型): sessions_spawn (ACP)
🟡 Agent A (决策型) → Agent C (执行型): 待实现适配器

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

技术细节:
- 决策型Agent MCP服务器: agent mcp serve
- 调度型Agent MCP服务器: openclaw mcp serve
- subagent会话自动加载MCP配置
- mcp插件: 主agent会话直接访问MCP工具
```

### Phase 2: Agent 群智协议 (SIP) ✅ (加密层完成)

```
┌─────────────────────────────────────────────────────────────────────┐
│              Agent 群智协议 (Swarm Intelligence Protocol)      │
│              支持多方通信、集体决策和群组会话                  │
└─────────────────────────────────────────────────────────────────────┘

    ┌────────────────┐        ┌────────────────┐
    │   Agent A      │        │   Agent B      │
    │   (决策型)     │        │   (调度型)     │
    └────────┬───────┘        └──────┬─────────┘
             │                        │
             │                        │
    ┌────────▼──────────────────────▼─────────┐
    │         加密层 (PSK)         ✅ 已实现    │
    │  • 预共享密钥管理              ✅          │
    │  • 消息端到端加密 (XChaCha20) ✅          │
    │  • 三重DH密钥交换             ✅          │
    │  • HKDF-SHA256密钥派生        ✅          │
    │  • HMAC-SHA256签名            ✅          │
    │  • 密钥轮换机制 (Rekey)       ✅          │
    │  • 群组加密 (Double Ratchet)  ✅          │
    └────────┬──────────────────────┬─────────┘
             │                        │
    ┌────────▼──────────────────────▼─────────┐
    │         传输层             🟡 部分实现    │
    │  ┌─────────┐      ┌──────────┐        │
    │  │ OpenClaw │      │ WebSocket│        │
    │  │ 适配器   │      │ (规划中) │        │
    │  │ ✅ 已实现│      │ 🟡 未实现│        │
    │  └─────────┘      └──────────┘        │
    └────────┬──────────────────────┬─────────┘
             │                        │
             ▼                        ▼
    ┌──────────────────────────────────────────┐
    │         发现机制           🟡 未实现     │
    │  ┌──────────────┐  ┌────────────┐ │
    │  │ 自主暴露(Push)│  │分享匹配(Pull)│ │
    │  │ mDNS/Bonjour │  │ DHT/种子    │ │
    │  └──────────────┘  └────────────┘ │
    └──────────────────────────────────────────┘

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

已实现特性:
✅ 端到端加密 (XChaCha20-Poly1305)
✅ 前向保密 (Rekey密钥轮换)
✅ 抗重放攻击 (nonce + timestamp + replay_tag)
✅ 抗篡改 (HMAC-SHA256)
✅ 群组加密 (Double Ratchet + Skip Ratchet)
✅ 协议版本协商 (SIP-1.0 ~ SIP-1.3)
✅ 消息分片 (>1MB自动分片)
✅ 连接恢复 (24小时TTL)
✅ 群组管理消息 (9种消息类型)
✅ 成员加入/离开流程 (前向+后向保密)
✅ Transport层 (消息格式 + 加密通道 + OpenClaw适配器)

待实现特性:
🟡 集体决策机制
🟡 消息持久化
🟡 离线消息队列
🟡 文件/图片/视频传输
```

### Phase 3: 远程 Agent 协议 🟡 (规划中)

```
┌─────────────────────────────────────────────────────────────────────┐
│             远程 Agent 协议 (QUIC + WebRTC)                     │
└─────────────────────────────────────────────────────────────────────┘

    ┌────────────────┐                    ┌────────────────┐
    │   本地 Agent   │                    │   远程 Agent   │
    │   (决策型)     │                    │   (调度型)     │
    └────────┬───────┘                    └──────┬─────────┘
             │                                  │
    ┌────────▼──────────────────────────────────▼─────────┐
    │          远程 MCP 桥接层             🟡 未实现      │
    │  • JSON-RPC 2.0 over QUIC streams                    │
    │  • WebRTC DataChannel for 实时工具调用               │
    │  • 自动重连和心跳                                     │
    └────────┬──────────────────────────────────┬─────────┘
             │                                  │
    ┌────────▼──────────────────────────────────▼─────────┐
    │         QUIC + WebRTC 传输层         🟡 未实现      │
    │  • UDP多路复用                                       │
    │  • 0-RTT快速重连                                     │
    │  • NAT穿透                                           │
    └────────┬──────────────────────────────────┬─────────┘
             │                                  │
             ▼                                  ▼
    ┌────────────────────────────────────────────────────┐
    │              网络层                                │
    │  • 本地网络 (LAN)                                  │
    │  • Tailnet / Tailscale                             │
    │  • 互联网 (NAT穿透)                                │
    └────────────────────────────────────────────────────┘
```

## 🎯 完整架构图

```
                    ┌─────────────────────────────────────────┐
                    │         用户工作站                      │
                    │    (Gateway运行中，多Agent协同)         │
                    └────────────────┬────────────────────────┘
                                   │
             ┌─────────────────────┼─────────────────────┐
             │                     │                     │
        ┌────▼─────┐         ┌────▼─────┐         ┌────▼─────┐
        │ Agent A  │         │ Agent B  │         │ Agent C  │
        │ (决策型) │         │ (调度型) │         │ (执行型) │
        └────┬─────┘         └────┬─────┘         └────┬─────┘
             │                     │                     │
             │ MCP双向             │ ACP调用              │
             ├─────────────────────┼────────────────────>│
             │                     │                     │
             └─────────────────────┼─────────────────────┘
                                   │
                             ┌─────▼─────┐
                             │  消息通道  │
                             └─────┬─────┘
                                   │
                             ┌─────▼───────────────────┐
                             │    用户 (随时通信)       │
                             └─────────────────────────┘

示例配置:
- Agent A (决策型): Hermes
- Agent B (调度型): OpenClaw
- Agent C (执行型): Claude Code
- 消息通道: openclaw-weixin (552d3101d303)

注意：以上仅为示例，实际部署时可以是任意类型的Agent。

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

                    远程扩展 (Phase 3)

    ┌─────────────────┐              ┌─────────────────┐
    │  远程 Agent A  │◄────────────►│  远程 Agent B  │
    │  (其他机器)     │   QUIC/WebRTC │  (其他机器)     │
    └─────────────────┘              └─────────────────┘
           │                               │
           │    Agent 群智协议 (SIP)        │
           └───────────────────────────────┘
                    (基于蜂群效应的协同)
```

## 📊 当前状态

| 阶段 | 任务 | 状态 | 说明 |
|------|------|------|------|
| **Phase 1** | Agent A ↔ Agent B MCP双向 | ✅ 完成 | Hermes ↔ OpenClaw |
| | Agent B → Agent C ACP调用 | ✅ 完成 | OpenClaw → Claude Code |
| | Agent A → Agent C 适配器 | 🟡 待实现 | Hermes → Claude Code |
| | 多Agent循环测试 | 🟡 待完成 | |
| **Phase 2** | SIP加密协议设计 | ✅ 完成 | docs/e2ee-protocol.md |
| | 三重DH密钥交换 | ✅ 完成 | python/src/protocol/handshake.py |
| | XChaCha20-Poly1305加密 | ✅ 完成 | python/src/crypto/ |
| | HKDF-SHA256密钥派生 | ✅ 完成 | python/src/crypto/hkdf.py |
| | HMAC-SHA256签名 | ✅ 完成 | python/src/protocol/handshake.py |
| | Rekey密钥轮换 | ✅ 完成 | python/src/protocol/rekey.py |
| | 群组加密 (Double Ratchet) | ✅ 完成 | python/src/protocol/group.py |
| | 群组管理消息 (9种) | ✅ 完成 | python/src/protocol/group.py |
| | 成员加入/离开流程 | ✅ 完成 | 前向+后向保密 |
| | 协议版本协商 | ✅ 完成 | python/src/protocol/version.py |
| | 消息分片 | ✅ 完成 | python/src/protocol/fragment.py |
| | 连接恢复 | ✅ 完成 | python/src/protocol/resume.py |
| | Transport层 (消息格式) | ✅ 完成 | python/src/transport/message.py |
| | Transport层 (加密通道) | ✅ 完成 | python/src/transport/encrypted_channel.py |
| | Transport层 (OpenClaw适配器) | ✅ 完成 | python/src/transport/openclaw_adapter.py |
| | OpenClaw桥接 (真正调用API) | ❌ 未实现 | 需要调用Gateway API |
| | MCP Server封装 | ❌ 未实现 | 让agent通过MCP调用SIP |
| | 集体决策机制 | ❌ 未实现 | |
| | 消息持久化 | ❌ 未实现 | |
| | 离线消息队列 | ❌ 未实现 | |
| | 文件/图片/视频传输 | ❌ 未实现 | |
| **Phase 3** | 远程MCP桥接 | ❌ 未实现 | |
| | QUIC + WebRTC传输层 | ❌ 未实现 | |
| | 发现机制 (Push/Pull) | ❌ 未实现 | |

## 🔧 技术栈

### Phase 1 (本地互通) ✅
- 决策型Agent: Python 3.11, MCP Server (例如：Hermes)
- 调度型Agent: Node.js, MCP Client/Server, ACP Runtime (例如：OpenClaw)
- 执行型Agent: TypeScript, ACP Protocol (例如：Claude Code)
- 通信: MCP (stdio JSON-RPC), ACP (spawn sessions)

### Phase 2 (Agent 群智协议 SIP) 🔄 加密层已完成
- 加密: XChaCha20-Poly1305 + Argon2id + HKDF-SHA256
- 密钥交换: X25519 三重DH
- 群组: Double Ratchet + Skip Ratchet
- Transport: 加密通道 + OpenClaw适配器
- 测试: 117/117通过, 覆盖率82%

### Phase 3 (远程 Agent) 🟡 规划中
- 传输层: QUIC (quinn-rs) / WebRTC (pion/webrtc)
- 发现: mDNS / DHT (libp2p / kademlia)
- 协议: Agent群智协议 over QUIC/WebRTC

## 📁 项目结构

```
sip-protocol/
├── python/
│   ├── src/
│   │   ├── crypto/          # 加密原语
│   │   │   ├── aes_gcm.py       ✅ XChaCha20-Poly1305
│   │   │   ├── hkdf.py          ✅ HKDF-SHA256密钥派生
│   │   │   ├── argon2.py        ✅ Argon2id PSK哈希
│   │   │   └── xchacha20_poly1305.py ✅ 加密/解密
│   │   ├── protocol/        # 协议层
│   │   │   ├── handshake.py     ✅ 三重DH握手
│   │   │   ├── message.py       ✅ 消息加密/解密
│   │   │   ├── rekey.py         ✅ Rekey密钥轮换
│   │   │   ├── version.py       ✅ 协议版本协商
│   │   │   ├── fragment.py      ✅ 消息分片
│   │   │   ├── resume.py        ✅ 连接恢复
│   │   │   ├── group.py         ✅ 群组加密
│   │   │   └── group_simple.py  ✅ 简化群组
│   │   ├── transport/       # 传输层
│   │   │   ├── message.py       ✅ Agent消息格式
│   │   │   ├── encrypted_channel.py ✅ 加密通道
│   │   │   └── openclaw_adapter.py  ✅ OpenClaw适配器
│   │   └── managers/        # 管理器
│   │       ├── session.py       ✅ 会话管理
│   │       └── nonce.py         ✅ Nonce管理
│   ├── tests/               # 测试 (117个)
│   └── examples/
│       └── three_party_chat.py  ✅ 三方通信示例
├── javascript/              # JavaScript实现
│   └── src/
├── docs/                    # 文档
│   ├── e2ee-protocol.md         ✅ SIP协议规范
│   └── agent-chat-architecture.md ✅ 架构设计
└── .github/workflows/       # CI/CD
```

---

*最后更新: 2026-04-22*

**协议名称：** Swarm Intelligence Protocol (SIP)
**核心理念：** 基于蜂群效应的多Agent协同

**示例配置：**
```
Agent A (决策型): Hermes - 决策中心
Agent B (调度型): OpenClaw - 调度中心  
Agent C (执行型): Claude Code - 执行中心
```

**注意：** 以上仅为示例，实际部署时可以是任意类型的Agent。
