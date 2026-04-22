# Hermes ↔ Claude Code 加密通信适配器

## 当前问题

现在三方通信流程：
```
果果 → hermes_spawn_claude_code → Claude Code
```

消息通过OpenClaw的sessions_spawn/sessions_send传输，**不是SIP加密的**。

## 目标

实现Hermes和Claude Code之间的SIP端到端加密：
```
Hermes (SIP加密) ↔ Claude Code (SIP加密)
```

## 方案

### 1. Claude Code端：SIP MCP Server

Claude Code通过MCP Server接收SIP加密消息：
- 提供MCP工具：`send_encrypted_message()`, `receive_encrypted_messages()`
- 消息格式：AgentMessage (SIP协议层)
- 解密后传给Claude Code处理

### 2. Hermes端：加密发送

Hermes通过MCP Client调用Claude Code的SIP MCP Server：
1. 用SIP加密消息
2. 通过MCP发送加密消息到Claude Code
3. Claude Code解密后处理

### 3. 密钥交换

方式1：预共享密钥（简单，用于测试）
- 双方约定一个PSK
- 用PSK派生会话密钥

方式2：DH密钥交换（生产）
- 第一次握手通过OpenClaw传输DH公钥
- 后续用派生的会话密钥加密

## 实现步骤

1. **SIP MCP Server** - 让Claude Code能接收SIP加密消息
2. **Hermes加密包装器** - 让Hermes能发送SIP加密消息
3. **密钥管理** - DH交换或PSK
4. **测试** - 验证端到端加密
