# 多Agent加密通信配置指南

> SIP协议库与Hermes/OpenClaw/Claude Code的集成配置

## 架构

```
Hermes ──SIP加密──► OpenClaw Agent ──SIP加密──► Claude Code
(glm-5.1)    hermes_claude_adapter    (GLM-5.1)    openclaw_adapter
                  │                                     │
                  ▼                                     ▼
            sip_mcp_server                       sessions_spawn
            (MCP工具)                            (ACP子agent)
```

## 1. SIP MCP Server 配置

### 1.1 注册为MCP Server

在OpenClaw配置中注册SIP MCP Server：

```json
// ~/.openclaw/openclaw.json → mcp.servers
{
  "sip-protocol": {
    "command": "/Users/joey0x1/.local/bin/python3.11",
    "args": [
      "/Users/joey0x1/.openclaw/workspace/sip-protocol/python/sip_mcp_server_standalone.py",
      "--psk", "<预共享密钥>",
      "--agent-id", "openclaw-agent"
    ]
  }
}
```

> **注意**: 使用`sip_mcp_server_standalone.py`（独立版），而非`src/transport/sip_mcp_server.py`（相对导入无法独立运行）。

Hermes端同样配置（在`mcp_config.json`中）：

```json
{
  "sip-protocol": {
    "command": "/Users/joey0x1/.local/bin/python3.11",
    "args": [
      "/Users/joey0x1/.openclaw/workspace/sip-protocol/python/sip_mcp_server_standalone.py",
      "--psk", "<预共享密钥>",
      "--agent-id", "hermes"
    ]
  }
}
```

### 1.2 PSK密钥分发

所有参与通信的Agent必须使用相同的PSK：

```bash
# 生成PSK
python3 -c "import secrets; print(secrets.token_hex(32))"
# 输出: a1b2c3d4...（64字符hex）

# 各Agent配置相同的PSK
# OpenClaw: openclaw.json 中 mcp.servers.sip-protocol.args
# Hermes: mcp_config.json 中 args
# Claude Code: 环境变量 SIP_PSK
```

### 1.3 MCP工具使用

注册后，Agent可使用以下MCP工具：

| 工具 | 用途 | 参数 |
|------|------|------|
| `sip_handshake` | 三重DH握手 | role, agent_id, message |
| `sip_encrypt` | 加密消息 | plaintext, recipient_id |
| `sip_decrypt` | 解密消息 | encrypted_message |
| `sip_rekey` | 密钥轮换 | role, message |

## 2. OpenClaw 适配器配置

### 2.1 安装SIP协议库

```bash
cd sip-protocol/python
pip install -e .
```

### 2.2 在Agent代码中使用

OpenClaw Agent通过 `OpenClawAdapter` 发送加密消息：

```python
from sip_protocol.transport import OpenClawAdapter

adapter = OpenClawAdapter(agent_id="openclaw-agent")
await adapter.connect()

# 加密发送消息给Hermes
await adapter.gateway_send_message(
    target="hermes",
    message="需要加密传输的内容",
)

# 接收并解密Hermes的回复
messages = await adapter.gateway_read_messages()
```

### 2.3 发送给Claude Code

```python
from sip_protocol.transport import HermesClaudeAdapter

adapter = HermesClaudeAdapter(
    hermes_agent_id="openclaw-agent",
    claude_agent_id="claude-code",
    psk=psk_bytes,
)

await adapter.handshake()
response = await adapter.send("加密任务消息")
```

## 3. Hermes 适配器配置

### 3.1 通过MCP调用

Hermes注册SIP MCP Server后，可直接在对话中使用：

```
# Hermes对话中
> sip_handshake role=initiator agent_id=hermes
← hello_message: "base64编码的握手消息..."

# 将hello_message发送给对方Agent
> sip_encrypt plaintext="机密消息" recipient_id="openclaw-agent"
← encrypted_message: "base64编码的加密消息..."
```

### 3.2 通过Hermes技能集成

创建自定义技能调用SIP：

```yaml
# ~/.hermes/hermes-agent/skills/sip-encrypt/SKILL.md
---
name: sip-encrypt
description: 使用SIP协议加密发送消息给其他Agent
---

通过MCP工具 sip_encrypt 和 sip_decrypt 进行加密通信。

步骤：
1. 调用 sip_handshake 建立加密通道
2. 调用 sip_encrypt 加密消息
3. 通过terminal/hermes工具发送加密消息
4. 对方调用 sip_decrypt 解密
```

## 4. Claude Code 适配器配置

### 4.1 作为MCP Server运行

Claude Code通过MCP Server接收SIP加密消息：

```json
// Claude Code项目配置 .claude/settings.json
{
  "mcpServers": {
    "sip-protocol": {
      "command": "python3",
      "args": ["-m", "sip_protocol.transport.sip_mcp_server",
               "--psk", "<预共享密钥>",
               "--agent-id", "claude-code"],
      "cwd": "/path/to/sip-protocol/python"
    }
  }
}
```

### 4.2 作为子Agent运行

通过OpenClaw的`sessions_spawn`启动Claude Code时，注入SIP配置：

```python
from sip_protocol.transport import HermesClaudeAdapter

adapter = HermesClaudeAdapter(
    hermes_agent_id="openclaw-agent",
    claude_agent_id="claude-code",
    psk=psk_bytes,
    model="claude-sonnet",
)

# 自动启动Claude Code子会话并建立SIP加密通道
response = await adapter.send("加密任务描述")
```

## 5. 三方通信流程

### 5.1 建立加密通道

```
Step 1: OpenClaw Agent ↔ Hermes
  OpenClaw: sip_handshake(role=initiator) → hello_msg
  → 通过hermes CLI发送hello_msg给Hermes
  Hermes: sip_handshake(role=responder, message=hello_msg) → auth_msg
  → 返回auth_msg
  OpenClaw: sip_handshake(role=complete, message=auth_msg)
  ✅ 通道建立

Step 2: OpenClaw Agent ↔ Claude Code
  同上流程，通过sessions_spawn传递握手消息
  ✅ 通道建立
```

### 5.2 加密通信

```
OpenClaw → Hermes:
  1. sip_encrypt(plaintext="评审请求", recipient_id="hermes")
  2. 通过hermes CLI发送加密消息
  3. Hermes: sip_decrypt(encrypted_message)

OpenClaw → Claude Code:
  1. sip_encrypt(plaintext="编码任务", recipient_id="claude-code")
  2. 通过sessions_send发送加密消息
  3. Claude Code: sip_decrypt(encrypted_message)
```

### 5.3 密钥轮换

```
任一方发起:
  sip_rekey(role=initiator) → rekey_request
  → 发送给对方
  对方: sip_rekey(role=responder, message=rekey_request)
  ✅ 密钥已轮换
```

## 6. 集体决策配置

三方参与投票决策：

```python
from sip_protocol.protocol.decision import DecisionEngine

# 任一方创建提案
engine = DecisionEngine(agent_id="openclaw-agent")
proposal = engine.create_proposal(
    title="部署方案选择",
    config={
        "voters": ["openclaw-agent", "hermes", "claude-code"],
        "options": ["蓝绿部署", "滚动更新", "金丝雀发布"],
        "strategy": "majority",
        "quorum": 3,
    },
)

# 导出提案（通过SIP加密发送给其他Agent）
exported = engine.export_proposal(proposal.proposal_id)

# 其他Agent导入并投票
engine_b = DecisionEngine(agent_id="hermes")
engine_b.import_proposal(exported)
engine_b.vote(proposal.proposal_id, "滚动更新", reason="风险最低")

# 汇总投票后评估
result = engine.evaluate(proposal.proposal_id)
```

## 7. 消息持久化配置

```python
from sip_protocol.protocol.persistence import MessageStore

# 文件数据库（推荐）
store = MessageStore(db_path="~/.openclaw/sip_messages.db")

# 保存加密消息
store.save({
    "id": msg.id,
    "sender_id": "hermes",
    "recipient_id": "openclaw-agent",
    "payload": msg.to_json(),
    "encrypted": True,
    "session_id": "three-party-chat",
})

# 按会话查询历史
messages = store.query(filters={"session_id": "three-party-chat"}, limit=50)
```

## 8. 离线消息配置

```python
from sip_protocol.protocol.offline_queue import OfflineQueue

# Agent离线时缓存消息
queue = OfflineQueue(
    agent_id="claude-code",
    db_path="~/.openclaw/sip_offline.db",
    default_ttl=86400,  # 24小时
)

# 发送方入队
queue.enqueue("hermes", "claude-code", {"payload": "紧急任务"})

# Agent上线后投递
messages = queue.deliver_pending()
for msg in messages:
    handle(msg)
    queue.ack(msg["id"])
```

## 9. 故障排除

| 问题 | 原因 | 解决 |
|------|------|------|
| MCP Server无法启动 | Python路径或PSK错误 | 检查command和args |
| 握手失败 | PSK不一致 | 确认所有Agent使用相同PSK |
| 加密解密失败 | 通道未建立 | 先执行sip_handshake |
| Hermes返回空 | glm-4.7模型问题 | 切换到glm-5.1 |
| Claude Code卡住 | CLI交互模式问题 | 使用print模式(-p)或subagent |
| MyPy类型错误 | Python 3.14本地环境 | CI/CD使用3.11验证 |

## 10. 安全注意事项

1. **PSK通过环境变量分发**，不要硬编码在配置文件中
2. **定期轮换PSK**（建议每月一次）
3. **启用Rekey**（每10000条消息自动轮换密钥）
4. **离线队列TTL**不宜过长（默认24小时）
5. **消息持久化数据库**设置文件权限为600
6. **API Key**存储在本地，不提交到Git
