# 多Agent加密通信配置指南

> 本文档说明如何配置 Hermes + OpenClaw + Claude Code 三方加密通信环境，
> 并使用SIP协议库实现端到端加密。

## 架构概览

```
┌─────────────┐     SIP加密      ┌─────────────┐     SIP加密      ┌─────────────┐
│   Hermes    │ ◄──────────────► │  OpenClaw   │ ◄──────────────► │ Claude Code │
│  (决策型)    │   hermes CLI    │  (调度型)    │  sessions_spawn  │  (执行型)    │
│             │                  │  果果 (你)   │                  │             │
│  glm-5.1    │                  │  GLM-5.1    │                  │  claude-sonnet │
└─────────────┘                  └─────────────┘                  └─────────────┘
      │                              │                              │
      ▼                              ▼                              ▼
  hermes CLI                   OpenClaw Gateway              claude CLI
  (~/.hermes/)                (~/.openclaw/)               (npm全局安装)
```

### 通信路径

| 路径 | 方式 | 加密 |
|------|------|------|
| 果果 → Claude Code | `sessions_spawn` (ACP) | SIP端到端加密 |
| 果果 → Hermes | `hermes chat` CLI | SIP端到端加密 |
| Hermes → Claude Code | `hermes_spawn_claude_code` | SIP端到端加密 |

## 1. 环境要求

### 基础环境

| 组件 | 版本 | 安装方式 |
|------|------|----------|
| Python | 3.11+ | 系统安装 |
| Node.js | 20+ | 系统安装 |
| Git | 2.x | 系统安装 |

### Agent组件

| 组件 | 版本 | 安装方式 |
|------|------|----------|
| OpenClaw | 2026.4+ | `npm install -g openclaw` |
| Hermes Agent | 0.8+ | `curl -fsSL https://hermes.agent/install \| bash` |
| Claude Code | 2.x+ | `npm install -g @anthropic-ai/claude-code` |

## 2. OpenClaw 配置

### 基础配置 (`~/.openclaw/openclaw.json`)

```json
{
  "agents": {
    "defaults": {
      "model": {
        "primary": "zhipuglmcodingplanpro/GLM-5.1",
        "fallbacks": ["zhipuglmcodingplanpro/GLM-4.7"]
      },
      "workspace": "~/.openclaw/workspace"
    }
  },
  "plugins": {
    "allow": [
      "openclaw-weixin",
      "zai",
      "memory-core",
      "hermes-mcp",
      "acpx",
      "zhipu-mcp"
    ]
  }
}
```

### 模型配置

OpenClaw使用 `openclaw.json` 中的 `agents.defaults.model` 配置模型：

```json
{
  "agents": {
    "defaults": {
      "model": {
        "primary": "zhipuglmcodingplanpro/GLM-5.1"
      }
    }
  }
}
```

也可以通过API Key配置自定义模型提供商：

```json
{
  "models": {
    "providers": {
      "glm-5.1": {
        "api": "openai-completions",
        "apiKey": "your-api-key",
        "baseUrl": "https://open.bigmodel.cn/api/paas/v4"
      }
    }
  }
}
```

### 验证配置

```bash
# 检查OpenClaw状态
openclaw status

# 检查Gateway是否运行
openclaw gateway status
```

## 3. Hermes 配置

### 基础设置

```bash
# 安装后初始化
hermes setup

# 配置模型（推荐glm-5.1）
hermes model

# 检查状态
hermes status
```

### 模型配置

Hermes使用 `.env` 文件配置API Key：

```bash
# ~/.hermes/hermes-agent/.env
ZAI_API_KEY=your-zhipu-api-key
```

切换模型：
```bash
hermes model  # 交互式选择
```

推荐使用 glm-5.1（glm-4.7会返回空响应）。

### Claude Code集成

Hermes通过skills目录下的`autonomous-ai-agents/claude-code`技能调用Claude Code：

```bash
# 安装Claude Code CLI
npm install -g @anthropic-ai/claude-code

# 登录认证
claude auth login

# 验证
claude auth status
```

Hermes调用Claude Code有两种模式：
- **Print模式** (`-p`): 一次性任务，不需要PTY
- **交互式PTY模式**: 通过tmux进行多轮对话

### 验证配置

```bash
# 测试Hermes基本功能
hermes chat -q "回复OK"

# 测试Claude Code集成
hermes chat -q "用claude-code回复OK"
```

## 4. SIP协议库配置

### 安装

```bash
cd sip-protocol/python
pip install -r requirements.txt
pip install -e .
```

### 在Agent中使用

#### 果果（OpenClaw主Agent）使用SIP

```python
from src.transport import EncryptedChannel, ChannelConfig

# 创建加密通道
channel = EncryptedChannel(
    agent_id="guoguo",
    psk=b"shared-secret-key",
    config=ChannelConfig(
        rekey_after_messages=10000,
        rekey_after_seconds=3600,
    ),
)

# 发起握手（Triple DH）
hello_msg = channel.initiate()
# 将hello_msg通过sessions_send发送给对方

# 加密发送
encrypted = channel.send("机密消息", "claude-code")
# 通过sessions_send发送encrypted.to_json()

# 接收解密
received = channel.receive(agent_message)
print(received)  # 解密后的明文
```

#### Hermes使用SIP（通过MCP Server）

```bash
# 启动SIP MCP Server
python -m sip_protocol.transport.sip_mcp_server --psk "shared-secret-key" --agent-id hermes
```

MCP工具列表：
- `sip_handshake`: 三重DH握手
- `sip_encrypt`: 加密消息
- `sip_decrypt`: 解密消息
- `sip_rekey`: 密钥轮换

## 5. 三方加密通信测试

### 测试1: 果果 → Claude Code（明文）

这是最基本的通信测试，通过OpenClaw的sessions_spawn：

```bash
# 在OpenClaw聊天中
# 果果直接发送消息给Claude Code子agent
# 通过sessions_spawn启动，sessions_send发送消息
```

验证：Claude Code应能正常回复。

### 测试2: 果果 → Hermes（通过CLI）

```bash
# 通过hermes CLI发送消息
hermes chat -q "测试消息：回复OK确认收到"
```

验证：Hermes应回复"OK"或类似确认。

### 测试3: SIP加密通信（果果 ↔ Hermes）

使用SIP协议库实现端到端加密：

```python
# 果果端
from src.transport import EncryptedChannel

channel_a = EncryptedChannel(agent_id="guoguo", psk=b"test-key")
hello = channel_a.initiate()

# 将hello发送给Hermes（通过hermes CLI或MCP）
# Hermes端处理hello，返回auth
# channel_a.complete_handshake(auth_msg)

# 加密通信
encrypted = channel_a.send("加密测试消息", "hermes")
```

### 测试4: 三方加密通信

完整的A→B→C加密通信流程：

```
1. 果果发起SIP握手 → Hermes
2. Hermes响应握手 → 果果
3. 果果发起SIP握手 → Claude Code（通过sessions_spawn）
4. Claude Code响应握手 → 果果
5. 三方建立加密通道
6. 果果通过SIP加密发送消息给Hermes和Claude Code
```

## 6. 集体决策测试

使用DecisionEngine进行多Agent投票：

```python
from src.protocol.decision import DecisionEngine

engine = DecisionEngine(agent_id="guoguo")

# 创建提案
proposal = engine.create_proposal(
    title="选择加密算法",
    config={
        "voters": ["guoguo", "hermes", "claude-code"],
        "options": ["XChaCha20-Poly1305", "AES-256-GCM", "ChaCha20-Poly1305"],
        "strategy": "majority",
        "quorum": 3,
    },
)

# 果果投票
engine.vote(proposal.proposal_id, "XChaCha20-Poly1305")

# 导出提案给其他Agent
exported = engine.export_proposal(proposal.proposal_id)
# 通过sessions_send发送给Claude Code处理
```

## 7. 消息持久化

使用MessageStore保存通信历史：

```python
from src.protocol.persistence import MessageStore

# 创建持久化存储
store = MessageStore(db_path="sip_messages.db")

# 保存消息
store.save({
    "id": "msg-001",
    "sender_id": "hermes",
    "recipient_id": "guoguo",
    "payload": "加密通信内容",
    "encrypted": True,
    "timestamp": time.time(),
})

# 查询历史
messages = store.query(filters={"sender": "hermes"}, limit=20)
```

## 8. 离线消息队列

Agent离线时缓存消息：

```python
from src.protocol.offline_queue import OfflineQueue

queue = OfflineQueue(agent_id="claude-code")

# 其他Agent发送消息给离线的claude-code
queue.enqueue("hermes", "claude-code", {"payload": "离线消息"})

# claude-code上线后投递
messages = queue.deliver_pending()
for msg in messages:
    process(msg)
    queue.ack(msg["id"])
```

## 9. 故障排除

### Hermes不回复

```bash
# 检查API Key
hermes status

# 检查模型配置
hermes model

# 检查glm-5.1是否限流（HTTP 429）
hermes chat -q "OK" 2>&1 | grep 429
```

### Claude Code卡住

Claude Code CLI约有75%概率卡住，解决方案：
- 使用 `-p` (print模式) 替代交互模式
- 设置超时（`timeout`参数）
- 通过subagent模式（`sessions_spawn`）运行

### OpenClaw Gateway未运行

```bash
openclaw gateway status
openclaw gateway start
```

### SIP加密通信失败

```bash
# 运行SIP协议测试
cd sip-protocol/python
python3 -m pytest tests/test_sip_protocol.py -v

# 运行集成测试
python3 -m pytest tests/test_integration.py -v
```

## 10. 安全注意事项

1. **PSK管理**: 预共享密钥应通过安全渠道分发，不要硬编码
2. **API Key保护**: 所有API Key存储在本地配置文件，不要提交到Git
3. **加密消息转发**: 即使消息通过OpenClaw中转，内容也是SIP加密的
4. **Rekey轮换**: 建议每10000条消息或每1小时轮换一次密钥
5. **离线队列**: 过期消息默认30天清理，敏感消息应设置更短TTL
