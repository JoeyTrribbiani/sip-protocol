# 远程 MCP 桥接设计文档

> 版本: v1.0
> 日期: 2026-04-22
> 状态: 接口骨架定义（暂不实现）
> 关联: L1 (agent-chat-architecture.md Phase 3)

## 1. 问题陈述

当前MCP通信限于本地（stdio JSON-RPC）。远程Agent之间需要通过SIP加密通道桥接MCP工具调用。

## 2. 设计原则

1. **透明桥接** — 远程MCP调用对本地Agent透明
2. **先本地后远程** — 本地三方通信跑通后再实现
3. **复用SIP加密** — MCP JSON-RPC消息通过SIP加密通道传输

## 3. 架构

```
Agent A (本地)              SIP加密通道              Agent B (远程)
┌─────────────┐                                     ┌─────────────┐
│ MCP Client  │                                     │ MCP Server  │
│ (工具调用)  │                                     │ (工具实现)  │
└──────┬──────┘                                     └──────┬──────┘
       │                                                   │
       │  ToolRequestPart (S1 Message Schema)              │
       ▼                                                   ▼
┌──────────────────────────────────────────────────────────────────┐
│                 MCPBridge                                      │
│  ┌─────────────┐     ┌─────────────┐     ┌─────────────┐      │
│  │ Local → SIP │     │  SIP加密通道  │     │ SIP → Local │      │
│  │ (序列化)    │────→│ (传输+加密)  │────→│ (反序列化)  │      │
│  └─────────────┘     └─────────────┘     └─────────────┘      │
└──────────────────────────────────────────────────────────────────┘
```

## 4. 接口定义（骨架）

```python
class MCPBridge:
    """MCP远程桥接 — 将本地MCP调用通过SIP转发到远程Agent"""

    def __init__(
        self,
        local_agent_id: str,
        remote_agent_id: str,
        transport: TransportBase,
    ):
        ...

    def call_tool(
        self,
        tool_name: str,
        arguments: dict,
        timeout: float = 30.0,
    ) -> dict:
        """远程调用工具

        1. 构建ToolRequestPart
        2. 包装为SIP消息（MessageType.TEXT或自定义）
        3. 通过transport发送
        4. 等待ToolResponsePart
        5. 返回结果

        Raises:
            AgentNotAvailableError: 远程Agent不在线
            TaskTimeoutError: 调用超时
        """
        raise NotImplementedError("等待S1 Message Schema实现后补充")

    def list_tools(self) -> list[dict]:
        """查询远程Agent的工具列表

        发送MessageType.CAPABILITY_ANNOUNCE消息，
        等待AgentCard响应。
        """
        raise NotImplementedError("等待S2 AgentCard实现后补充")
```

## 5. 消息格式

复用S1 Message Schema的Part类型：

```python
# 工具调用请求
{
    "schema": "sip-msg/v1",
    "message_type": "text",  # 或自定义 mcp_tool_call
    "parts": [
        {
            "type": "tool_request",
            "call_id": "call-uuid-xxx",
            "name": "sql_query",
            "arguments": {"query": "SELECT * FROM sales"}
        }
    ]
}

# 工具调用响应
{
    "schema": "sip-msg/v1",
    "message_type": "text",
    "parts": [
        {
            "type": "tool_response",
            "call_id": "call-uuid-xxx",
            "result": {"rows": [...]}
        }
    ]
}
```

## 6. 实现前置条件

| 前置 | 状态 | 说明 |
|------|------|------|
| S1 Message Schema | 未实现 | ToolRequestPart/ToolResponsePart |
| 本地三方通信 | 🟡 基本可用 | Hermes↔OpenClaw↔Claude Code |
| Transport层 | ✅ WebSocket已有 | HTTP适配器（S3）加分 |

## 7. 模块位置（预留）

```
python/src/sip_protocol/
├── bridge/
│   ├── __init__.py
│   └── mcp_bridge.py    # MCPBridge（待实现）
```
