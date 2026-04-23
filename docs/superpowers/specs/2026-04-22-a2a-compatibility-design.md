# A2A 兼容性 Binding 设计文档

> 版本: v1.0
> 日期: 2026-04-22
> 状态: 概念设计（暂不实现）
> 基于A2A规范版本: draft-2026-04（后续规范变更需追溯更新）
> 关联: L5 (sip-protocol-report.md Section 8.6)

## 1. 问题陈述

Google A2A (Agent-to-Agent) 协议正在成为行业标准。SIP需要提供A2A兼容层，以便与A2A生态互通。

## 2. 整合策略

**SIP as Transport for A2A** — SIP作为加密传输层，A2A作为应用层：

```
A2A Message → SIP Encrypt → HTTP Transport → SIP Decrypt → A2A Parse
```

## 3. 映射关系

| A2A 概念 | SIP 对应 | 说明 |
|----------|---------|------|
| AgentCard | S2 AgentCard | 已对齐设计 |
| Task | M1 Task | 已对齐设计 |
| Message/Part | S1 Message Schema Part | 已对齐设计 |
| TextPart | TextPart | 直接映射 |
| FilePart | FileRefPart + FileDataPart | SIP拆分为两种 |
| DataPart | DataPart | 直接映射 |
| JSON-RPC 2.0 | SIP Protocol Header | SIP用自己的二进制头 |
| Streaming (SSE) | M2 StreamPart | SIP用分块实现 |

## 4. A2A Binding 实现

```python
class A2ABinding:
    """A2A协议绑定层 — 将A2A消息转换为SIP消息"""

    def a2a_to_sip(self, a2a_message: dict) -> dict:
        """将A2A JSON-RPC消息转换为SIP Message Schema"""
        raise NotImplementedError("等待S1 Message Schema实现")

    def sip_to_a2a(self, sip_message: dict) -> dict:
        """将SIP Message Schema转换回A2A JSON-RPC"""
        raise NotImplementedError("等待S1 Message Schema实现")

    def get_agent_card(self) -> dict:
        """返回A2A格式的AgentCard"""
        raise NotImplementedError("等待S2 AgentCard实现")
```

## 5. 实现前置条件

| 前置 | 状态 |
|------|------|
| S1 Message Schema | 未实现 |
| S2 AgentCard | 未实现 |
| M1 TaskManager | 未实现 |
| A2A协议规范稳定 | 🟡 草案阶段 |

## 6. 模块位置（预留）

```
python/src/sip_protocol/
├── a2a/
│   ├── __init__.py
│   ├── binding.py         # A2ABinding
│   ├── card_adapter.py    # AgentCard ↔ A2A AgentCard 转换
│   └── message_adapter.py # Message ↔ A2A Message 转换
```
