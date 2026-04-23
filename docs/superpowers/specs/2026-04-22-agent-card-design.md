# AgentCard 模块设计文档

> 版本: v1.0
> 日期: 2026-04-22
> 状态: 已批准
> 关联: S2 (sip-protocol-report.md Section 8.3.1 差距1)

## 1. 问题陈述

Agent无法在运行时发现其他Agent的能力（会做什么、支持什么协议、需要什么认证）。
参考A2A协议的AgentCard规范，实现SIP自己的能力发现机制。

## 2. 设计原则

1. **自描述** — 每个Agent发布一个AgentCard，描述自己的身份和能力
2. **公开透明** — AgentCard是公开信息，不含敏感凭证
3. **可序列化** — 支持JSON序列化/反序列化，通过SIP消息通道传输
4. **不引入新依赖** — 使用标准库`@dataclass`，不依赖pydantic

## 3. 数据结构

### 3.1 AgentCard

```python
from dataclasses import dataclass, field
from typing import Any


@dataclass
class AgentCard:
    """Agent能力卡片 — 自描述文档"""

    name: str                              # Agent唯一标识名
    description: str                       # 人类可读描述
    version: str                           # Agent软件版本（语义化版本）
    url: str                               # 主通信端点 URL
    capabilities: "Capabilities"           # 能力声明
    authentication: list["AuthScheme"]     # 支持的认证方案列表
    skills: list["Skill"]                  # 技能列表
    endpoints: "Endpoints"                 # 多端点配置
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """序列化为JSON兼容字典"""
        return {
            "name": self.name,
            "description": self.description,
            "version": self.version,
            "url": self.url,
            "capabilities": {
                "streaming": self.capabilities.streaming,
                "push_notifications": self.capabilities.push_notifications,
                "task_management": self.capabilities.task_management,
                "file_transfer": self.capabilities.file_transfer,
                "group_communication": self.capabilities.group_communication,
                "max_message_size": self.capabilities.max_message_size,
                "supported_schemas": self.capabilities.supported_schemas,
            },
            "authentication": [a.to_dict() for a in self.authentication],
            "skills": [s.to_dict() for s in self.skills],
            "endpoints": {
                "primary": self.endpoints.primary,
                "streaming": self.endpoints.streaming,
                "file_transfer": self.endpoints.file_transfer,
                "health": self.endpoints.health,
            },
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AgentCard":
        """从JSON兼容字典反序列化"""
        caps_data = data.get("capabilities", {})
        caps = Capabilities(
            streaming=caps_data.get("streaming", False),
            push_notifications=caps_data.get("push_notifications", False),
            task_management=caps_data.get("task_management", False),
            file_transfer=caps_data.get("file_transfer", False),
            group_communication=caps_data.get("group_communication", False),
            max_message_size=caps_data.get("max_message_size", 1048576),
            supported_schemas=caps_data.get("supported_schemas", ["sip-msg/v1"]),
        )
        auth = [AuthScheme.from_dict(a) for a in data.get("authentication", [])]
        skills = [Skill.from_dict(s) for s in data.get("skills", [])]
        ep_data = data.get("endpoints", {})
        endpoints = Endpoints(
            primary=ep_data.get("primary", ""),
            streaming=ep_data.get("streaming"),
            file_transfer=ep_data.get("file_transfer"),
            health=ep_data.get("health"),
        )
        return cls(
            name=data["name"],
            description=data.get("description", ""),
            version=data.get("version", "0.0.0"),
            url=data.get("url", ""),
            capabilities=caps,
            authentication=auth,
            skills=skills,
            endpoints=endpoints,
            metadata=data.get("metadata", {}),
        )
```

### 3.2 Capabilities

```python
@dataclass
class Capabilities:
    """Agent能力声明"""
    streaming: bool = False
    push_notifications: bool = False
    task_management: bool = False
    file_transfer: bool = False
    group_communication: bool = False
    max_message_size: int = 1048576          # 1MB默认
    supported_schemas: list[str] = field(default_factory=lambda: ["sip-msg/v1"])
```

### 3.3 Skill

```python
@dataclass
class Skill:
    """Agent技能 — 可选的输入/输出schema"""
    id: str
    name: str
    description: str
    input_schema: dict | None = None         # 可选，JSON Schema格式
    output_schema: dict | None = None        # 可选，JSON Schema格式
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "tags": self.tags,
        }
        if self.input_schema is not None:
            d["input_schema"] = self.input_schema
        if self.output_schema is not None:
            d["output_schema"] = self.output_schema
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Skill":
        return cls(
            id=data["id"],
            name=data["name"],
            description=data.get("description", ""),
            input_schema=data.get("input_schema"),
            output_schema=data.get("output_schema"),
            tags=data.get("tags", []),
        )
```

### 3.4 AuthScheme

认证方案声明（不含实际凭证，只声明类型）：

```python
@dataclass
class AuthScheme:
    """认证方案声明 — 只声明类型，不含凭证"""
    type: str               # "psk" | "bearer" | "api_key" | "oauth2" | "mtls"
    description: str = ""   # 人类可读描述

    def to_dict(self) -> dict[str, Any]:
        return {"type": self.type, "description": self.description}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AuthScheme":
        return cls(type=data["type"], description=data.get("description", ""))
```

### 3.5 Endpoints

```python
@dataclass
class Endpoints:
    """多端点配置"""
    primary: str                   # 主端点（必填）
    streaming: str | None = None   # 流式端点（SSE）
    file_transfer: str | None = None  # 文件传输端点
    health: str | None = None      # 健康检查端点
```

## 4. AgentCard 交换流程

AgentCard交换在**认证协商阶段**发生，此时**未建立加密通道**（AgentCard是公开信息）：

```
1. Agent A 上线 → 注册AgentCard到Registry
2. Agent A 要与 Agent B 通信
3. Agent A 从Registry获取 Agent B 的AgentCard
4. Agent A 发送 CAPABILITY_ANNOUNCE 消息（明文，含自己的AgentCard）
5. Agent B 回复自己的AgentCard
6. 双方根据AgentCard.authentication协商认证方案
7. 认证成功后建立SIP加密通道
8. 加密通道建立后所有通信加密
```

## 5. 模块位置

```
python/src/sip_protocol/
├── discovery/
│   ├── __init__.py
│   ├── agent_card.py     # AgentCard 数据结构
│   └── capabilities.py   # Capabilities, Skill, AuthScheme, Endpoints
```
