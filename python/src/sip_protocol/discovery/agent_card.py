"""AgentCard 数据结构 — Agent 自描述能力卡片"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class Capabilities:
    """Agent能力声明"""

    streaming: bool = False
    push_notifications: bool = False
    task_management: bool = False
    file_transfer: bool = False
    group_communication: bool = False
    max_message_size: int = 1048576
    supported_schemas: tuple[str, ...] = ("sip-msg/v1",)

    def to_dict(self) -> dict[str, Any]:
        """序列化为字典"""
        d: dict[str, Any] = {
            "streaming": self.streaming,
            "push_notifications": self.push_notifications,
            "task_management": self.task_management,
            "file_transfer": self.file_transfer,
            "group_communication": self.group_communication,
            "max_message_size": self.max_message_size,
            "supported_schemas": list(self.supported_schemas),
        }
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Capabilities:
        """从字典反序列化"""
        return cls(
            streaming=data.get("streaming", False),
            push_notifications=data.get("push_notifications", False),
            task_management=data.get("task_management", False),
            file_transfer=data.get("file_transfer", False),
            group_communication=data.get("group_communication", False),
            max_message_size=data.get("max_message_size", 1048576),
            supported_schemas=tuple(data.get("supported_schemas", ["sip-msg/v1"])),
        )


@dataclass
class Skill:
    """Agent技能"""

    id: str
    name: str
    description: str = ""
    input_schema: dict | None = None
    output_schema: dict | None = None
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """序列化为字典，None 的 schema 不输出"""
        d: dict[str, Any] = {
            "id": self.id,
            "name": self.name,
        }
        if self.description:
            d["description"] = self.description
        if self.input_schema is not None:
            d["input_schema"] = self.input_schema
        if self.output_schema is not None:
            d["output_schema"] = self.output_schema
        if self.tags:
            d["tags"] = list(self.tags)
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Skill:
        """从字典反序列化"""
        return cls(
            id=data["id"],
            name=data["name"],
            description=data.get("description", ""),
            input_schema=data.get("input_schema"),
            output_schema=data.get("output_schema"),
            tags=data.get("tags", []),
        )


@dataclass(frozen=True)
class AuthScheme:
    """认证方案声明（不含凭证）"""

    type: str
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
        """序列化为字典"""
        d: dict[str, Any] = {"type": self.type}
        if self.description:
            d["description"] = self.description
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AuthScheme:
        """从字典反序列化"""
        return cls(
            type=data["type"],
            description=data.get("description", ""),
        )


@dataclass(frozen=True)
class Endpoints:
    """多端点配置"""

    primary: str
    streaming: str | None = None
    file_transfer: str | None = None
    health: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """序列化为字典，None 端点不输出"""
        d: dict[str, Any] = {"primary": self.primary}
        if self.streaming is not None:
            d["streaming"] = self.streaming
        if self.file_transfer is not None:
            d["file_transfer"] = self.file_transfer
        if self.health is not None:
            d["health"] = self.health
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Endpoints:
        """从字典反序列化"""
        return cls(
            primary=data["primary"],
            streaming=data.get("streaming"),
            file_transfer=data.get("file_transfer"),
            health=data.get("health"),
        )


@dataclass
class AgentCard:
    """Agent 自描述能力卡片

    Agent 通过 AgentCard 向外界声明自己的身份、能力、认证方式和可用端点。
    """

    name: str
    description: str
    version: str
    url: str
    capabilities: Capabilities = field(default_factory=Capabilities)
    authentication: list[AuthScheme] = field(default_factory=list)
    skills: list[Skill] = field(default_factory=list)
    endpoints: Endpoints | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """递归序列化为字典"""
        d: dict[str, Any] = {
            "name": self.name,
            "description": self.description,
            "version": self.version,
            "url": self.url,
            "capabilities": self.capabilities.to_dict(),
        }
        if self.authentication:
            d["authentication"] = [a.to_dict() for a in self.authentication]
        if self.skills:
            d["skills"] = [s.to_dict() for s in self.skills]
        if self.endpoints is not None:
            d["endpoints"] = self.endpoints.to_dict()
        if self.metadata:
            d["metadata"] = dict(self.metadata)
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AgentCard:
        """递归从字典反序列化"""
        caps = Capabilities.from_dict(data.get("capabilities", {}))
        auth_list = [
            AuthScheme.from_dict(a) for a in data.get("authentication", [])
        ]
        skill_list = [Skill.from_dict(s) for s in data.get("skills", [])]
        endpoints_data = data.get("endpoints")
        endpoints = Endpoints.from_dict(endpoints_data) if endpoints_data else None
        return cls(
            name=data["name"],
            description=data["description"],
            version=data["version"],
            url=data["url"],
            capabilities=caps,
            authentication=auth_list,
            skills=skill_list,
            endpoints=endpoints,
            metadata=data.get("metadata", {}),
        )
