"""SIP 消息 Schema Part 类型

Part是消息内容的载体，采用discriminated union模式，通过type字段区分。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class TextPart:
    """纯文本Part"""

    text: str

    @property
    def type(self) -> str:
        return "text"

    def to_dict(self) -> dict[str, Any]:
        return {"type": self.type, "text": self.text}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TextPart:
        return cls(text=data.get("text", ""))


@dataclass
class DataPart:
    """结构化数据Part"""

    content_type: str = "application/json"
    data: Any = None

    @property
    def type(self) -> str:
        return "data"

    def to_dict(self) -> dict[str, Any]:
        return {"type": self.type, "content_type": self.content_type, "data": self.data}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DataPart:
        return cls(content_type=data.get("content_type", "application/json"), data=data.get("data"))


@dataclass
class FileRefPart:
    """文件引用Part（轻量，指向远程文件）"""

    url: str = ""
    hash: str = ""
    name: str = ""
    size: int = 0
    mime_type: str = "application/octet-stream"

    @property
    def type(self) -> str:
        return "file_ref"

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.type,
            "url": self.url,
            "hash": self.hash,
            "name": self.name,
            "size": self.size,
            "mime_type": self.mime_type,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> FileRefPart:
        return cls(
            url=data.get("url", ""),
            hash=data.get("hash", ""),
            name=data.get("name", ""),
            size=data.get("size", 0),
            mime_type=data.get("mime_type", "application/octet-stream"),
        )


@dataclass
class FileDataPart:
    """文件内联Part（重量级，base64编码）"""

    data: str = ""
    name: str = ""
    mime_type: str = "application/octet-stream"

    @property
    def type(self) -> str:
        return "file_data"

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.type,
            "data": self.data,
            "name": self.name,
            "mime_type": self.mime_type,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> FileDataPart:
        return cls(
            data=data.get("data", ""),
            name=data.get("name", ""),
            mime_type=data.get("mime_type", "application/octet-stream"),
        )


@dataclass
class ToolRequestPart:
    """工具调用请求Part"""

    call_id: str = ""
    name: str = ""
    arguments: dict[str, Any] = field(default_factory=dict)

    @property
    def type(self) -> str:
        return "tool_request"

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.type,
            "call_id": self.call_id,
            "name": self.name,
            "arguments": self.arguments,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ToolRequestPart:
        return cls(
            call_id=data.get("call_id", ""),
            name=data.get("name", ""),
            arguments=data.get("arguments", {}),
        )


@dataclass
class ToolResponsePart:
    """工具调用响应Part"""

    call_id: str = ""
    result: Any = None
    error: str | None = None

    @property
    def type(self) -> str:
        return "tool_response"

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"type": self.type, "call_id": self.call_id}
        if self.error is not None:
            d["error"] = self.error
        else:
            d["result"] = self.result
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ToolResponsePart:
        return cls(
            call_id=data.get("call_id", ""), result=data.get("result"), error=data.get("error")
        )


@dataclass
class ContextPart:
    """上下文传递Part"""

    key: str = ""
    value: Any = None
    ttl: int = 86400

    @property
    def type(self) -> str:
        return "context"

    def to_dict(self) -> dict[str, Any]:
        return {"type": self.type, "key": self.key, "value": self.value, "ttl": self.ttl}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ContextPart:
        return cls(key=data.get("key", ""), value=data.get("value"), ttl=data.get("ttl", 86400))


@dataclass
class StreamPart:
    """流式数据块Part"""

    chunk_index: int = 0
    total_chunks: int | None = None
    is_final: bool = False
    data: Any = None

    @property
    def type(self) -> str:
        return "stream"

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "type": self.type,
            "chunk_index": self.chunk_index,
            "is_final": self.is_final,
            "data": self.data,
        }
        if self.total_chunks is not None:
            d["total_chunks"] = self.total_chunks
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> StreamPart:
        return cls(
            chunk_index=data.get("chunk_index", 0),
            total_chunks=data.get("total_chunks"),
            is_final=data.get("is_final", False),
            data=data.get("data"),
        )


def part_from_dict(data: dict[str, Any]) -> Any:
    """根据type字段分发，从字典创建对应的Part实例"""
    type_val = data.get("type", "")
    part_map: dict[str, type[Any]] = {
        "text": TextPart,
        "data": DataPart,
        "file_ref": FileRefPart,
        "file_data": FileDataPart,
        "tool_request": ToolRequestPart,
        "tool_response": ToolResponsePart,
        "context": ContextPart,
        "stream": StreamPart,
    }
    cls = part_map.get(type_val)
    if cls is None:
        raise ValueError(f"Unknown part type: {type_val}")
    return cls.from_dict(data)
