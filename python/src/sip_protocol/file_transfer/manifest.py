"""文件清单 — 描述分块文件的元数据与块列表"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from sip_protocol.schema._utils import _generate_uuid7, _iso_now


@dataclass
class FileChunk:
    """单个文件块的描述"""

    index: int = 0
    size: int = 0
    hash: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"index": self.index, "size": self.size, "hash": self.hash}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> FileChunk:
        return cls(
            index=data.get("index", 0),
            size=data.get("size", 0),
            hash=data.get("hash", ""),
        )


@dataclass
class FileManifest:
    """文件清单 — 包含完整文件描述和块列表"""

    id: str = field(default_factory=_generate_uuid7)
    file_name: str = ""
    mime_type: str = "application/octet-stream"
    total_size: int = 0
    chunk_size: int = 1048576
    content_hash: str = ""
    chunks: list[FileChunk] = field(default_factory=list)
    created_at: str = field(default_factory=_iso_now)
    expires_at: str = ""
    default_ttl: int = 86400

    @property
    def total_chunks(self) -> int:
        return len(self.chunks)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "id": self.id,
            "file_name": self.file_name,
            "mime_type": self.mime_type,
            "total_size": self.total_size,
            "total_chunks": self.total_chunks,
            "chunk_size": self.chunk_size,
            "content_hash": self.content_hash,
            "chunks": [c.to_dict() for c in self.chunks],
            "created_at": self.created_at,
        }
        if self.expires_at:
            d["expires_at"] = self.expires_at
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> FileManifest:
        chunks = [FileChunk.from_dict(c) for c in data.get("chunks", [])]
        return cls(
            id=data.get("id", ""),
            file_name=data.get("file_name", ""),
            mime_type=data.get("mime_type", "application/octet-stream"),
            total_size=data.get("total_size", 0),
            chunk_size=data.get("chunk_size", 1048576),
            content_hash=data.get("content_hash", ""),
            chunks=chunks,
            created_at=data.get("created_at", ""),
            expires_at=data.get("expires_at", ""),
        )
