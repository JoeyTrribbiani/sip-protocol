"""FileChunk 与 FileManifest 数据类测试"""

from __future__ import annotations

import calendar
import time

import pytest

from sip_protocol.file_transfer.manifest import FileChunk, FileManifest

# ==================== FileChunk ====================


class TestFileChunk:
    """FileChunk 数据类测试"""

    def test_defaults(self) -> None:
        chunk = FileChunk()
        assert chunk.index == 0
        assert chunk.size == 0
        assert chunk.hash == ""

    def test_to_dict(self) -> None:
        chunk = FileChunk(index=3, size=1024, hash="abc123")
        d = chunk.to_dict()
        assert d == {"index": 3, "size": 1024, "hash": "abc123"}

    def test_from_dict(self) -> None:
        data = {"index": 1, "size": 2048, "hash": "deadbeef"}
        chunk = FileChunk.from_dict(data)
        assert chunk.index == 1
        assert chunk.size == 2048
        assert chunk.hash == "deadbeef"

    def test_roundtrip(self) -> None:
        original = FileChunk(index=5, size=4096, hash="cafe")
        restored = FileChunk.from_dict(original.to_dict())
        assert restored.index == original.index
        assert restored.size == original.size
        assert restored.hash == original.hash


# ==================== FileManifest ====================


class TestFileManifest:
    """FileManifest 数据类测试"""

    def test_defaults(self) -> None:
        m = FileManifest()
        # id 由 _generate_uuid7 生成，应非空
        assert m.id != ""
        assert m.file_name == ""
        assert m.mime_type == "application/octet-stream"
        assert m.total_size == 0
        assert m.chunk_size == 1048576
        assert m.content_hash == ""
        assert m.chunks == []
        assert m.total_chunks == 0
        assert m.default_ttl == 86400

    def test_total_chunks_computed(self) -> None:
        chunks = [FileChunk(index=0), FileChunk(index=1)]
        m = FileManifest(chunks=chunks)
        assert m.total_chunks == 2

    def test_to_dict(self) -> None:
        chunks = [FileChunk(index=0, size=512, hash="a1")]
        m = FileManifest(
            id="test-id",
            file_name="photo.jpg",
            mime_type="image/jpeg",
            total_size=512,
            chunk_size=512,
            content_hash="overall-hash",
            chunks=chunks,
            created_at="2025-01-01T00:00:00Z",
            expires_at="2025-01-02T00:00:00Z",
        )
        d = m.to_dict()
        assert d["id"] == "test-id"
        assert d["file_name"] == "photo.jpg"
        assert d["mime_type"] == "image/jpeg"
        assert d["total_size"] == 512
        assert d["total_chunks"] == 1
        assert d["chunk_size"] == 512
        assert d["content_hash"] == "overall-hash"
        assert d["chunks"] == [{"index": 0, "size": 512, "hash": "a1"}]
        assert d["created_at"] == "2025-01-01T00:00:00Z"
        assert d["expires_at"] == "2025-01-02T00:00:00Z"

    def test_to_dict_no_expires(self) -> None:
        """expires_at 为空时 to_dict 不应包含该字段"""
        m = FileManifest(expires_at="")
        d = m.to_dict()
        assert "expires_at" not in d

    def test_from_dict(self) -> None:
        data = {
            "id": "restore-id",
            "file_name": "doc.pdf",
            "mime_type": "application/pdf",
            "total_size": 2048,
            "chunk_size": 1024,
            "content_hash": "hash-abc",
            "chunks": [
                {"index": 0, "size": 1024, "hash": "h0"},
                {"index": 1, "size": 1024, "hash": "h1"},
            ],
            "created_at": "2025-06-01T12:00:00Z",
            "expires_at": "2025-06-02T12:00:00Z",
        }
        m = FileManifest.from_dict(data)
        assert m.id == "restore-id"
        assert m.file_name == "doc.pdf"
        assert len(m.chunks) == 2
        assert isinstance(m.chunks[0], FileChunk)
        assert m.chunks[0].hash == "h0"
        assert m.chunks[1].index == 1

    def test_roundtrip(self) -> None:
        chunks = [
            FileChunk(index=0, size=100, hash="x0"),
            FileChunk(index=1, size=200, hash="x1"),
        ]
        original = FileManifest(
            id="rt-id",
            file_name="data.bin",
            mime_type="application/octet-stream",
            total_size=300,
            chunk_size=200,
            content_hash="rt-hash",
            chunks=chunks,
            created_at="2025-03-15T08:30:00Z",
            expires_at="2025-03-16T08:30:00Z",
        )
        restored = FileManifest.from_dict(original.to_dict())
        assert restored.id == original.id
        assert restored.file_name == original.file_name
        assert restored.mime_type == original.mime_type
        assert restored.total_size == original.total_size
        assert restored.chunk_size == original.chunk_size
        assert restored.content_hash == original.content_hash
        assert restored.total_chunks == 2
        assert restored.chunks[0].hash == "x0"
        assert restored.chunks[1].size == 200
        assert restored.created_at == original.created_at
        assert restored.expires_at == original.expires_at

    def test_created_at_auto(self) -> None:
        """created_at 应自动填充为 ISO 格式，包含 T 和 Z"""
        m = FileManifest()
        assert m.created_at != ""
        assert "T" in m.created_at
        assert m.created_at.endswith("Z")

    def test_expires_at_from_ttl(self) -> None:
        """根据 default_ttl 计算 expires_at 的场景验证

        此测试验证：设置 default_ttl=3600 后，
        使用方手动计算 expires_at 时能得到正确的 ISO 时间。
        created_at 是 UTC 时间字符串，解析时也必须按 UTC 处理。
        """
        m = FileManifest(default_ttl=3600)
        # default_ttl 字段本身应正确存储
        assert m.default_ttl == 3600

        # UTC 时间字符串 → epoch 秒（使用 calendar.timegm 避免 local tz 偏移）
        created_ts = calendar.timegm(time.strptime(m.created_at, "%Y-%m-%dT%H:%M:%SZ"))
        expires_ts = created_ts + m.default_ttl
        expires_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(expires_ts))

        # 验证计算出的 expires_at 是合法 ISO 格式
        assert "T" in expires_at
        assert expires_at.endswith("Z")

        # 验证时间差精确为 3600 秒
        expires_parsed = calendar.timegm(time.strptime(expires_at, "%Y-%m-%dT%H:%M:%SZ"))
        assert abs(expires_parsed - created_ts - 3600) <= 1

    def test_empty_chunks_total_chunks(self) -> None:
        m = FileManifest(chunks=[])
        assert m.total_chunks == 0
