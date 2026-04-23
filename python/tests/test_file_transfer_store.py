"""FileStore / LocalFileStore 测试"""

import time

import pytest

from sip_protocol.file_transfer.manifest import FileChunk, FileManifest
from sip_protocol.file_transfer.store import LocalFileStore

# ==================== Fixtures ====================


@pytest.fixture
def store(tmp_path):
    """基于 tmp_path 的 LocalFileStore 实例"""
    return LocalFileStore(base_path=str(tmp_path))


@pytest.fixture
def sample_manifest():
    """构造一个简单的 FileManifest"""
    return FileManifest(
        file_name="test.txt",
        mime_type="text/plain",
        total_size=100,
        chunk_size=50,
        content_hash="abc123",
        chunks=[
            FileChunk(index=0, size=50, hash="h0"),
            FileChunk(index=1, size=50, hash="h1"),
        ],
    )


# ==================== 测试 ====================


class TestLocalFileStore:
    """LocalFileStore 核心功能测试"""

    def test_store_and_retrieve_manifest(self, store, sample_manifest):
        """存储并读取 manifest，验证 id 和 total_chunks 一致"""
        path = store.store_manifest(sample_manifest)
        assert path.endswith("manifest.json")

        retrieved = store.retrieve_manifest(path)
        assert retrieved.id == sample_manifest.id
        assert retrieved.total_chunks == sample_manifest.total_chunks

    def test_store_and_retrieve_chunk(self, store):
        """存储并读取单个 chunk，验证内容一致"""
        data = b"hello world"
        path = store.store_chunk("file-1", 0, data)
        assert "chunk_0" in path

        result = store.retrieve_chunk("file-1", 0)
        assert result == data

    def test_delete_file(self, store, sample_manifest):
        """删除文件后目录不存在"""
        store.store_manifest(sample_manifest)
        store.store_chunk(sample_manifest.id, 0, b"data")

        store.delete(sample_manifest.id)

        import os

        assert not os.path.exists(store._file_dir(sample_manifest.id))

    def test_retrieve_nonexistent_manifest_raises(self, store, tmp_path):
        """读取不存在的 manifest 抛出 FileNotFoundError"""
        fake_path = str(tmp_path / "no_such_file.json")
        with pytest.raises(FileNotFoundError, match="文件清单不存在"):
            store.retrieve_manifest(fake_path)

    def test_retrieve_nonexistent_chunk_raises(self, store):
        """读取不存在的 chunk 抛出 FileNotFoundError"""
        with pytest.raises(FileNotFoundError, match="文件块不存在"):
            store.retrieve_chunk("no-such-file", 0)

    def test_cleanup_expired(self, store, tmp_path):
        """cleanup_expired 清理过期文件"""
        # 构造一个已过期的 manifest（expires_at 设为过去时间）
        expired = FileManifest(
            id="expired-file",
            file_name="old.txt",
            expires_at="2000-01-01T00:00:00Z",
        )
        store.store_manifest(expired)

        cleaned = store.cleanup_expired()
        assert cleaned >= 1

    def test_multiple_chunks(self, store):
        """存储并读取多个 chunk，全部内容正确"""
        file_id = "multi-chunk-file"
        chunks = {i: f"chunk-data-{i}".encode() for i in range(5)}

        for idx, data in chunks.items():
            store.store_chunk(file_id, idx, data)

        for idx, expected in chunks.items():
            assert store.retrieve_chunk(file_id, idx) == expected
