"""FileTransferManager 测试 — 文件分块发送与接收"""

import base64
import os

import pytest

from sip_protocol.exceptions import ChunkIntegrityError, FileTooLargeError
from sip_protocol.file_transfer.config import FileTransferConfig
from sip_protocol.file_transfer.manager import (
    FileTransferManager,
    TransferProgress,
    TransferStatus,
)
from sip_protocol.file_transfer.store import LocalFileStore
from sip_protocol.schema.parts import FileDataPart, FileRefPart

# ==================== Fixtures ====================


@pytest.fixture
def manager(tmp_path):
    """基于 tmp_path 的 FileTransferManager，小阈值便于测试"""
    store = LocalFileStore(base_path=str(tmp_path / "store"))
    config = FileTransferConfig(inline_threshold=64, chunk_size=32, max_file_size=200)
    return FileTransferManager(config=config, store=store)


@pytest.fixture
def small_file(tmp_path):
    """64 字节小文件"""
    path = tmp_path / "small.txt"
    path.write_bytes(b"a" * 64)
    return str(path)


@pytest.fixture
def large_file(tmp_path):
    """100 字节大文件（超过 inline_threshold）"""
    path = tmp_path / "large.bin"
    path.write_bytes(b"b" * 100)
    return str(path)


@pytest.fixture
def pdf_file(tmp_path):
    """PDF 文件（测试 MIME 推断）"""
    path = tmp_path / "report.pdf"
    path.write_bytes(b"%PDF-1.4 fake content")
    return str(path)


# ==================== TestSendFile ====================


class TestSendFile:
    """send_file 核心路径测试"""

    def test_small_file_returns_file_data_part(self, manager, small_file):
        """小文件内联传输，返回 FileDataPart，base64 可正确解码"""
        result = manager.send_file(small_file)
        assert isinstance(result, FileDataPart)
        decoded = base64.b64decode(result.data)
        assert decoded == b"a" * 64

    def test_large_file_returns_file_ref_part(self, manager, large_file):
        """大文件分块传输，返回 FileRefPart，url/hash/size 非空"""
        result = manager.send_file(large_file)
        assert isinstance(result, FileRefPart)
        assert result.url != ""
        assert result.hash != ""
        assert result.size == 100

    def test_large_file_manifest_stored(self, manager, large_file):
        """分块传输后 manifest 存入 store，可检索验证"""
        result = manager.send_file(large_file)
        assert isinstance(result, FileRefPart)
        manifest = manager.get_manifest(result)
        assert manifest.file_name == "large.bin"
        assert manifest.total_size == 100

    def test_large_file_chunks_stored(self, manager, large_file):
        """分块传输后每个 chunk 可从 store 读取"""
        result = manager.send_file(large_file)
        assert isinstance(result, FileRefPart)
        manifest = manager.get_manifest(result)
        for chunk_desc in manifest.chunks:
            data = manager._store.retrieve_chunk(manifest.id, chunk_desc.index)
            assert len(data) > 0

    def test_file_too_large_raises(self, manager, tmp_path):
        """超过 max_file_size 的文件抛出 FileTooLargeError"""
        big = tmp_path / "huge.bin"
        big.write_bytes(b"x" * 300)
        with pytest.raises(FileTooLargeError):
            manager.send_file(str(big))

    def test_nonexistent_file_raises(self, manager):
        """不存在的文件抛出 FileNotFoundError"""
        with pytest.raises(FileNotFoundError):
            manager.send_file("/no/such/file.txt")

    def test_mime_type_detection(self, manager, pdf_file):
        """根据扩展名推断 MIME 类型"""
        result = manager.send_file(pdf_file)
        assert result.mime_type == "application/pdf"


# ==================== TestReceiveFile ====================


class TestReceiveFile:
    """receive_file 核心路径测试"""

    def test_receive_reassembles_file(self, manager, large_file, tmp_path):
        """send_file → receive_file，原始内容与接收内容一致"""
        part = manager.send_file(large_file)
        output = str(tmp_path / "output" / "received.bin")
        manager.receive_file(part, output)
        with open(output, "rb") as f:
            assert f.read() == b"b" * 100

    def test_receive_small_file(self, manager, small_file, tmp_path):
        """FileDataPart → receive_file，内容一致"""
        part = manager.send_file(small_file)
        assert isinstance(part, FileDataPart)
        output = str(tmp_path / "output.txt")
        manager.receive_file(part, output)
        with open(output, "rb") as f:
            assert f.read() == b"a" * 64

    def test_receive_creates_parent_dirs(self, manager, small_file, tmp_path):
        """output_path 子目录不存在时自动创建"""
        part = manager.send_file(small_file)
        output = str(tmp_path / "deep" / "nested" / "dir" / "out.txt")
        manager.receive_file(part, output)
        assert os.path.exists(output)

    def test_receive_chunk_hash_mismatch_raises(self, manager, large_file, tmp_path):
        """篡改块数据后 receive 抛出 ChunkIntegrityError"""
        part = manager.send_file(large_file)
        assert isinstance(part, FileRefPart)

        # 篡改第一个 chunk 的数据
        manifest = manager.get_manifest(part)
        manager._store.store_chunk(manifest.id, 0, b"TAMPERED_DATA_HERE!!!!!!!")

        output = str(tmp_path / "tampered.bin")
        with pytest.raises(ChunkIntegrityError):
            manager.receive_file(part, output)


# ==================== TestProgress ====================


class TestProgress:
    """TransferProgress 测试"""

    def test_get_progress_nonexistent(self, manager):
        """不存在的 file_id 返回 None"""
        assert manager.get_progress("no-such-id") is None

    def test_get_progress_after_send(self, manager, large_file):
        """send 后 progress.is_complete=True, progress_ratio=1.0"""
        part = manager.send_file(large_file)
        file_id = part.hash if isinstance(part, FileRefPart) else ""
        # 对于分块文件，file_id 就是 manifest.id
        manifest = manager.get_manifest(part) if isinstance(part, FileRefPart) else None
        if manifest is not None:
            file_id = manifest.id
        progress = manager.get_progress(file_id)
        assert progress is not None
        assert progress.is_complete is True
        assert progress.progress_ratio == 1.0

    def test_transfer_status_enum(self):
        """验证所有 TransferStatus 枚举值"""
        expected = {"PENDING", "SENDING", "RECEIVING", "COMPLETED", "FAILED", "CANCELED"}
        actual = {s.name for s in TransferStatus}
        assert actual == expected

    def test_progress_ratio_calculation(self):
        """progress_ratio 正确归一化"""
        p = TransferProgress(
            file_id="test",
            file_name="test.bin",
            status=TransferStatus.SENDING,
            transferred_chunks=5,
            total_chunks=10,
            transferred_bytes=50,
            total_bytes=100,
        )
        assert p.progress_ratio == 0.5

    def test_progress_ratio_zero_total(self):
        """total 为 0 时 progress_ratio 为 0.0"""
        p = TransferProgress(
            file_id="empty",
            file_name="empty.bin",
            status=TransferStatus.PENDING,
            transferred_chunks=0,
            total_chunks=0,
            transferred_bytes=0,
            total_bytes=0,
        )
        assert p.progress_ratio == 0.0


# ==================== TestSafeOutputPath ====================


class TestSafeOutputPath:
    """_safe_output_path 路径安全测试"""

    def test_normal_path(self, tmp_path):
        """正常路径直接返回"""
        output = str(tmp_path / "output.txt")
        result = FileTransferManager._safe_output_path(output, "file.txt")
        assert result.endswith("file.txt")

    def test_path_traversal_blocked(self, tmp_path):
        """路径遍历攻击被 realpath 消除"""
        output = str(tmp_path / "safe_dir")
        result = FileTransferManager._safe_output_path(output, "../../../etc/passwd")
        # 确保结果在 safe_dir 内
        assert ".." not in result

    def test_filename_conflict_rename(self, tmp_path):
        """同名文件存在时自动追加 (2)"""
        existing = tmp_path / "file.txt"
        existing.write_text("old")
        result = FileTransferManager._safe_output_path(str(tmp_path), "file.txt")
        assert "(2)" in result

    def test_filename_conflict_multiple(self, tmp_path):
        """多次冲突递增编号"""
        (tmp_path / "file.txt").write_text("v1")
        (tmp_path / "file (2).txt").write_text("v2")
        result = FileTransferManager._safe_output_path(str(tmp_path), "file.txt")
        assert "(3)" in result


# ==================== TestChunkIter ====================


class TestChunkIter:
    """_chunk_iter 分块工具测试"""

    def test_even_split(self):
        """数据恰好整除"""
        chunks = FileTransferManager._chunk_iter(b"123456", 3)
        assert chunks == [b"123", b"456"]

    def test_remainder(self):
        """数据不整除时最后一块较小"""
        chunks = FileTransferManager._chunk_iter(b"12345", 2)
        assert chunks == [b"12", b"34", b"5"]

    def test_empty_data(self):
        """空数据返回空列表"""
        chunks = FileTransferManager._chunk_iter(b"", 32)
        assert chunks == []
