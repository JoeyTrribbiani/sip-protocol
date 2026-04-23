"""文件传输端到端集成测试"""

import os

import pytest

from sip_protocol.file_transfer import (
    FileTransferConfig,
    FileTransferManager,
    LocalFileStore,
    TransferStatus,
)
from sip_protocol.schema.parts import FileDataPart, FileRefPart


def test_send_receive_small_file(tmp_path):
    """小文件：send_file → FileDataPart → receive_file → 原始内容"""
    store = LocalFileStore(base_path=str(tmp_path / "store"))
    config = FileTransferConfig(inline_threshold=1024)
    manager = FileTransferManager(config=config, store=store)

    src = tmp_path / "hello.txt"
    src.write_bytes(b"Hello, SIP!")

    part = manager.send_file(str(src))
    assert isinstance(part, FileDataPart)

    dst = tmp_path / "output" / "hello.txt"
    manager.receive_file(part, str(dst))
    assert dst.read_bytes() == b"Hello, SIP!"


def test_send_receive_large_file(tmp_path):
    """大文件：send_file → FileRefPart → receive_file → 原始内容"""
    store = LocalFileStore(base_path=str(tmp_path / "store"))
    config = FileTransferConfig(inline_threshold=64, chunk_size=128)
    manager = FileTransferManager(config=config, store=store)

    src = tmp_path / "big.bin"
    content = os.urandom(1024)
    src.write_bytes(content)

    part = manager.send_file(str(src))
    assert isinstance(part, FileRefPart)
    assert part.size == 1024

    dst = tmp_path / "output" / "big.bin"
    manager.receive_file(part, str(dst))
    assert dst.read_bytes() == content


def test_send_receive_pdf(tmp_path):
    """PDF 文件：MIME 类型正确"""
    store = LocalFileStore(base_path=str(tmp_path / "store"))
    config = FileTransferConfig(inline_threshold=64, chunk_size=128)
    manager = FileTransferManager(config=config, store=store)

    src = tmp_path / "report.pdf"
    src.write_bytes(os.urandom(256))

    part = manager.send_file(str(src))
    assert part.mime_type == "application/pdf"

    dst = tmp_path / "report_copy.pdf"
    manager.receive_file(part, str(dst))
    assert dst.read_bytes() == src.read_bytes()


def test_package_imports():
    """验证包级导出"""
    from sip_protocol.file_transfer import (
        FileChunk,
        FileManifest,
        FileStore,
        FileTransferConfig,
        FileTransferManager,
        LocalFileStore,
        TransferProgress,
        TransferStatus,
    )

    assert FileTransferConfig is not None
    assert FileTransferManager is not None


def test_transfer_status_enum():
    """验证 TransferStatus 枚举值"""
    assert TransferStatus.PENDING.value == "pending"
    assert TransferStatus.SENDING.value == "sending"
    assert TransferStatus.RECEIVING.value == "receiving"
    assert TransferStatus.COMPLETED.value == "completed"
    assert TransferStatus.FAILED.value == "failed"
    assert TransferStatus.CANCELED.value == "canceled"


def test_progress_ratio(tmp_path):
    """验证进度归一化"""
    store = LocalFileStore(base_path=str(tmp_path / "store"))
    config = FileTransferConfig(inline_threshold=64, chunk_size=128)
    manager = FileTransferManager(config=config, store=store)

    src = tmp_path / "data.bin"
    src.write_bytes(os.urandom(256))
    ref = manager.send_file(str(src))

    progress = manager.get_progress(ref.url.split("/")[-2])
    assert progress is not None
    assert progress.is_complete is True
    assert progress.progress_ratio == 1.0


def test_file_name_conflict(tmp_path):
    """文件名冲突时自动重命名"""
    store = LocalFileStore(base_path=str(tmp_path / "store"))
    config = FileTransferConfig(inline_threshold=64, chunk_size=128)
    manager = FileTransferManager(config=config, store=store)

    # src 在独立目录，避免和 dst 路径冲突
    src = tmp_path / "source" / "output.txt"
    src.parent.mkdir()
    src.write_bytes(os.urandom(128))
    src_content = src.read_bytes()

    # 创建同名的已存在目标文件
    dst = tmp_path / "output.txt"
    dst.write_bytes(b"existing")
    dst2 = tmp_path / "output (2).txt"  # 预期重命名路径

    ref = manager.send_file(str(src))
    manager.receive_file(ref, str(dst))

    # 原文件未被覆盖
    assert dst.read_bytes() == b"existing"
    # 新文件在重命名路径
    assert dst2.read_bytes() == src_content
