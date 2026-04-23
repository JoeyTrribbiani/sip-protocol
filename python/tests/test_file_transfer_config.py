"""FileTransferConfig 与文件传输异常测试"""

import pytest

from sip_protocol.exceptions import (
    FileTransferError,
    ChunkIntegrityError,
    FileTooLargeError,
    SIPError,
)

# ==================== FileTransferConfig 测试 ====================


class TestFileTransferConfig:
    """FileTransferConfig 配置类测试"""

    def test_defaults(self):
        from sip_protocol.file_transfer.config import FileTransferConfig

        cfg = FileTransferConfig()
        assert cfg.inline_threshold == 4096
        assert cfg.chunk_size == 1048576
        assert cfg.max_file_size == 5368709120
        assert cfg.max_chunks == 5120
        assert cfg.default_ttl == 86400

    def test_custom_values(self):
        from sip_protocol.file_transfer.config import FileTransferConfig

        cfg = FileTransferConfig(
            inline_threshold=8192,
            chunk_size=2097152,
            max_file_size=10737418240,
            max_chunks=10240,
            default_ttl=172800,
        )
        assert cfg.inline_threshold == 8192
        assert cfg.chunk_size == 2097152
        assert cfg.max_file_size == 10737418240
        assert cfg.max_chunks == 10240
        assert cfg.default_ttl == 172800

    def test_should_inline_true(self):
        from sip_protocol.file_transfer.config import FileTransferConfig

        cfg = FileTransferConfig(inline_threshold=4096)
        assert cfg.should_inline(100) is True
        assert cfg.should_inline(4096) is True

    def test_should_inline_false(self):
        from sip_protocol.file_transfer.config import FileTransferConfig

        cfg = FileTransferConfig(inline_threshold=4096)
        assert cfg.should_inline(4097) is False
        assert cfg.should_inline(1048576) is False

    def test_validate_size_ok(self):
        from sip_protocol.file_transfer.config import FileTransferConfig

        cfg = FileTransferConfig(max_file_size=5368709120)
        # 不应抛出异常
        cfg.validate_size(1024)
        cfg.validate_size(5368709120)

    def test_validate_size_too_large(self):
        from sip_protocol.file_transfer.config import FileTransferConfig

        cfg = FileTransferConfig(max_file_size=5368709120)
        with pytest.raises(FileTooLargeError) as exc_info:
            cfg.validate_size(5368709121)
        err = exc_info.value
        assert err.code == "SIP-FILE-002"
        assert "5368709121" in err.message
        assert "5368709120" in err.message

    def test_slots_prevent_arbitrary_attributes(self):
        """__slots__ 应阻止意外属性赋值"""
        from sip_protocol.file_transfer.config import FileTransferConfig

        cfg = FileTransferConfig()
        with pytest.raises(AttributeError):
            cfg.nonexistent_field = 42  # type: ignore[attr-defined]


# ==================== 文件传输异常测试 ====================


class TestFileTransferExceptions:
    """文件传输异常体系测试"""

    def test_file_transfer_error_code(self):
        err = FileTransferError()
        assert isinstance(err, SIPError)
        assert err.code == "SIP-FILE-000"
        assert err.message == "文件传输错误"

    def test_file_transfer_error_custom_message(self):
        err = FileTransferError(message="传输中断")
        assert err.message == "传输中断"
        assert err.code == "SIP-FILE-000"

    def test_chunk_integrity_error(self):
        err = ChunkIntegrityError(chunk_index=7)
        assert isinstance(err, FileTransferError)
        assert err.code == "SIP-FILE-001"
        assert err.recoverable is False
        assert "7" in err.message

    def test_chunk_integrity_error_negative_index(self):
        err = ChunkIntegrityError(chunk_index=-1)
        assert "完整性校验失败" in err.message

    def test_file_too_large_error(self):
        err = FileTooLargeError(file_size=9999, max_size=5000)
        assert isinstance(err, FileTransferError)
        assert err.code == "SIP-FILE-002"
        assert "9999" in err.message
        assert "5000" in err.message

    def test_from_dict_roundtrip_file_transfer_error(self):
        original = FileTransferError()
        d = original.to_dict()
        recovered = SIPError.from_dict(d)
        assert isinstance(recovered, FileTransferError)
        assert recovered.code == original.code
        assert recovered.message == original.message

    def test_from_dict_roundtrip_chunk_integrity_error(self):
        original = ChunkIntegrityError(chunk_index=3)
        d = original.to_dict()
        recovered = SIPError.from_dict(d)
        assert isinstance(recovered, ChunkIntegrityError)
        assert recovered.code == original.code
        assert recovered.recoverable == original.recoverable

    def test_from_dict_roundtrip_file_too_large_error(self):
        original = FileTooLargeError(file_size=100, max_size=50)
        d = original.to_dict()
        recovered = SIPError.from_dict(d)
        assert isinstance(recovered, FileTooLargeError)
        assert recovered.code == original.code
