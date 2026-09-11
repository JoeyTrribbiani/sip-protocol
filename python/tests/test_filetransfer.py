"""filetransfer 模块测试 — 加密文件工件（pack/unpack）

覆盖：加解密往返 / 分块乱序拒判 / 篡改拒判 / 截断拒判 / 跨工件拼接拒判 /
大文件流式内存上界 / 路径穿越清洗 / 冲突重命名 / AEAD AAD 原语兼容性。
"""

from __future__ import annotations

import os
import secrets
import struct
import tracemalloc

import pytest
from cryptography.exceptions import InvalidTag

from sip_protocol.crypto.xchacha20_poly1305 import (
    decrypt_xchacha20_poly1305,
    encrypt_xchacha20_poly1305,
    generate_nonce,
)
from sip_protocol.exceptions import (
    ArtifactCorruptedError,
    ChunkIntegrityError,
    FileTooLargeError,
)
from sip_protocol.filetransfer import pack_file, unpack_file
from sip_protocol.filetransfer import format as ft_format
from sip_protocol.filetransfer.packer import _write_artifact
from sip_protocol.filetransfer.unpacker import _safe_file_name

KEY = secrets.token_bytes(32)
CHUNK = 64 * 1024  # 测试用小分块，多块场景不用造大文件


def make_src(tmp_path, name: str, size: int) -> str:
    """生成随机内容源文件"""
    path = str(tmp_path / name)
    with open(path, "wb") as f:
        f.write(secrets.token_bytes(size))
    return path


def artifact_layout(artifact_path: str, master_key: bytes) -> list[int]:
    """计算工件中各块帧的起始偏移（白盒：定位篡改点）"""
    from sip_protocol.filetransfer.unpacker import _read_header

    with open(artifact_path, "rb") as f:
        header, _ = _read_header(f, master_key)
    offsets = []
    off = ft_format.prefix_length() + 12 + len(header.to_json_bytes()) + 16
    for i in range(header.total_chunks):
        offsets.append(off)
        off += 12 + header.expected_chunk_length(i) + 16
    return offsets


# ==================== 加解密往返 ====================


class TestRoundtrip:
    """pack → unpack 往返与元数据保持"""

    @pytest.mark.parametrize(
        "size",
        [
            0,  # 空文件（0 块）
            100,  # 单块不满
            CHUNK,  # 恰好一块
            2 * CHUNK + 333,  # 多块 + 非对齐尾块
        ],
    )
    def test_roundtrip_various_sizes(self, tmp_path, size):
        src = make_src(tmp_path, "payload.bin", size)
        result = pack_file(src, KEY, chunk_size=CHUNK)
        assert result.total_size == size
        assert os.path.isfile(result.artifact_path)

        out = unpack_file(result.artifact_path, KEY, output_path=str(tmp_path / "out.bin"))
        assert out.total_size == size
        assert out.chunks_verified == result.total_chunks
        with open(out.output_path, "rb") as f:
            assert f.read() == secrets_token_bytes_read(src)

    def test_metadata_preserved(self, tmp_path):
        src = make_src(tmp_path, "photo.png", 1000)
        result = pack_file(src, KEY, chunk_size=CHUNK)
        out = unpack_file(result.artifact_path, KEY, output_path=str(tmp_path / "out.bin"))
        assert out.file_name == "photo.png"
        assert result.file_id and result.artifact_size > 1000

    def test_default_output_paths(self, tmp_path):
        src = make_src(tmp_path, "default.bin", 500)
        result = pack_file(src, KEY, chunk_size=CHUNK)
        # 默认工件名 = 源文件 + .sipft
        assert result.artifact_path == src + ".sipft"
        # 默认解包到工件所在目录，文件名取头部（源文件占名 → 自动 (2)）
        out = unpack_file(result.artifact_path, KEY)
        assert out.output_path == str(tmp_path / "default (2).bin")
        # output_path 为目录时拼入头部文件名
        (tmp_path / "sub").mkdir()
        out2 = unpack_file(result.artifact_path, KEY, output_path=str(tmp_path / "sub"))
        assert out2.output_path == str(tmp_path / "sub" / "default.bin")

    def test_pack_non_deterministic(self, tmp_path):
        src = make_src(tmp_path, "twice.bin", 4096)
        a1 = pack_file(src, KEY, chunk_size=CHUNK, output_path=str(tmp_path / "a1.sipft"))
        a2 = pack_file(src, KEY, chunk_size=CHUNK, output_path=str(tmp_path / "a2.sipft"))
        assert a1.file_id != a2.file_id
        with open(a1.artifact_path, "rb") as f1, open(a2.artifact_path, "rb") as f2:
            assert f1.read() != f2.read()
        # 两个工件都能解回原文
        for a in (a1, a2):
            out = unpack_file(a.artifact_path, KEY, output_path=str(tmp_path / "r.bin"))
            with open(out.output_path, "rb") as f:
                assert f.read() == secrets_token_bytes_read(src)

    def test_custom_chunk_size(self, tmp_path):
        src = make_src(tmp_path, "chunked.bin", 3 * 1024 + 1)
        result = pack_file(src, KEY, chunk_size=1024)
        assert result.chunk_size == 1024
        assert result.total_chunks == 4
        out = unpack_file(result.artifact_path, KEY)
        with open(out.output_path, "rb") as f:
            assert len(f.read()) == 3 * 1024 + 1


# ==================== 完整性拒判 ====================


class TestIntegrityRejection:
    """篡改 / 乱序 / 截断 / 拼接全链路拒判"""

    def _packed(self, tmp_path, size=3 * CHUNK + 100, chunk_size=CHUNK):
        src = make_src(tmp_path, "target.bin", size)
        result = pack_file(src, KEY, chunk_size=chunk_size)
        return src, result

    def _flip_byte(self, path: str, offset: int):
        with open(path, "r+b") as f:
            f.seek(offset)
            byte = f.read(1)
            f.seek(offset)
            f.write(bytes([byte[0] ^ 0xFF]))

    def test_tampered_chunk_ciphertext_rejected(self, tmp_path):
        _, result = self._packed(tmp_path)
        offsets = artifact_layout(result.artifact_path, KEY)
        # 篡改第 1 块密文（跳过 nonce，取密文中段）
        self._flip_byte(result.artifact_path, offsets[1] + 12 + 10)
        with pytest.raises(ChunkIntegrityError) as exc_info:
            unpack_file(result.artifact_path, KEY)
        assert exc_info.value.details.get("chunk_index") == 1

    def test_tampered_chunk_tag_rejected(self, tmp_path):
        _, result = self._packed(tmp_path)
        offsets = artifact_layout(result.artifact_path, KEY)
        self._flip_byte(result.artifact_path, offsets[1] + 12 + CHUNK + 8)
        with pytest.raises(ChunkIntegrityError):
            unpack_file(result.artifact_path, KEY)

    def test_reordered_chunks_rejected(self, tmp_path):
        _, result = self._packed(tmp_path)
        offsets = artifact_layout(result.artifact_path, KEY)
        frame_len = 12 + CHUNK + 16
        with open(result.artifact_path, "rb") as f:
            blob = bytearray(f.read())
        # 整帧交换第 0、1 块（nonce+密文+标签一起搬）
        frame0 = bytes(blob[offsets[0] : offsets[0] + frame_len])
        frame1 = bytes(blob[offsets[1] : offsets[1] + frame_len])
        blob[offsets[0] : offsets[0] + frame_len] = frame1
        blob[offsets[1] : offsets[1] + frame_len] = frame0
        with open(result.artifact_path, "wb") as f:
            f.write(blob)
        # 第 0 帧实为块 1：AAD 块序不符 → 认证失败
        with pytest.raises(ChunkIntegrityError) as exc_info:
            unpack_file(result.artifact_path, KEY)
        assert exc_info.value.details.get("chunk_index") == 0

    def test_middle_chunk_deleted_rejected(self, tmp_path):
        _, result = self._packed(tmp_path)
        offsets = artifact_layout(result.artifact_path, KEY)
        frame_len = 12 + CHUNK + 16
        with open(result.artifact_path, "rb") as f:
            blob = bytearray(f.read())
        # 抽掉第 1 帧：后续块序整体前移，AAD 索引错位
        del blob[offsets[1] : offsets[1] + frame_len]
        with open(result.artifact_path, "wb") as f:
            f.write(blob)
        with pytest.raises(ChunkIntegrityError):
            unpack_file(result.artifact_path, KEY)

    def test_truncated_artifact_rejected(self, tmp_path):
        _, result = self._packed(tmp_path)
        with open(result.artifact_path, "rb") as f:
            blob = f.read()
        # 砍掉最后一块整帧
        with open(result.artifact_path, "wb") as f:
            f.write(blob[: -(12 + CHUNK + 16)])
        with pytest.raises(ArtifactCorruptedError):
            unpack_file(result.artifact_path, KEY)

    def test_truncated_header_rejected(self, tmp_path):
        _, result = self._packed(tmp_path)
        with open(result.artifact_path, "rb") as f:
            blob = f.read()
        with open(result.artifact_path, "wb") as f:
            f.write(blob[:20])  # 魔数+长度+部分头部
        with pytest.raises(ArtifactCorruptedError):
            unpack_file(result.artifact_path, KEY)

    def test_trailing_garbage_rejected(self, tmp_path):
        _, result = self._packed(tmp_path)
        with open(result.artifact_path, "ab") as f:
            f.write(b"GARBAGE")
        with pytest.raises(ArtifactCorruptedError):
            unpack_file(result.artifact_path, KEY)

    def test_wrong_key_rejected(self, tmp_path):
        _, result = self._packed(tmp_path)
        with pytest.raises(ArtifactCorruptedError) as exc_info:
            unpack_file(result.artifact_path, secrets.token_bytes(32))
        assert "密钥错误" in str(exc_info.value)

    def test_corrupted_magic_rejected(self, tmp_path):
        _, result = self._packed(tmp_path)
        self._flip_byte(result.artifact_path, 2)
        with pytest.raises(ArtifactCorruptedError):
            unpack_file(result.artifact_path, KEY)

    def test_tampered_header_rejected(self, tmp_path):
        _, result = self._packed(tmp_path)
        header_ct_start = ft_format.prefix_length() + 12
        self._flip_byte(result.artifact_path, header_ct_start + 5)
        with pytest.raises(ArtifactCorruptedError):
            unpack_file(result.artifact_path, KEY)

    def test_cross_artifact_splice_rejected(self, tmp_path):
        """同密钥两个工件，把 B 的一帧移植进 A —— file_id 绑定拒判"""
        _, result_a = self._packed(tmp_path)
        src_b = make_src(tmp_path, "donor.bin", 3 * CHUNK + 100)
        result_b = pack_file(src_b, KEY, chunk_size=CHUNK)

        offsets_a = artifact_layout(result_a.artifact_path, KEY)
        offsets_b = artifact_layout(result_b.artifact_path, KEY)
        frame_len = 12 + CHUNK + 16
        with open(result_b.artifact_path, "rb") as f:
            f.seek(offsets_b[0])
            donor_frame = f.read(frame_len)
        with open(result_a.artifact_path, "r+b") as f:
            f.seek(offsets_a[1])
            f.write(donor_frame)

        with pytest.raises(ChunkIntegrityError):
            unpack_file(result_a.artifact_path, KEY)


# ==================== 边界与安全 ====================


class TestBoundariesAndSafety:
    """大小上限 / 参数校验 / 路径穿越 / 冲突重命名 / 半成品清理"""

    def test_file_too_large_rejected(self, tmp_path, monkeypatch):
        from sip_protocol.filetransfer import packer

        monkeypatch.setattr(packer, "MAX_FILE_SIZE", 100)
        src = make_src(tmp_path, "big.bin", 200)
        with pytest.raises(FileTooLargeError):
            pack_file(src, KEY, chunk_size=CHUNK)

    def test_invalid_chunk_size_rejected(self, tmp_path):
        src = make_src(tmp_path, "any.bin", 10)
        with pytest.raises(ArtifactCorruptedError):
            pack_file(src, KEY, chunk_size=16)  # 低于下限 1KB
        with pytest.raises(ArtifactCorruptedError):
            pack_file(src, KEY, chunk_size=32 * 1024 * 1024)  # 超上限 16MB

    def test_missing_source_rejected(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            pack_file(str(tmp_path / "nope.bin"), KEY)

    def test_missing_artifact_rejected(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            unpack_file(str(tmp_path / "nope.sipft"), KEY)

    def test_output_conflict_renumbered(self, tmp_path):
        src = make_src(tmp_path, "clash.bin", 10)
        result = pack_file(src, KEY, chunk_size=CHUNK)
        out1 = unpack_file(result.artifact_path, KEY, output_path=str(tmp_path / "clash.bin"))
        # 源文件已占用 clash.bin → 自动落 "clash (2).bin"
        assert out1.output_path == str(tmp_path / "clash (2).bin")

    def test_path_traversal_sanitized(self, tmp_path):
        """伪造携带路径穿越的头部文件名 —— 解包只落 basename"""
        from sip_protocol.filetransfer.format import ArtifactHeader

        header = ArtifactHeader(
            file_id=os.urandom(16).hex(),
            file_name="../../../../etc/evil.sh",
            mime_type="application/x-sh",
            total_size=4,
            chunk_size=CHUNK,
            total_chunks=1,
            created_at="2026-09-11T00:00:00+00:00",
        )
        artifact = str(tmp_path / "evil.sipft")
        _write_artifact(artifact, make_src(tmp_path, "real.bin", 4), KEY, header)
        sandbox = tmp_path / "sandbox"
        sandbox.mkdir()
        out = unpack_file(artifact, KEY, output_path=str(sandbox))
        assert out.output_path == str(sandbox / "evil.sh")
        assert os.path.isfile(str(sandbox / "evil.sh"))

    def test_safe_file_name_unit(self):
        assert _safe_file_name("../../a/b/c.txt") == "c.txt"
        assert _safe_file_name("..\\..\\win.txt") == "win.txt"
        assert _safe_file_name("   ") == "unpacked_file"
        assert _safe_file_name("/etc/passwd") == "passwd"

    def test_failed_unpack_leaves_no_partial_file(self, tmp_path):
        src = make_src(tmp_path, "partial.bin", 2 * CHUNK + 5)
        result = pack_file(src, KEY, chunk_size=CHUNK)
        offsets = artifact_layout(result.artifact_path, KEY)
        with open(result.artifact_path, "r+b") as f:
            f.seek(offsets[2] + 12 + 3)
            f.write(b"\x00")
        with pytest.raises(ChunkIntegrityError):
            unpack_file(result.artifact_path, KEY)
        # 目录中不留半成品/临时文件
        leftovers = [p for p in os.listdir(tmp_path) if "unpacking" in p or "packing" in p]
        assert leftovers == []


# ==================== 大文件流式 ====================


class TestStreaming:
    """大文件常量内存：峰值内存远小于文件大小"""

    def test_pack_unpack_streaming_memory(self, tmp_path):
        size = 8 * 1024 * 1024  # 8MB
        chunk_size = 256 * 1024  # 32 块
        src = make_src(tmp_path, "large.bin", size)

        tracemalloc.start()
        result = pack_file(src, KEY, chunk_size=chunk_size)
        _, pack_peak = tracemalloc.get_traced_memory()
        out = unpack_file(result.artifact_path, KEY, output_path=str(tmp_path / "restored.bin"))
        _, unpack_peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        assert out.chunks_verified == 32
        with open(out.output_path, "rb") as f:
            assert len(f.read()) == size
        # 流式上界：峰值 < 文件一半（非流式全量 read 会到 ~8MB+）
        assert pack_peak < size / 2, f"打包峰值内存 {pack_peak} 超上界"
        assert unpack_peak < size / 2, f"解包峰值内存 {unpack_peak} 超上界"


# ==================== AEAD AAD 原语兼容性 ====================


class TestAeadAadPrimitive:
    """crypto 原语新增可选 aad 参数 —— 既有调用（无 aad）行为不变"""

    def test_aad_roundtrip_and_mismatch(self):
        key = secrets.token_bytes(32)
        nonce = generate_nonce()
        ct, tag = encrypt_xchacha20_poly1305(key, b"payload", nonce, aad=b"ctx-1")
        assert decrypt_xchacha20_poly1305(key, ct, nonce, tag, aad=b"ctx-1") == b"payload"
        with pytest.raises(InvalidTag):
            decrypt_xchacha20_poly1305(key, ct, nonce, tag, aad=b"ctx-2")

    def test_legacy_calls_without_aad_unchanged(self):
        key = secrets.token_bytes(32)
        nonce = generate_nonce()
        ct, tag = encrypt_xchacha20_poly1305(key, b"payload", nonce)
        assert decrypt_xchacha20_poly1305(key, ct, nonce, tag) == b"payload"

    def test_aad_chain_binds_order(self):
        """tag 链最小模型：交换两块必被拒（模块级原理验证）"""
        key = secrets.token_bytes(32)
        nonce0, nonce1 = generate_nonce(), generate_nonce()
        _, tag0 = encrypt_xchacha20_poly1305(
            key, b"AAA", nonce0, aad=b"f" + struct.pack(">I", 0) + b"\x00" * 16
        )
        _, tag1 = encrypt_xchacha20_poly1305(
            key, b"BBB", nonce1, aad=b"f" + struct.pack(">I", 1) + tag0
        )
        # 把块 1 的密文放到位置 0（AAD 索引 0 + 链首零标签）→ 认证失败
        with pytest.raises(InvalidTag):
            decrypt_xchacha20_poly1305(
                key, b"BBB", nonce1, tag1, aad=b"f" + struct.pack(">I", 0) + b"\x00" * 16
            )


def secrets_token_bytes_read(path: str) -> bytes:
    """读回源文件内容用于比对"""
    with open(path, "rb") as f:
        return f.read()
