"""加密文件工件格式 — 二进制布局、头部与密钥调度

工件（artifact）布局（大端）::

    偏移   内容
    0      MAGIC "SIPFT1.0"（8 字节，明文，并作为 AAD 前缀参与认证）
    8      header_len（4 字节 uint32）
    12     header_nonce（12 字节）
    24     header_ciphertext（header_len 字节，明文为头部 JSON）
    24+L   header_tag（16 字节）
    之后   每块一帧：chunk_nonce(12) | chunk_ct(期望长度) | chunk_tag(16)

密钥调度（HKDF-SHA256，复用 crypto 原语）::

    header_key = HKDF(master, salt=b"SIP-FileTransfer", info=b"header")
    chunk_key_i = HKDF(master, salt=file_id(16字节), info=b"chunk:{i}")

完整性链（AEAD tag 链，防篡改/重排/拼接/截断）::

    AAD(header) = MAGIC
    AAD(chunk_i) = MAGIC + file_id + index(4字节) + prev_tag(16字节)
    链首 prev_tag = header_tag

任一块的密文/标签被改动、块序被重排、块被跨工件移植（file_id 不同）
或尾部被截断，解包时都会在对应块上认证失败或计数不符。
"""

from __future__ import annotations

import json
import os
import struct
from dataclasses import dataclass
from typing import Any

from sip_protocol.crypto.hkdf import hkdf
from sip_protocol.crypto.xchacha20_poly1305 import NONCE_LENGTH
from sip_protocol.exceptions import ArtifactCorruptedError

# ==================== 格式常量 ====================

MAGIC = b"SIPFT1.0"
MAGIC_LENGTH = len(MAGIC)
HEADER_FORMAT = 1
TAG_LENGTH = 16
FILE_ID_LENGTH = 16

# 头部 JSON 大小上限（文件名等元数据按 64KB 封顶）
MAX_HEADER_LENGTH = 64 * 1024
# 分块数上限（防解包端被伪造头部撑爆）
MAX_TOTAL_CHUNKS = 65536
# 默认/极限分块大小
DEFAULT_CHUNK_SIZE = 1024 * 1024
MIN_CHUNK_SIZE = 1024
MAX_CHUNK_SIZE = 16 * 1024 * 1024
# 单文件大小上限（默认 5GB，与 v1.x file_transfer 保持一致）
MAX_FILE_SIZE = 5 * 1024 * 1024 * 1024

_KDF_SALT = b"SIP-FileTransfer"

# magic(8) + header_len(4)
_PREFIX_LENGTH = MAGIC_LENGTH + 4
# nonce(12) + tag(16)
_FRAME_OVERHEAD = NONCE_LENGTH + TAG_LENGTH


def validate_chunk_size(chunk_size: int) -> None:
    """校验分块大小，非法则抛 ArtifactCorruptedError"""
    if not MIN_CHUNK_SIZE <= chunk_size <= MAX_CHUNK_SIZE:
        raise ArtifactCorruptedError(
            message=f"分块大小非法: {chunk_size}（合法范围 {MIN_CHUNK_SIZE}..{MAX_CHUNK_SIZE}）"
        )


@dataclass
class ArtifactHeader:
    """工件头部 — 认证过的文件元数据（解包前密文存储）"""

    file_id: str
    file_name: str
    mime_type: str
    total_size: int
    chunk_size: int
    total_chunks: int
    created_at: str

    def to_json_bytes(self) -> bytes:
        """序列化为头部 JSON 字节（工件内为密文）"""
        return json.dumps(
            {
                "format": HEADER_FORMAT,
                "file_id": self.file_id,
                "file_name": self.file_name,
                "mime_type": self.mime_type,
                "total_size": self.total_size,
                "chunk_size": self.chunk_size,
                "total_chunks": self.total_chunks,
                "created_at": self.created_at,
            },
            ensure_ascii=False,
        ).encode("utf-8")

    @classmethod
    def from_json_bytes(cls, raw: bytes) -> ArtifactHeader:
        """从 JSON 字节解析头部并校验字段合法性"""
        try:
            data: dict[str, Any] = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ArtifactCorruptedError(message="头部 JSON 解析失败") from error
        if data.get("format") != HEADER_FORMAT:
            raise ArtifactCorruptedError(message=f"不支持的工件格式版本: {data.get('format')}")
        header = cls(
            file_id=str(data.get("file_id", "")),
            file_name=str(data.get("file_name", "")),
            mime_type=str(data.get("mime_type", "application/octet-stream")),
            total_size=int(data.get("total_size", 0)),
            chunk_size=int(data.get("chunk_size", 0)),
            total_chunks=int(data.get("total_chunks", 0)),
            created_at=str(data.get("created_at", "")),
        )
        _validate_header(header)
        return header

    @property
    def file_id_bytes(self) -> bytes:
        """file_id 原始字节（16 字节，用作 HKDF 盐与 AAD 绑定）"""
        return bytes.fromhex(self.file_id)

    def expected_chunk_length(self, index: int) -> int:
        """按头部推算第 index 块的明文长度（解包端据此读帧）"""
        if self.total_size == 0:
            return 0
        full_chunks, last_size = divmod(self.total_size, self.chunk_size)
        if index < full_chunks:
            return self.chunk_size
        return last_size


def _validate_header(header: ArtifactHeader) -> None:
    """头部字段合法性校验（防伪造头部撑爆解包端）"""
    try:
        file_id_bytes = header.file_id_bytes
    except ValueError as error:
        raise ArtifactCorruptedError(message="file_id 非十六进制") from error
    if len(file_id_bytes) != FILE_ID_LENGTH:
        raise ArtifactCorruptedError(message=f"file_id 长度非法: {len(header.file_id) // 2} 字节")
    if header.total_size < 0:
        raise ArtifactCorruptedError(message=f"total_size 非法: {header.total_size}")
    if not 0 <= header.total_chunks <= MAX_TOTAL_CHUNKS:
        raise ArtifactCorruptedError(
            message=f"分块数超限: {header.total_chunks}（上限 {MAX_TOTAL_CHUNKS}）"
        )
    validate_chunk_size(header.chunk_size)
    expected_chunks = (
        0
        if header.total_size == 0
        else (header.total_size + header.chunk_size - 1) // header.chunk_size
    )
    if header.total_chunks != expected_chunks:
        raise ArtifactCorruptedError(
            message=f"total_chunks 与 total_size 不符: {header.total_chunks} != {expected_chunks}"
        )


def new_file_id() -> bytes:
    """生成新文件标识（16 字节随机）"""
    return os.urandom(FILE_ID_LENGTH)


def derive_header_key(master_key: bytes) -> bytes:
    """派生头部加密密钥"""
    return hkdf(master_key, _KDF_SALT, b"header", 32)


def derive_chunk_key(master_key: bytes, file_id: bytes, index: int) -> bytes:
    """派生第 index 块的独立加密密钥"""
    return hkdf(master_key, file_id, b"chunk:%d" % index, 32)


def header_aad() -> bytes:
    """头部 AAD：绑定 MAGIC 进认证（魔数被改即头部认证失败）"""
    return MAGIC


def chunk_aad(file_id: bytes, index: int, prev_tag: bytes) -> bytes:
    """块 AAD：MAGIC + file_id + 块序 + 前一帧标签 —— AEAD tag 链的核心"""
    return MAGIC + file_id + struct.pack(">I", index) + prev_tag


def read_exact(reader, length: int, what: str) -> bytes:
    """从二进制读流中精确读取 length 字节，不足即工件截断"""
    data = reader.read(length)
    if data is None or len(data) < length:
        raise ArtifactCorruptedError(
            message=f"工件截断：{what} 需要 {length} 字节，实际 {len(data or b'')}"
        )
    return bytes(data)


def write_frame(writer, nonce: bytes, ciphertext: bytes, tag: bytes) -> None:
    """写一帧：nonce(12) | 密文 | tag(16)"""
    writer.write(nonce)
    writer.write(ciphertext)
    writer.write(tag)


def read_frame(reader, plaintext_length: int) -> tuple[bytes, bytes, bytes]:
    """读一帧，返回 (nonce, ciphertext, tag)"""
    nonce = read_exact(reader, NONCE_LENGTH, "chunk_nonce")
    ciphertext = read_exact(reader, plaintext_length, "chunk_ciphertext")
    tag = read_exact(reader, TAG_LENGTH, "chunk_tag")
    return nonce, ciphertext, tag


def write_prefix(writer, header_length: int) -> None:
    """写工件前缀：MAGIC + header_len"""
    writer.write(MAGIC)
    writer.write(struct.pack(">I", header_length))


def read_prefix(reader) -> int:
    """读工件前缀，返回 header_len"""
    magic = read_exact(reader, MAGIC_LENGTH, "magic")
    if magic != MAGIC:
        raise ArtifactCorruptedError(message=f"魔数不符: {magic!r}")
    raw_len = read_exact(reader, 4, "header_len")
    header_length = int(struct.unpack(">I", raw_len)[0])
    if header_length > MAX_HEADER_LENGTH:
        raise ArtifactCorruptedError(
            message=f"头部超长: {header_length}（上限 {MAX_HEADER_LENGTH}）"
        )
    return header_length


def frame_overhead() -> int:
    """每帧固定开销字节数（nonce + tag）"""
    return _FRAME_OVERHEAD


def prefix_length() -> int:
    """工件前缀固定长度（magic + header_len）"""
    return _PREFIX_LENGTH
