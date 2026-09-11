"""加密文件打包 — 流式分块加密为自包含工件（.sipft）

内存策略：逐块读取-加密-写出，峰值内存与文件大小无关
（约 chunk_size 的常数倍）。master_key 可为随机会话密钥，
也可直接复用 EncryptedChannel 握手派生的 encryption_key。
"""

from __future__ import annotations

import datetime
import mimetypes
import os
from dataclasses import dataclass

from sip_protocol.crypto.xchacha20_poly1305 import (
    encrypt_xchacha20_poly1305,
    generate_nonce,
)
from sip_protocol.exceptions import FileTooLargeError, FileTransferError
from sip_protocol.filetransfer.format import (
    ArtifactHeader,
    DEFAULT_CHUNK_SIZE,
    MAX_FILE_SIZE,
    chunk_aad,
    derive_chunk_key,
    derive_header_key,
    header_aad,
    new_file_id,
    validate_chunk_size,
    write_frame,
    write_prefix,
)

# 工件默认扩展名
ARTIFACT_SUFFIX = ".sipft"
# 打包中途的临时后缀（完成后原子替换，失败即清理）
_TMP_SUFFIX = ".sipft-packing"


@dataclass
class PackResult:
    """打包结果"""

    file_name: str
    file_id: str
    total_size: int
    chunk_size: int
    total_chunks: int
    artifact_path: str
    artifact_size: int

    def to_dict(self) -> dict:
        """序列化为字典（dsh tool / 日志用）"""
        return {
            "file_name": self.file_name,
            "file_id": self.file_id,
            "total_size": self.total_size,
            "chunk_size": self.chunk_size,
            "total_chunks": self.total_chunks,
            "artifact_path": self.artifact_path,
            "artifact_size": self.artifact_size,
        }


def pack_file(
    input_path: str,
    master_key: bytes,
    output_path: str | None = None,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> PackResult:
    """把文件流式加密打包为自包含工件

    工件布局与密钥调度见 format.py 模块注释。
    每块独立密钥（HKDF 派生）+ AEAD tag 链（前一帧标签进本块 AAD），
    乱序/拼接/截断/篡改在解包端逐块拒绝。

    Args:
        input_path: 源文件路径
        master_key: 32 字节主密钥（HKDF 输入，建议与通道会话密钥同级保密）
        output_path: 工件输出路径（默认源文件名 + .sipft）
        chunk_size: 分块大小（默认 1MB，1KB..16MB）

    Returns:
        PackResult: 打包结果元数据

    Raises:
        FileNotFoundError: 源文件不存在
        FileTooLargeError: 文件超过 MAX_FILE_SIZE（5GB）
        FileTransferError: 源文件在打包期间被改动或 I/O 失败
    """
    validate_chunk_size(chunk_size)
    if not os.path.isfile(input_path):
        raise FileNotFoundError(f"源文件不存在: {input_path}")

    total_size = os.path.getsize(input_path)
    if total_size > MAX_FILE_SIZE:
        raise FileTooLargeError(file_size=total_size, max_size=MAX_FILE_SIZE)

    file_name = os.path.basename(input_path)
    file_id = new_file_id()
    total_chunks = 0 if total_size == 0 else (total_size + chunk_size - 1) // chunk_size

    header = ArtifactHeader(
        file_id=file_id.hex(),
        file_name=file_name,
        mime_type=mimetypes.guess_type(file_name)[0] or "application/octet-stream",
        total_size=total_size,
        chunk_size=chunk_size,
        total_chunks=total_chunks,
        created_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
    )

    artifact_path = output_path or (input_path + ARTIFACT_SUFFIX)
    tmp_path = artifact_path + _TMP_SUFFIX

    written_chunks = _write_artifact(tmp_path, input_path, master_key, header)
    if written_chunks != total_chunks:
        os.unlink(tmp_path)
        raise FileTransferError(
            message=f"源文件在打包期间被改动: 期望 {total_chunks} 块，实际 {written_chunks} 块"
        )

    os.replace(tmp_path, artifact_path)
    return PackResult(
        file_name=file_name,
        file_id=header.file_id,
        total_size=total_size,
        chunk_size=chunk_size,
        total_chunks=total_chunks,
        artifact_path=artifact_path,
        artifact_size=os.path.getsize(artifact_path),
    )


def _write_artifact(
    tmp_path: str, input_path: str, master_key: bytes, header: ArtifactHeader
) -> int:
    """写工件主体：认证头部 + 全部块帧，返回实际写入块数"""
    header_key = derive_header_key(master_key)
    header_nonce = generate_nonce()
    header_ct, header_tag = encrypt_xchacha20_poly1305(
        header_key, header.to_json_bytes(), header_nonce, header_aad()
    )

    written = 0
    try:
        with open(input_path, "rb") as src, open(tmp_path, "wb") as dst:
            write_prefix(dst, len(header_ct))
            write_frame(dst, header_nonce, header_ct, header_tag)

            prev_tag = header_tag
            while True:
                plaintext = src.read(header.chunk_size)
                if not plaintext:
                    break
                chunk_key = derive_chunk_key(master_key, header.file_id_bytes, written)
                nonce = generate_nonce()
                ciphertext, tag = encrypt_xchacha20_poly1305(
                    chunk_key, plaintext, nonce, chunk_aad(header.file_id_bytes, written, prev_tag)
                )
                write_frame(dst, nonce, ciphertext, tag)
                # tag 链推进：下一块的 AAD 绑定本块标签
                prev_tag = tag
                written += 1
    except OSError as error:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
        raise FileTransferError(message=f"打包 I/O 失败: {error}") from error
    return written
