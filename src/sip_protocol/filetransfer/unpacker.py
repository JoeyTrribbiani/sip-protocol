"""加密文件解包 — 流式校验解密自包含工件（.sipft）

逐帧解密认证（fail-fast：第一处篡改即在对应块抛 ChunkIntegrityError），
不将整个文件读入内存。输出路径经 basename 清洗 + realpath 消解，
头部文件名不可携带路径穿越（且头部本身是认证过的，无法篡改）。
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import BinaryIO

from cryptography.exceptions import InvalidTag

from sip_protocol.crypto.xchacha20_poly1305 import NONCE_LENGTH, decrypt_xchacha20_poly1305
from sip_protocol.exceptions import ArtifactCorruptedError, ChunkIntegrityError
from sip_protocol.filetransfer.format import (
    TAG_LENGTH,
    ArtifactHeader,
    chunk_aad,
    derive_chunk_key,
    derive_header_key,
    header_aad,
    read_exact,
    read_frame,
    read_prefix,
)

# 解包中途的临时后缀（全部块校验通过后才落成正式文件）
_TMP_SUFFIX = ".sipft-unpacking"


@dataclass
class UnpackResult:
    """解包结果"""

    file_name: str
    total_size: int
    chunks_verified: int
    output_path: str

    def to_dict(self) -> dict:
        """序列化为字典（dsh tool / 日志用）"""
        return {
            "file_name": self.file_name,
            "total_size": self.total_size,
            "chunks_verified": self.chunks_verified,
            "output_path": self.output_path,
        }


def unpack_file(
    artifact_path: str,
    master_key: bytes,
    output_path: str | None = None,
) -> UnpackResult:
    """校验并解密自包含工件，写出原文件

    Args:
        artifact_path: 工件路径（pack_file 产物）
        master_key: 打包时使用的 32 字节主密钥
        output_path: 输出文件或目录路径（默认：工件同目录 + 头部文件名；
                     同名冲突时自动追加 " (2)"、"(3)"…；路径穿越被清洗）

    Returns:
        UnpackResult: 解包结果元数据

    Raises:
        FileNotFoundError: 工件不存在
        ArtifactCorruptedError: 魔数/头部/长度非法，或头部认证失败（密钥错误同此表现）
        ChunkIntegrityError: 任一块认证失败（篡改/乱序/跨工件拼接）
    """
    if not os.path.isfile(artifact_path):
        raise FileNotFoundError(f"工件不存在: {artifact_path}")

    tmp_path = ""
    try:
        with open(artifact_path, "rb") as src:
            header, prev_tag = _read_header(src, master_key)
            target = _resolve_output_path(artifact_path, output_path, header.file_name)
            os.makedirs(os.path.dirname(target) or ".", exist_ok=True)
            tmp_path = target + _TMP_SUFFIX
            with open(tmp_path, "wb") as dst:
                verified = _verify_chunks(src, dst, master_key, header, prev_tag)
                _ensure_eof(src)
        os.replace(tmp_path, target)
    except Exception:
        # 中途失败（含校验失败）不残留半成品文件
        if tmp_path and os.path.exists(tmp_path):
            os.unlink(tmp_path)
        raise

    return UnpackResult(
        file_name=header.file_name,
        total_size=header.total_size,
        chunks_verified=verified,
        output_path=target,
    )


def _read_header(src: BinaryIO, master_key: bytes) -> tuple[ArtifactHeader, bytes]:
    """读取并认证头部，返回 (头部, header_tag —— tag 链首)"""
    header_length = read_prefix(src)
    header_nonce = read_exact(src, NONCE_LENGTH, "header_nonce")
    header_ct = read_exact(src, header_length, "header_ciphertext")
    header_tag = read_exact(src, TAG_LENGTH, "header_tag")
    try:
        header_plain = decrypt_xchacha20_poly1305(
            derive_header_key(master_key), header_ct, header_nonce, header_tag, header_aad()
        )
    except InvalidTag as error:
        raise ArtifactCorruptedError(message="头部认证失败：密钥错误或工件被篡改") from error
    return ArtifactHeader.from_json_bytes(header_plain), header_tag


def _verify_chunks(
    src: BinaryIO,
    dst: BinaryIO,
    master_key: bytes,
    header: ArtifactHeader,
    prev_tag: bytes,
) -> int:
    """逐帧解密认证并写出，返回校验通过的块数"""
    verified = 0
    written_total = 0
    for index in range(header.total_chunks):
        expected_len = header.expected_chunk_length(index)
        nonce, ciphertext, tag = read_frame(src, expected_len)
        try:
            plaintext = decrypt_xchacha20_poly1305(
                derive_chunk_key(master_key, header.file_id_bytes, index),
                ciphertext,
                nonce,
                tag,
                chunk_aad(header.file_id_bytes, index, prev_tag),
            )
        except InvalidTag as error:
            raise ChunkIntegrityError(chunk_index=index) from error
        dst.write(plaintext)
        prev_tag = tag
        written_total += len(plaintext)
        verified += 1

    if written_total != header.total_size:
        raise ArtifactCorruptedError(
            message=f"解出字节数与头部不符: {written_total} != {header.total_size}"
        )
    return verified


def _ensure_eof(src: BinaryIO) -> None:
    """工件必须精确终止：任何尾部多余字节都视为损坏（防拼接）"""
    if src.read(1):
        raise ArtifactCorruptedError(message="工件尾部有多余数据（疑似拼接）")


def _resolve_output_path(artifact_path: str, output_path: str | None, file_name: str) -> str:
    """解析输出路径：清洗头部文件名的路径穿越 + 同名冲突追加序号

    output_path 为目录时拼入头部文件名（basename 清洗）；
    为文件路径时直接使用（realpath 消解遍历）；未提供时落到工件所在目录。
    """
    if output_path is None:
        target = os.path.join(
            os.path.dirname(os.path.abspath(artifact_path)), _safe_file_name(file_name)
        )
    elif os.path.isdir(output_path):
        target = os.path.join(output_path, _safe_file_name(file_name))
    else:
        target = os.path.realpath(output_path)

    if os.path.exists(target):
        root, ext = os.path.splitext(target)
        counter = 2
        while os.path.exists(f"{root} ({counter}){ext}"):
            counter += 1
        target = f"{root} ({counter}){ext}"
    return target


def _safe_file_name(name: str) -> str:
    """清洗文件名：只保留 basename，空名回退为 unpacked_file"""
    safe = os.path.basename(name.replace("\\", "/")).strip()
    return safe or "unpacked_file"
