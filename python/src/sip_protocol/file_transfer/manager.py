"""文件传输管理器 — 文件分块发送与接收的核心协调器"""

from __future__ import annotations

import base64
import hashlib
import mimetypes
import os
from dataclasses import dataclass
from enum import Enum
from typing import Union

from sip_protocol.file_transfer.config import FileTransferConfig
from sip_protocol.file_transfer.manifest import FileChunk, FileManifest
from sip_protocol.file_transfer.store import FileStore, LocalFileStore
from sip_protocol.schema.parts import FileDataPart, FileRefPart

# ==================== 传输状态枚举 ====================


class TransferStatus(str, Enum):
    """文件传输状态机"""

    PENDING = "pending"
    SENDING = "sending"
    RECEIVING = "receiving"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELED = "canceled"


# ==================== 传输进度 ====================


@dataclass
class TransferProgress:
    """文件传输进度追踪"""

    file_id: str = ""
    file_name: str = ""
    status: TransferStatus = TransferStatus.PENDING
    transferred_chunks: int = 0
    total_chunks: int = 0
    transferred_bytes: int = 0
    total_bytes: int = 0

    @property
    def is_complete(self) -> bool:
        """传输是否已完成"""
        return self.status == TransferStatus.COMPLETED

    @property
    def progress_ratio(self) -> float:
        """归一化进度 0..1"""
        if self.total_bytes == 0:
            return 0.0
        return min(self.transferred_bytes / self.total_bytes, 1.0)


# ==================== 文件传输管理器 ====================


class FileTransferManager:
    """文件传输管理器

    协调文件的分块发送与接收：小文件内联传输（FileDataPart），
    大文件分块存储后返回引用（FileRefPart）。
    """

    def __init__(
        self,
        config: FileTransferConfig | None = None,
        store: FileStore | None = None,
    ) -> None:
        self._config = config or FileTransferConfig()
        self._store = store or LocalFileStore()
        # file_id -> TransferProgress 进度记录
        self._progress: dict[str, TransferProgress] = {}

    @property
    def _store(self) -> FileStore | LocalFileStore:
        return self.__store

    @_store.setter
    def _store(self, value: FileStore | None) -> None:
        self.__store = value or LocalFileStore()

    # ==================== 公开接口 ====================

    def send_file(self, file_path: str) -> FileRefPart | FileDataPart:
        """发送文件：小文件内联，大文件分块存储

        Args:
            file_path: 文件路径

        Returns:
            FileDataPart（小文件内联）或 FileRefPart（大文件引用）

        Raises:
            FileNotFoundError: 文件不存在
            FileTooLargeError: 文件超过 max_file_size
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"文件不存在: {file_path}")

        file_size = os.path.getsize(file_path)
        self._config.validate_size(file_size)

        if self._config.should_inline(file_size):
            return self._send_inline(file_path)
        return self._send_chunked(file_path)

    def receive_file(
        self,
        part: Union[FileRefPart, FileDataPart],
        output_path: str,
    ) -> None:
        """接收文件并写入指定路径

        Args:
            part: FileDataPart（内联）或 FileRefPart（分块引用）
            output_path: 输出文件路径

        Raises:
            ChunkIntegrityError: 分块哈希校验失败
        """
        if isinstance(part, FileDataPart):
            self._receive_inline(part, output_path)
        else:
            self._receive_chunked(part, output_path)

    def get_manifest(self, ref: FileRefPart) -> FileManifest:
        """从 FileRefPart 获取文件清单"""
        return self._store.retrieve_manifest(ref.url)

    def get_progress(self, file_id: str) -> TransferProgress | None:
        """获取传输进度"""
        return self._progress.get(file_id)

    # ==================== 内联传输 ====================

    def _send_inline(self, file_path: str) -> FileDataPart:
        """小文件内联：base64 编码后直接放入 FileDataPart"""
        file_name = os.path.basename(file_path)
        mime_type = mimetypes.guess_type(file_name)[0] or "application/octet-stream"

        with open(file_path, "rb") as f:
            raw = f.read()

        encoded = base64.b64encode(raw).decode("ascii")
        return FileDataPart(data=encoded, name=file_name, mime_type=mime_type)

    def _receive_inline(self, part: FileDataPart, output_path: str) -> None:
        """接收内联文件：base64 解码后写入"""
        safe_path = self._safe_output_path(output_path)
        os.makedirs(os.path.dirname(safe_path) or ".", exist_ok=True)
        with open(safe_path, "wb") as f:
            f.write(base64.b64decode(part.data))

    # ==================== 分块传输 ====================

    def _send_chunked(self, file_path: str) -> FileRefPart:
        """大文件分块：读取 → 分块 → 存储 manifest + chunks"""
        file_name = os.path.basename(file_path)
        mime_type = mimetypes.guess_type(file_name)[0] or "application/octet-stream"

        with open(file_path, "rb") as f:
            data = f.read()

        # 整体哈希
        content_hash = hashlib.sha256(data).hexdigest()

        # 分块
        chunk_bytes_list = self._chunk_iter(data, self._config.chunk_size)
        chunks: list[FileChunk] = []
        for idx, chunk_data in enumerate(chunk_bytes_list):
            chunk_hash = hashlib.sha256(chunk_data).hexdigest()
            chunks.append(FileChunk(index=idx, size=len(chunk_data), hash=chunk_hash))

        # 构造 manifest 获取 id，然后存储 chunks 和 manifest
        manifest = FileManifest(
            file_name=file_name,
            mime_type=mime_type,
            total_size=len(data),
            chunk_size=self._config.chunk_size,
            content_hash=content_hash,
            chunks=chunks,
        )

        for idx, chunk_data in enumerate(chunk_bytes_list):
            self._store.store_chunk(manifest.id, idx, chunk_data)

        # 存储 manifest
        manifest_url = self._store.store_manifest(manifest)

        # 记录进度
        progress = TransferProgress(
            file_id=manifest.id,
            file_name=file_name,
            status=TransferStatus.COMPLETED,
            transferred_chunks=len(chunks),
            total_chunks=len(chunks),
            transferred_bytes=len(data),
            total_bytes=len(data),
        )
        self._progress[manifest.id] = progress

        return FileRefPart(
            url=manifest_url,
            hash=content_hash,
            name=file_name,
            size=len(data),
            mime_type=mime_type,
        )

    def _receive_chunked(self, ref: FileRefPart, output_path: str) -> None:
        """接收分块文件：检索 manifest → 下载块 → 校验 → 重组 → 写入"""
        manifest = self._store.retrieve_manifest(ref.url)
        file_id = manifest.id

        # 初始化进度
        progress = TransferProgress(
            file_id=file_id,
            file_name=manifest.file_name,
            status=TransferStatus.RECEIVING,
            transferred_chunks=0,
            total_chunks=manifest.total_chunks,
            transferred_bytes=0,
            total_bytes=manifest.total_size,
        )
        self._progress[file_id] = progress

        # 逐块下载并校验
        assembled = bytearray()
        for chunk_desc in manifest.chunks:
            # pylint: disable=import-outside-toplevel
            from sip_protocol.exceptions import ChunkIntegrityError

            chunk_data = self._store.retrieve_chunk(file_id, chunk_desc.index)
            actual_hash = hashlib.sha256(chunk_data).hexdigest()
            if actual_hash != chunk_desc.hash:
                progress.status = TransferStatus.FAILED
                raise ChunkIntegrityError(chunk_index=chunk_desc.index)

            assembled.extend(chunk_data)
            progress.transferred_chunks += 1
            progress.transferred_bytes += len(chunk_data)

        # 整体哈希校验
        assembled_bytes = bytes(assembled)
        if hashlib.sha256(assembled_bytes).hexdigest() != manifest.content_hash:
            progress.status = TransferStatus.FAILED
            raise ChunkIntegrityError(chunk_index=-1)

        # 写入文件
        safe_path = self._safe_output_path(output_path)
        os.makedirs(os.path.dirname(safe_path) or ".", exist_ok=True)
        with open(safe_path, "wb") as f:
            f.write(assembled_bytes)

        progress.status = TransferStatus.COMPLETED

    # ==================== 工具方法 ====================

    @staticmethod
    def _safe_output_path(output_path: str, file_name: str | None = None) -> str:
        """路径遍历防护 + 文件名冲突处理

        1. 用 os.path.realpath 消除路径遍历
        2. 文件名冲突时追加 (2), (3), ... 计数器

        Args:
            output_path: 目标目录或完整文件路径
            file_name: 可选的文件名。若提供则拼接到 output_path 后面，
                       否则 output_path 视为完整路径。
        """
        if file_name is not None:
            # 路径遍历防护：只取文件名的 basename 部分
            safe_name = os.path.basename(file_name)
            target_dir = os.path.realpath(output_path)
            target = os.path.join(target_dir, safe_name)
        else:
            # output_path 是完整路径，realpath 消除遍历
            target = os.path.realpath(output_path)

        # 文件名冲突处理
        if os.path.exists(target):
            base, ext = os.path.splitext(target)
            counter = 2
            while True:
                candidate = f"{base} ({counter}){ext}"
                if not os.path.exists(candidate):
                    target = candidate
                    break
                counter += 1

        return target

    @staticmethod
    def _chunk_iter(data: bytes, chunk_size: int) -> list[bytes]:
        """按 chunk_size 切分字节序列"""
        if not data:
            return []
        return [data[i : i + chunk_size] for i in range(0, len(data), chunk_size)]
