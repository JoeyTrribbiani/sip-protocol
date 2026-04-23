"""文件存储 — 本地文件系统存储实现"""

from __future__ import annotations

import json
import os
import time
from typing import Protocol, runtime_checkable

from sip_protocol.file_transfer.manifest import FileManifest

# ==================== 文件存储协议 ====================


@runtime_checkable
class FileStore(Protocol):
    """文件存储接口"""

    def store_manifest(self, manifest: FileManifest) -> str: ...
    def retrieve_manifest(self, url: str) -> FileManifest: ...
    def store_chunk(self, file_id: str, index: int, data: bytes) -> str: ...
    def retrieve_chunk(self, file_id: str, index: int) -> bytes: ...
    def delete(self, file_id: str) -> None: ...
    def cleanup_expired(self) -> int: ...


# ==================== 本地文件系统实现 ====================


class LocalFileStore:
    """本地文件系统存储

    目录结构:
        <base_path>/
            files/
                <file_id>/
                    manifest.json
                    chunk_0
                    chunk_1
                    ...
    """

    def __init__(self, base_path: str = ".sip_files") -> None:
        self.base_path = base_path
        self._files_dir = os.path.join(base_path, "files")
        os.makedirs(self._files_dir, exist_ok=True)

    def _file_dir(self, file_id: str) -> str:
        return os.path.join(self._files_dir, file_id)

    def _manifest_path(self, file_id: str) -> str:
        return os.path.join(self._file_dir(file_id), "manifest.json")

    def _chunk_path(self, file_id: str, index: int) -> str:
        return os.path.join(self._file_dir(file_id), f"chunk_{index}")

    # ---- 接口实现 ----

    def store_manifest(self, manifest: FileManifest) -> str:
        """存储文件清单，返回清单路径"""
        fdir = self._file_dir(manifest.id)
        os.makedirs(fdir, exist_ok=True)
        path = self._manifest_path(manifest.id)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(manifest.to_dict(), f, ensure_ascii=False, indent=2)
        return path

    def retrieve_manifest(self, url: str) -> FileManifest:
        """从路径读取文件清单"""
        if not os.path.exists(url):
            raise FileNotFoundError(f"文件清单不存在: {url}")
        with open(url, encoding="utf-8") as f:
            return FileManifest.from_dict(json.load(f))

    def store_chunk(self, file_id: str, index: int, data: bytes) -> str:
        """存储块，返回块路径"""
        fdir = self._file_dir(file_id)
        os.makedirs(fdir, exist_ok=True)
        path = self._chunk_path(file_id, index)
        with open(path, "wb") as f:
            f.write(data)
        return path

    def retrieve_chunk(self, file_id: str, index: int) -> bytes:
        """读取存储的块"""
        path = self._chunk_path(file_id, index)
        if not os.path.exists(path):
            raise FileNotFoundError(f"文件块不存在: {path}")
        with open(path, "rb") as f:
            return f.read()

    def delete(self, file_id: str) -> None:
        """删除文件及所有块"""
        import shutil

        fdir = self._file_dir(file_id)
        if os.path.exists(fdir):
            shutil.rmtree(fdir)

    def cleanup_expired(self) -> int:
        """清理过期文件，返回删除数量"""
        import datetime

        now = time.time()
        cleaned = 0
        if not os.path.exists(self._files_dir):
            return 0
        for file_id in os.listdir(self._files_dir):
            manifest_path = self._manifest_path(file_id)
            if not os.path.exists(manifest_path):
                continue
            try:
                with open(manifest_path, encoding="utf-8") as f:
                    data = json.load(f)
                expires_at = data.get("expires_at", "")
                if not expires_at:
                    continue
                dt = datetime.datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
                if dt.timestamp() < now:
                    self.delete(file_id)
                    cleaned += 1
            except (json.JSONDecodeError, ValueError, KeyError):
                continue
        return cleaned
