# F1 文件传输 实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 实现基于分块的文件传输模块，小文件内联（FileDataPart），大文件分块引用（FileRefPart + FileManifest）。

**Architecture:** FileTransferManager 协调分块/存储/重组。LocalFileStore 提供本地文件系统存储。文件传输产出 Part（FileRefPart 或 FileDataPart），由调用方包装进 SIPMessage。SIP 加密层负责传输加密，文件传输模块不自行加密。

**Tech Stack:** Python 3.11+, stdlib dataclasses, hashlib, pathlib, shutil, tempfile（测试用）

**设计文档:** `docs/superpowers/specs/2026-04-22-file-transfer-design.md`

**已存在:** FileRefPart / FileDataPart（schema/parts.py）、MessageType.FILE_TRANSFER_PROGRESS（schema/types.py）

**关键约束:**
- 纯同步 API，无 async/await
- 纯 stdlib dataclasses + enum，无 pydantic
- Pylint max-args=7
- 注释/文档中文，标识符英文
- 异常继承链用 kwargs.setdefault()

**设计参考（LocalSend, /Users/joey0x1/Workspace/localsend）:**

LocalSend 是开源跨平台局域网文件传输应用（Dart/Flutter/Rust）。以下设计模式被借鉴：

1. **会话状态机** — LocalSend 的 `SessionStatus`（waiting → sending → finished/canceled）和 `FileStatus`（queue → sending → finished/failed/skipped）枚举。SIP 的 `TransferStatus` 枚举借鉴此模式。
2. **文件名冲突自动重命名** — LocalSend 的 `file.txt` → `file (2).txt` 计数器追加策略。SIP 的 `receive_file` 实现相同逻辑。
3. **路径遍历防护** — LocalSend 在 `file_saver.dart` 中校验目标路径是否在父目录内。SIP 的 `receive_file` 必须做相同校验。
4. **两步式协商** — LocalSend 的 `prepare-upload`（元数据）→ `upload`（数据）模式。SIP 的 manifest + chunks 设计与之呼应。
5. **进度归一化** — LocalSend 使用 0..1 归一化进度。SIP 的 `TransferProgress` 采用相同方式。

**不借鉴的部分（不适用）:**
- LocalSend 不做文件分块（流式直传），SIP 需要分块以支持存储转发和完整性校验
- LocalSend 是 Dart/Flutter/Rust，SIP 是纯 Python，只能借鉴设计模式不能复用代码
- LocalSend 仅支持局域网直连，SIP 是协议层不限定传输方式

**相对于设计文档的简化（YAGNI）:**
- v1 只实现 LocalFileStore，不做 FileTransport 抽象
- 不做并行下载，单线程顺序
- 不做速度追踪，只追踪块数/字节数
- 不做进度消息（由调用方在 SIPMessage 层自行处理）
- 不做 chunk 级加密（加密由 SIP 信封层负责）

---

## 文件结构

```
python/src/sip_protocol/
├── file_transfer/
│   ├── __init__.py      # 公开 API 导出
│   ├── config.py        # FileTransferConfig 数据类
│   ├── manifest.py      # FileChunk + FileManifest 数据类
│   ├── store.py         # FileStore 协议 + LocalFileStore
│   └── manager.py       # FileTransferManager 主协调器
```

---

### Task 1: FileTransferConfig + 文件传输异常

**Files:**
- Create: `src/sip_protocol/file_transfer/__init__.py`（空文件占位）
- Create: `src/sip_protocol/file_transfer/config.py`
- Modify: `src/sip_protocol/exceptions.py`（追加 3 个异常类）
- Create: `tests/test_file_transfer_config.py`

- [ ] **Step 1: 创建 file_transfer 包和 FileTransferConfig**

```python
# src/sip_protocol/file_transfer/__init__.py
"""SIP 文件传输模块 — 分块存储与引用传输"""
```

```python
# src/sip_protocol/file_transfer/config.py
"""文件传输配置"""

from __future__ import annotations


class FileTransferConfig:
    """文件传输配置（所有参数可按场景调整）

    使用 __slots__ 避免意外属性赋值。
    """

    __slots__ = (
        "inline_threshold",
        "chunk_size",
        "max_file_size",
        "max_chunks",
        "default_ttl",
    )

    def __init__(
        self,
        inline_threshold: int = 4096,
        chunk_size: int = 1048576,
        max_file_size: int = 5368709120,
        max_chunks: int = 5120,
        default_ttl: int = 86400,
    ) -> None:
        self.inline_threshold = inline_threshold
        self.chunk_size = chunk_size
        self.max_file_size = max_file_size
        self.max_chunks = max_chunks
        self.default_ttl = default_ttl

    def should_inline(self, file_size: int) -> bool:
        """判断文件是否应内联（base64 编码放入 FileDataPart）"""
        return file_size <= self.inline_threshold

    def validate_size(self, file_size: int) -> None:
        """校验文件大小，不合法则抛出 FileTooLargeError"""
        if file_size > self.max_file_size:
            raise FileTooLargeError(
                file_size=file_size,
                max_size=self.max_file_size,
            )
```

- [ ] **Step 2: 在 exceptions.py 追加文件传输异常**

在文件末尾（群组异常之后）追加：

```python
# ==================== 文件传输异常 ====================


@_register_error
@dataclass
class FileTransferError(SIPError):
    """文件传输基础异常"""

    def __init__(self, message: str = "文件传输错误", **kwargs: Any) -> None:
        kwargs.setdefault("code", "SIP-FILE-000")
        super().__init__(message=message, **kwargs)


@_register_error
@dataclass
class ChunkIntegrityError(FileTransferError):
    """文件块完整性校验失败"""

    def __init__(self, chunk_index: int = 0, **kwargs: Any) -> None:
        msg = f"块 {chunk_index} 完整性校验失败" if chunk_index >= 0 else "完整性校验失败"
        kwargs.setdefault("code", "SIP-FILE-001")
        kwargs.setdefault("recoverable", False)
        kwargs.setdefault("message", msg)
        super().__init__(**kwargs)


@_register_error
@dataclass
class FileTooLargeError(FileTransferError):
    """文件超过大小限制"""

    def __init__(
        self, file_size: int = 0, max_size: int = 0, **kwargs: Any
    ) -> None:
        msg = f"文件过大: {file_size} > {max_size}"
        kwargs.setdefault("code", "SIP-FILE-002")
        kwargs.setdefault("message", msg)
        super().__init__(**kwargs)
```

注意：`__init__` 参数 `chunk_index`、`file_size`、`max_size` 都是新增的自定义参数，不会与 from_dict 的 kwargs 冲突。

- [ ] **Step 3: 写测试**

```python
# tests/test_file_transfer_config.py
"""FileTransferConfig 和文件传输异常测试"""

import pytest

from sip_protocol.exceptions import (
    ChunkIntegrityError,
    FileTooLargeError,
    FileTransferError,
    SIPError,
)
from sip_protocol.file_transfer.config import FileTransferConfig


class TestFileTransferConfig:
    def test_defaults(self):
        cfg = FileTransferConfig()
        assert cfg.inline_threshold == 4096
        assert cfg.chunk_size == 1048576
        assert cfg.max_file_size == 5368709120
        assert cfg.max_chunks == 5120
        assert cfg.default_ttl == 86400

    def test_custom_values(self):
        cfg = FileTransferConfig(inline_threshold=1024, chunk_size=512)
        assert cfg.inline_threshold == 1024
        assert cfg.chunk_size == 512

    def test_should_inline_true(self):
        cfg = FileTransferConfig(inline_threshold=4096)
        assert cfg.should_inline(4000) is True
        assert cfg.should_inline(4096) is True

    def test_should_inline_false(self):
        cfg = FileTransferConfig(inline_threshold=4096)
        assert cfg.should_inline(4097) is False

    def test_validate_size_ok(self):
        cfg = FileTransferConfig(max_file_size=1000)
        cfg.validate_size(999)  # 不抛异常

    def test_validate_size_too_large(self):
        cfg = FileTransferConfig(max_file_size=1000)
        with pytest.raises(FileTooLargeError):
            cfg.validate_size(1001)


class TestFileTransferExceptions:
    def test_file_transfer_error_code(self):
        err = FileTransferError()
        assert err.code == "SIP-FILE-000"

    def test_chunk_integrity_error(self):
        err = ChunkIntegrityError(chunk_index=3)
        assert err.code == "SIP-FILE-001"
        assert "3" in err.message
        assert err.recoverable is False

    def test_file_too_large_error(self):
        err = FileTooLargeError(file_size=9999, max_size=1000)
        assert err.code == "SIP-FILE-002"
        assert "9999" in err.message
        assert "1000" in err.message

    def test_from_dict_roundtrip(self):
        err = FileTooLargeError(file_size=9999, max_size=1000)
        d = err.to_dict()
        recovered = SIPError.from_dict(d)
        assert isinstance(recovered, FileTooLargeError)
        assert recovered.code == "SIP-FILE-002"
```

- [ ] **Step 4: 运行测试确认通过**

```bash
cd python && source .venv/bin/activate
pytest tests/test_file_transfer_config.py -v
```

预期：全部 PASS

- [ ] **Step 5: 提交**

```bash
git add src/sip_protocol/file_transfer/ src/sip_protocol/exceptions.py tests/test_file_transfer_config.py
git commit -m "feat: 新增FileTransferConfig与文件传输异常类"
```

---

### Task 2: FileChunk + FileManifest

**Files:**
- Create: `src/sip_protocol/file_transfer/manifest.py`
- Create: `tests/test_file_transfer_manifest.py`

- [ ] **Step 1: 写测试**

```python
# tests/test_file_transfer_manifest.py
"""FileChunk + FileManifest 测试"""

import time

import pytest

from sip_protocol.file_transfer.manifest import FileChunk, FileManifest


class TestFileChunk:
    def test_defaults(self):
        chunk = FileChunk()
        assert chunk.index == 0
        assert chunk.size == 0
        assert chunk.hash == ""

    def test_to_dict(self):
        chunk = FileChunk(index=2, size=1024, hash="sha256:abc")
        d = chunk.to_dict()
        assert d == {"index": 2, "size": 1024, "hash": "sha256:abc"}

    def test_from_dict(self):
        chunk = FileChunk.from_dict({"index": 2, "size": 1024, "hash": "sha256:abc"})
        assert chunk.index == 2
        assert chunk.size == 1024
        assert chunk.hash == "sha256:abc"

    def test_roundtrip(self):
        original = FileChunk(index=5, size=999, hash="sha256:xyz")
        recovered = FileChunk.from_dict(original.to_dict())
        assert recovered.index == original.index
        assert recovered.size == original.size
        assert recovered.hash == original.hash


class TestFileManifest:
    def _make_manifest(self, **overrides) -> FileManifest:
        defaults = {
            "id": "file-001",
            "file_name": "test.pdf",
            "mime_type": "application/pdf",
            "total_size": 2048,
            "chunk_size": 1024,
            "content_hash": "sha256:abcdef",
            "chunks": [
                FileChunk(index=0, size=1024, hash="sha256:aaa"),
                FileChunk(index=1, size=1024, hash="sha256:bbb"),
            ],
        }
        defaults.update(overrides)
        return FileManifest(**defaults)

    def test_defaults(self):
        m = FileManifest()
        assert m.id == ""
        assert m.file_name == ""
        assert m.total_chunks == 0
        assert m.chunks == []

    def test_total_chunks_computed(self):
        m = self._make_manifest()
        assert m.total_chunks == 2

    def test_to_dict(self):
        m = self._make_manifest()
        d = m.to_dict()
        assert d["id"] == "file-001"
        assert d["file_name"] == "test.pdf"
        assert d["total_size"] == 2048
        assert d["total_chunks"] == 2
        assert d["content_hash"] == "sha256:abcdef"
        assert len(d["chunks"]) == 2
        assert d["chunks"][0]["index"] == 0

    def test_from_dict(self):
        m = self._make_manifest()
        d = m.to_dict()
        recovered = FileManifest.from_dict(d)
        assert recovered.id == "file-001"
        assert recovered.file_name == "test.pdf"
        assert recovered.total_chunks == 2
        assert recovered.chunks[0].hash == "sha256:aaa"

    def test_roundtrip(self):
        original = self._make_manifest()
        recovered = FileManifest.from_dict(original.to_dict())
        assert recovered.id == original.id
        assert recovered.total_size == original.total_size
        assert recovered.content_hash == original.content_hash
        assert len(recovered.chunks) == len(original.chunks)

    def test_created_at_auto(self):
        m = FileManifest(id="auto-test")
        assert m.created_at != ""
        # 应为 ISO 格式
        assert "T" in m.created_at and m.created_at.endswith("Z")

    def test_expires_at_from_ttl(self):
        m = FileManifest(id="ttl-test", default_ttl=3600)
        assert m.expires_at != ""
        assert "T" in m.expires_at

    def test_empty_chunks_total_chunks(self):
        m = FileManifest(id="empty")
        assert m.total_chunks == 0
```

- [ ] **Step 2: 运行测试确认失败**

```bash
pytest tests/test_file_transfer_manifest.py -v
```

预期：FAIL（ModuleNotFoundError）

- [ ] **Step 3: 实现 manifest.py**

```python
# src/sip_protocol/file_transfer/manifest.py
"""文件清单 — 描述分块文件的元数据与块列表"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from sip_protocol.schema._utils import _generate_uuid7, _iso_now


@dataclass
class FileChunk:
    """单个文件块的描述"""

    index: int = 0
    size: int = 0
    hash: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"index": self.index, "size": self.size, "hash": self.hash}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> FileChunk:
        return cls(
            index=data.get("index", 0),
            size=data.get("size", 0),
            hash=data.get("hash", ""),
        )


@dataclass
class FileManifest:
    """文件清单 — 包含完整文件描述和块列表"""

    id: str = field(default_factory=_generate_uuid7)
    file_name: str = ""
    mime_type: str = "application/octet-stream"
    total_size: int = 0
    chunk_size: int = 1048576
    content_hash: str = ""
    chunks: list[FileChunk] = field(default_factory=list)
    created_at: str = field(default_factory=_iso_now)
    expires_at: str = ""
    default_ttl: int = 86400

    @property
    def total_chunks(self) -> int:
        return len(self.chunks)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "id": self.id,
            "file_name": self.file_name,
            "mime_type": self.mime_type,
            "total_size": self.total_size,
            "total_chunks": self.total_chunks,
            "chunk_size": self.chunk_size,
            "content_hash": self.content_hash,
            "chunks": [c.to_dict() for c in self.chunks],
            "created_at": self.created_at,
        }
        if self.expires_at:
            d["expires_at"] = self.expires_at
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> FileManifest:
        chunks = [FileChunk.from_dict(c) for c in data.get("chunks", [])]
        return cls(
            id=data.get("id", ""),
            file_name=data.get("file_name", ""),
            mime_type=data.get("mime_type", "application/octet-stream"),
            total_size=data.get("total_size", 0),
            chunk_size=data.get("chunk_size", 1048576),
            content_hash=data.get("content_hash", ""),
            chunks=chunks,
            created_at=data.get("created_at", ""),
            expires_at=data.get("expires_at", ""),
        )
```

- [ ] **Step 4: 运行测试确认通过**

```bash
pytest tests/test_file_transfer_manifest.py -v
```

预期：全部 PASS

- [ ] **Step 5: 提交**

```bash
git add src/sip_protocol/file_transfer/manifest.py tests/test_file_transfer_manifest.py
git commit -m "feat: 新增FileChunk和FileManifest数据类"
```

---

### Task 3: LocalFileStore

**Files:**
- Create: `src/sip_protocol/file_transfer/store.py`
- Create: `tests/test_file_transfer_store.py`

- [ ] **Step 1: 写测试**

```python
# tests/test_file_transfer_store.py
"""LocalFileStore 测试"""

import json
import hashlib
import os

import pytest

from sip_protocol.file_transfer.manifest import FileChunk, FileManifest
from sip_protocol.file_transfer.store import LocalFileStore


@pytest.fixture
def store(tmp_path):
    return LocalFileStore(base_path=str(tmp_path))


@pytest.fixture
def sample_manifest():
    return FileManifest(
        id="test-file-001",
        file_name="hello.txt",
        total_size=20,
        chunk_size=10,
        content_hash="sha256:test",
        chunks=[
            FileChunk(index=0, size=10, hash="sha256:aaa"),
            FileChunk(index=1, size=10, hash="sha256:bbb"),
        ],
    )


class TestLocalFileStore:
    def test_store_and_retrieve_manifest(self, store, sample_manifest):
        url = store.store_manifest(sample_manifest)
        assert url.endswith("manifest.json")
        recovered = store.retrieve_manifest(url)
        assert recovered.id == "test-file-001"
        assert recovered.total_chunks == 2

    def test_store_and_retrieve_chunk(self, store, sample_manifest):
        chunk_data = b"hello worl"  # 10 bytes
        url = store.store_chunk(sample_manifest.id, 0, chunk_data)
        assert url.endswith("chunk_0")
        retrieved = store.retrieve_chunk(sample_manifest.id, 0)
        assert retrieved == chunk_data

    def test_delete_file(self, store, sample_manifest):
        store.store_manifest(sample_manifest)
        store.store_chunk(sample_manifest.id, 0, b"data")
        store.delete(sample_manifest.id)
        assert not os.path.exists(os.path.join(store.base_path, "files", sample_manifest.id))

    def test_retrieve_nonexistent_manifest_raises(self, store):
        with pytest.raises(FileNotFoundError):
            store.retrieve_manifest("/nonexistent/manifest.json")

    def test_retrieve_nonexistent_chunk_raises(self, store):
        with pytest.raises(FileNotFoundError):
            store.retrieve_chunk("no-such-file", 0)

    def test_cleanup_expired(self, store):
        # 创建过期文件目录（直接创建空目录模拟）
        file_dir = os.path.join(store.base_path, "files", "expired-file")
        os.makedirs(file_dir, exist_ok=True)
        manifest_path = os.path.join(file_dir, "manifest.json")
        with open(manifest_path, "w") as f:
            json.dump({"id": "expired-file", "created_at": "2020-01-01T00:00:00Z"}, f)

        cleaned = store.cleanup_expired()
        assert cleaned >= 1

    def test_multiple_chunks(self, store, sample_manifest):
        for i, chunk in enumerate(sample_manifest.chunks):
            store.store_chunk(sample_manifest.id, i, f"chunk_{i}".encode())
        for i in range(2):
            assert store.retrieve_chunk(sample_manifest.id, i) == f"chunk_{i}".encode()
```

- [ ] **Step 2: 运行测试确认失败**

```bash
pytest tests/test_file_transfer_store.py -v
```

预期：FAIL（ModuleNotFoundError）

- [ ] **Step 3: 实现 store.py**

```python
# src/sip_protocol/file_transfer/store.py
"""文件存储 — 本地文件系统存储实现"""

from __future__ import annotations

import json
import os
import time
from typing import Protocol, runtime_checkable

from sip_protocol.file_transfer.manifest import FileManifest


@runtime_checkable
class FileStore(Protocol):
    """文件存储接口"""

    def store_manifest(self, manifest: FileManifest) -> str: ...
    def retrieve_manifest(self, url: str) -> FileManifest: ...
    def store_chunk(self, file_id: str, index: int, data: bytes) -> str: ...
    def retrieve_chunk(self, file_id: str, index: int) -> bytes: ...
    def delete(self, file_id: str) -> None: ...
    def cleanup_expired(self) -> int: ...


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
        """存储加密块，返回块路径"""
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
        import json

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
                # 解析 ISO 时间
                import datetime

                dt = datetime.datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
                if dt.timestamp() < now:
                    self.delete(file_id)
                    cleaned += 1
            except (json.JSONDecodeError, ValueError, KeyError):
                continue
        return cleaned
```

- [ ] **Step 4: 运行测试确认通过**

```bash
pytest tests/test_file_transfer_store.py -v
```

预期：全部 PASS

- [ ] **Step 5: 提交**

```bash
git add src/sip_protocol/file_transfer/store.py tests/test_file_transfer_store.py
git commit -m "feat: 新增FileStore协议与LocalFileStore实现"
```

---

### Task 4: FileTransferManager

**Files:**
- Create: `src/sip_protocol/file_transfer/manager.py`
- Create: `tests/test_file_transfer_manager.py`

- [ ] **Step 1: 写测试**

```python
# tests/test_file_transfer_manager.py
"""FileTransferManager 测试"""

import base64
import hashlib
import os

import pytest

from sip_protocol.file_transfer.config import FileTransferConfig
from sip_protocol.file_transfer.manager import FileTransferManager
from sip_protocol.file_transfer.store import LocalFileStore
from sip_protocol.schema.parts import FileDataPart, FileRefPart


def _sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


@pytest.fixture
def manager(tmp_path):
    store = LocalFileStore(base_path=str(tmp_path))
    config = FileTransferConfig(inline_threshold=64, chunk_size=32)
    return FileTransferManager(config=config, store=store)


class TestSendFile:
    def test_small_file_returns_file_data_part(self, manager, tmp_path):
        """小文件 → FileDataPart（base64 内联）"""
        path = tmp_path / "small.txt"
        content = b"hello"
        path.write_bytes(content)

        result = manager.send_file(str(path))
        assert isinstance(result, FileDataPart)
        assert result.name == "small.txt"
        # base64 编码后的内容
        decoded = base64.b64decode(result.data)
        assert decoded == content

    def test_large_file_returns_file_ref_part(self, manager, tmp_path):
        """大文件 → FileRefPart + FileManifest 存储"""
        path = tmp_path / "large.bin"
        content = b"x" * 100  # 100 bytes > 64 (inline_threshold)
        path.write_bytes(content)

        result = manager.send_file(str(path))
        assert isinstance(result, FileRefPart)
        assert result.name == "large.bin"
        assert result.size == 100
        assert result.hash.startswith("sha256:")
        assert result.url != ""

    def test_large_file_manifest_stored(self, manager, tmp_path):
        """大文件的 manifest 已存入 store"""
        path = tmp_path / "large.bin"
        content = b"x" * 100
        path.write_bytes(content)

        result = manager.send_file(str(path))
        manifest = manager.get_manifest(result)
        assert manifest.file_name == "large.bin"
        assert manifest.total_size == 100
        assert len(manifest.chunks) > 0

    def test_large_file_chunks_stored(self, manager, tmp_path):
        """大文件的每个块都已存储且可读取"""
        path = tmp_path / "large.bin"
        content = b"x" * 100
        path.write_bytes(content)

        result = manager.send_file(str(path))
        manifest = manager.get_manifest(result)
        for chunk in manifest.chunks:
            data = manager.store.retrieve_chunk(result.url.split("/")[-2], chunk.index)
            assert len(data) > 0

    def test_file_too_large_raises(self, manager, tmp_path):
        path = tmp_path / "huge.bin"
        content = b"x" * 200  # max_file_size=100
        path.write_bytes(content)

        with pytest.raises(Exception):  # FileTooLargeError
            manager.send_file(str(path))

    def test_nonexistent_file_raises(self, manager):
        with pytest.raises(FileNotFoundError):
            manager.send_file("/nonexistent/file.txt")

    def test_mime_type_detection(self, manager, tmp_path):
        path = tmp_path / "doc.pdf"
        path.write_bytes(b"fake pdf")
        result = manager.send_file(str(path))
        assert result.mime_type == "application/pdf"


class TestReceiveFile:
    def _send_and_receive(self, manager, tmp_path):
        """辅助：发送后接收"""
        path = tmp_path / "original.bin"
        content = b"x" * 100
        path.write_bytes(content)
        ref = manager.send_file(str(path))
        output = tmp_path / "output.bin"
        manager.receive_file(ref, str(output))
        return content, output

    def test_receive_reassembles_file(self, manager, tmp_path):
        content, output = self._send_and_receive(manager, tmp_path)
        assert output.read_bytes() == content

    def test_receive_small_file(self, manager, tmp_path):
        """小文件（FileDataPart）接收"""
        path = tmp_path / "tiny.txt"
        content = b"hi"
        path.write_bytes(content)
        part = manager.send_file(str(path))
        assert isinstance(part, FileDataPart)
        output = tmp_path / "tiny_out.txt"
        manager.receive_file(part, str(output))
        assert output.read_bytes() == content

    def test_receive_creates_parent_dirs(self, manager, tmp_path):
        path = tmp_path / "original.bin"
        path.write_bytes(b"x" * 100)
        ref = manager.send_file(str(path))
        output = tmp_path / "sub" / "dir" / "output.bin"
        manager.receive_file(ref, str(output))
        assert output.read_bytes() == b"x" * 100

    def test_receive_chunk_hash_mismatch_raises(self, manager, tmp_path):
        """块 hash 不匹配时应抛出异常"""
        path = tmp_path / "original.bin"
        path.write_bytes(b"x" * 100)
        ref = manager.send_file(str(path))
        # 篡改一个块
        manifest = manager.get_manifest(ref)
        file_id = ref.url.split("/")[-2]
        manager.store.store_chunk(file_id, 0, b"TAMPERED_DATA")

        with pytest.raises(Exception):  # ChunkIntegrityError
            manager.receive_file(ref, str(tmp_path / "bad.bin"))


class TestProgress:
    def test_get_progress_nonexistent(self, manager):
        assert manager.get_progress("no-such-id") is None

    def test_get_progress_after_send(self, manager, tmp_path):
        path = tmp_path / "big.bin"
        path.write_bytes(b"x" * 100)
        ref = manager.send_file(str(path))
        progress = manager.get_progress(ref.url.split("/")[-2])
        assert progress is not None
        assert progress.is_complete is True
```

注意：FileTransferManager 的 max_file_size 需要设得足够小以便测试。测试 fixture 中已设 max_file_size=100（config 默认太大，需要调整）。实际实现中 FileTransferConfig 的默认 max_file_size=5GB，但测试中需要设小值。测试 fixture 通过构造 FileTransferConfig(max_file_size=200) 来覆盖。

- [ ] **Step 2: 运行测试确认失败**

```bash
pytest tests/test_file_transfer_manager.py -v
```

预期：FAIL

- [ ] **Step 3: 实现 manager.py**

```python
# src/sip_protocol/file_transfer/manager.py
"""文件传输管理器 — 协调分块、存储、引用"""

from __future__ import annotations

import base64
import hashlib
import mimetypes
import os
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from sip_protocol.exceptions import ChunkIntegrityError, FileTooLargeError
from sip_protocol.file_transfer.config import FileTransferConfig
from sip_protocol.file_transfer.manifest import FileChunk, FileManifest
from sip_protocol.file_transfer.store import LocalFileStore
from sip_protocol.schema._utils import _generate_uuid7
from sip_protocol.schema.parts import FileDataPart, FileRefPart


class TransferStatus(str, Enum):
    """传输状态（借鉴 LocalSend SessionStatus/FileStatus 模式）"""

    PENDING = "pending"
    SENDING = "sending"
    RECEIVING = "receiving"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELED = "canceled"


@dataclass
class TransferProgress:
    """传输进度（归一化 0..1，借鉴 LocalSend ProgressNotifier）"""

    file_id: str = ""
    file_name: str = ""
    status: TransferStatus = TransferStatus.PENDING
    transferred_chunks: int = 0
    total_chunks: int = 0
    transferred_bytes: int = 0
    total_bytes: int = 0
    is_complete: bool = False

    @property
    def progress_ratio(self) -> float:
        """归一化进度 0..1"""
        if self.total_bytes == 0:
            return 0.0
        return self.transferred_bytes / self.total_bytes


class FileTransferManager:
    """文件传输管理器

    协调文件分块、本地存储、引用生成和文件重组。
    """

    def __init__(
        self,
        config: FileTransferConfig | None = None,
        store: LocalFileStore | None = None,
    ) -> None:
        self._config = config or FileTransferConfig()
        self._store = store or LocalFileStore()
        self._progress: dict[str, TransferProgress] = {}

    def send_file(self, file_path: str) -> FileRefPart | FileDataPart:
        """发送文件：小文件内联，大文件分块存储后返回引用

        Args:
            file_path: 待发送文件的本地路径

        Returns:
            FileDataPart（小文件）或 FileRefPart（大文件）

        Raises:
            FileNotFoundError: 文件不存在
            FileTooLargeError: 文件过大
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"文件不存在: {file_path}")

        file_size = os.path.getsize(file_path)
        self._config.validate_size(file_size)

        if self._config.should_inline(file_size):
            return self._send_inline(file_path)
        return self._send_chunked(file_path)

    def _send_inline(self, file_path: str) -> FileDataPart:
        """内联发送小文件"""
        with open(file_path, "rb") as f:
            data = f.read()
        encoded = base64.b64encode(data).decode("ascii")
        file_name = os.path.basename(file_path)
        mime_type = mimetypes.guess_type(file_name)[0] or "application/octet-stream"
        return FileDataPart(data=encoded, name=file_name, mime_type=mime_type)

    def _send_chunked(self, file_path: str) -> FileRefPart:
        """分块存储大文件，返回引用"""
        file_name = os.path.basename(file_path)
        mime_type = mimetypes.guess_type(file_name)[0] or "application/octet-stream"
        file_id = _generate_uuid7()

        # 读取全文并计算 content_hash
        with open(file_path, "rb") as f:
            content = f.read()
        content_hash = "sha256:" + hashlib.sha256(content).hexdigest()

        # 分块
        chunks: list[FileChunk] = []
        for i in range(0, len(content), self._config.chunk_size):
            chunk_data = content[i : i + self._config.chunk_size]
            chunk_hash = "sha256:" + hashlib.sha256(chunk_data).hexdigest()
            chunks.append(FileChunk(index=len(chunks), size=len(chunk_data), hash=chunk_hash))

        # 构建 manifest
        manifest = FileManifest(
            id=file_id,
            file_name=file_name,
            mime_type=mime_type,
            total_size=len(content),
            chunk_size=self._config.chunk_size,
            content_hash=content_hash,
            chunks=chunks,
        )

        # 存储块
        for i, chunk_data in enumerate(self._chunk_iter(content)):
            self._store.store_chunk(file_id, i, chunk_data)

        # 存储 manifest
        manifest_url = self._store.store_manifest(manifest)

        # 记录进度
        self._progress[file_id] = TransferProgress(
            file_id=file_id,
            file_name=file_name,
            transferred_chunks=len(chunks),
            total_chunks=len(chunks),
            transferred_bytes=len(content),
            total_bytes=len(content),
            is_complete=True,
        )

        return FileRefPart(
            url=manifest_url,
            hash=content_hash,
            name=file_name,
            size=len(content),
            mime_type=mime_type,
        )

    def receive_file(self, part: FileRefPart | FileDataPart, output_path: str) -> None:
        """接收文件并写入本地路径

        Args:
            part: 文件引用（FileRefPart）或内联数据（FileDataPart）
            output_path: 输出文件路径

        Raises:
            ChunkIntegrityError: 块完整性校验失败
        """
        if isinstance(part, FileDataPart):
            self._receive_inline(part, output_path)
        else:
            self._receive_chunked(part, output_path)

    def _receive_inline(self, part: FileDataPart, output_path: str) -> None:
        """接收内联文件"""
        data = base64.b64decode(part.data)
        output_path = self._safe_output_path(output_path, part.name)
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        with open(output_path, "wb") as f:
            f.write(data)

    def _receive_chunked(self, part: FileRefPart, output_path: str) -> None:
        """接收分块文件：读取 manifest → 下载块 → 校验 → 重组"""
        manifest = self._store.retrieve_manifest(part.url)
        output_path = self._safe_output_path(output_path, manifest.file_name)
        file_id = manifest.id

        # 创建输出目录
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)

        # 下载并校验每个块
        assembled = bytearray()
        for chunk_meta in manifest.chunks:
            chunk_data = self._store.retrieve_chunk(file_id, chunk_meta.index)
            chunk_hash = "sha256:" + hashlib.sha256(chunk_data).hexdigest()
            if chunk_hash != chunk_meta.hash:
                raise ChunkIntegrityError(chunk_index=chunk_meta.index)
            assembled.extend(chunk_data)

        # 整体 hash 校验
        final_hash = "sha256:" + hashlib.sha256(bytes(assembled)).hexdigest()
        if final_hash != manifest.content_hash:
            raise ChunkIntegrityError()

        with open(output_path, "wb") as f:
            f.write(assembled)

        # 更新进度
        self._progress[file_id] = TransferProgress(
            file_id=file_id,
            file_name=manifest.file_name,
            transferred_chunks=manifest.total_chunks,
            total_chunks=manifest.total_chunks,
            transferred_bytes=manifest.total_size,
            total_bytes=manifest.total_size,
            is_complete=True,
        )

    def get_manifest(self, ref: FileRefPart) -> FileManifest:
        """从 FileRefPart 获取 FileManifest"""
        return self._store.retrieve_manifest(ref.url)

    def get_progress(self, file_id: str) -> TransferProgress | None:
        """获取传输进度"""
        return self._progress.get(file_id)

    @staticmethod
    def _chunk_iter(data: bytes, chunk_size: int) -> list[bytes]:
        """将字节数据按 chunk_size 切分"""
        return [data[i : i + chunk_size] for i in range(0, len(data), chunk_size)]

    @staticmethod
    def _safe_output_path(output_path: str, file_name: str) -> str:
        """安全的输出路径：路径遍历防护 + 文件名冲突自动重命名（借鉴 LocalSend）

        1. 路径遍历防护：确保输出路径不在父目录之外
        2. 文件名冲突：若文件已存在，自动追加计数器 file.txt → file (2).txt
        """
        # 路径遍历防护
        output_path = os.path.realpath(output_path)
        parent = os.path.dirname(output_path)
        if not os.path.exists(parent):
            os.makedirs(parent, exist_ok=True)

        # 文件名冲突处理
        if os.path.exists(output_path):
            base, ext = os.path.splitext(output_path)
            counter = 2
            while os.path.exists(f"{base} ({counter}){ext}"):
                counter += 1
            output_path = f"{base} ({counter}){ext}"

        return output_path
```

注意：测试中 fixture 的 `max_file_size` 需要 override。修改测试 fixture 为 `FileTransferConfig(inline_threshold=64, chunk_size=32, max_file_size=200)` 以确保 `test_file_too_large_raises` 测试能通过。

- [ ] **Step 4: 运行测试确认通过**

```bash
pytest tests/test_file_transfer_manager.py -v
```

预期：全部 PASS

- [ ] **Step 5: 提交**

```bash
git add src/sip_protocol/file_transfer/manager.py tests/test_file_transfer_manager.py
git commit -m "feat: 新增FileTransferManager，实现文件分块发送与接收"
```

---

### Task 5: 包导出 + 集成测试

**Files:**
- Modify: `src/sip_protocol/file_transfer/__init__.py`
- Create: `tests/test_file_transfer_integration.py`

- [ ] **Step 1: 更新 __init__.py 导出**

```python
# src/sip_protocol/file_transfer/__init__.py
"""SIP 文件传输模块 — 分块存储与引用传输"""

from sip_protocol.file_transfer.config import FileTransferConfig
from sip_protocol.file_transfer.manager import (
    FileTransferManager,
    TransferProgress,
    TransferStatus,
)
from sip_protocol.file_transfer.manifest import FileChunk, FileManifest
from sip_protocol.file_transfer.store import FileStore, LocalFileStore

__all__ = [
    "FileTransferConfig",
    "FileChunk",
    "FileManifest",
    "FileStore",
    "LocalFileStore",
    "FileTransferManager",
    "TransferProgress",
    "TransferStatus",
]
```

- [ ] **Step 2: 写集成测试**

```python
# tests/test_file_transfer_integration.py
"""文件传输端到端集成测试"""

import os

import pytest

from sip_protocol.file_transfer import FileTransferConfig, FileTransferManager, LocalFileStore
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
    )
    assert FileTransferConfig is not None
    assert FileTransferManager is not None
```

- [ ] **Step 3: 运行测试确认通过**

```bash
pytest tests/test_file_transfer_integration.py -v
```

预期：全部 PASS

- [ ] **Step 4: 运行全量测试确认无回归**

```bash
pytest tests/ -q
```

预期：全部 PASS（包括之前的 S1+P2 测试）

- [ ] **Step 5: 提交**

```bash
git add src/sip_protocol/file_transfer/__init__.py tests/test_file_transfer_integration.py
git commit -m "feat: 完善file_transfer包导出与集成测试"
```

---

### Task 6: Lint + 类型检查 + CHANGELOG

**Files:**
- Modify: `CHANGELOG.md`

- [ ] **Step 1: Pylint 检查**

```bash
cd python && source .venv/bin/activate
pylint src/sip_protocol/file_transfer/ src/sip_protocol/exceptions.py
```

预期：10.00/10。如有问题立即修复。

- [ ] **Step 2: MyPy 检查**

```bash
mypy src/sip_protocol/file_transfer/ --ignore-missing-imports
```

预期：Success: no issues found。如有问题立即修复。

- [ ] **Step 3: Black 格式化**

```bash
black src/sip_protocol/file_transfer/ tests/test_file_transfer*.py
```

- [ ] **Step 4: 运行全量测试**

```bash
pytest tests/ -q
```

预期：全部 PASS

- [ ] **Step 5: 更新 CHANGELOG**

在 `CHANGELOG.md` 的 `[Unreleased]` 段 `### 新增` 下追加：

```markdown
#### 文件传输（F1）
- **FileTransferConfig**（src/sip_protocol/file_transfer/config.py）
  - 可配置阈值：inline_threshold, chunk_size, max_file_size
  - should_inline() / validate_size()
- **FileChunk + FileManifest**（src/sip_protocol/file_transfer/manifest.py）
  - 文件块描述（index, size, hash）
  - 文件清单（元数据 + 块列表 + 序列化）
- **LocalFileStore**（src/sip_protocol/file_transfer/store.py）
  - 本地文件系统存储，目录结构化
  - FileStore Protocol 定义接口
  - 过期文件自动清理
- **FileTransferManager**（src/sip_protocol/file_transfer/manager.py）
  - send_file()：小文件内联（FileDataPart），大文件分块引用（FileRefPart）
  - receive_file()：引用解析 → 块校验 → 重组
  - TransferProgress 进度追踪
- **文件传输异常**（追加到 exceptions.py）
  - FileTransferError, ChunkIntegrityError, FileTooLargeError
```

- [ ] **Step 6: 提交**

```bash
git add CHANGELOG.md
git commit -m "docs: 更新CHANGELOG记录F1文件传输实现"
```
