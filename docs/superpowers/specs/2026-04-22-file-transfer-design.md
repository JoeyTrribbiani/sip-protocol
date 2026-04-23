# 文件/图片/视频传输设计文档

> 版本: v1.0
> 日期: 2026-04-22
> 状态: 已批准
> 关联: F1 (agent-chat-architecture.md Phase 2 待实现)

## 1. 问题陈述

当前SIP协议只支持文本消息，无法传输二进制文件（图片、视频、模型权重、配置文件等）。Agent在协作中经常需要交换文件：分析报告、代码包、数据集等。

## 2. 设计原则

1. **文件不上消息通道** — 消息通道只传引用（FileRefPart），实际文件走独立传输
2. **块级加密** — 每个文件块独立加密，支持断点续传和并行下载
3. **内容寻址** — 块hash(SHA-256)作为唯一标识，天然去重
4. **可配置阈值** — 内联/引用阈值和分块大小均可配置
5. **进度通知** — 大文件传输实时进度通过MessageType.FILE_TRANSFER_PROGRESS通知

## 3. 传输架构

```
┌─────────────────────────────────────────────────┐
│               文件传输流程                        │
├─────────────────────────────────────────────────┤
│                                                 │
│  发送方 Agent                                    │
│  ┌──────────┐                                   │
│  │ 文件     │                                   │
│  │ (任意大小)│                                   │
│  └────┬─────┘                                   │
│       │                                         │
│       ▼                                         │
│  ┌──────────┐    ┌──────────────┐               │
│  │ 分块     │───>│ 加密每个块   │               │
│  │ (config) │    │ (XChaCha20) │               │
│  └──────────┘    └──────┬───────┘               │
│                         │                        │
│              ┌──────────▼──────────┐            │
│              │  FileStore          │            │
│              │  (本地/S3/共享内存)  │            │
│              └──────────┬──────────┘            │
│                         │                        │
│              ┌──────────▼──────────┐            │
│              │ 发送 FileRefPart    │            │
│              │ + FileManifest      │            │
│              └──────────┬──────────┘            │
│                         │ SIP加密通道            │
│              ┌──────────▼──────────┐            │
│              │ 接收方 Agent        │            │
│              │ 验证hash → 下载块   │            │
│              │ → 解密 → 重组       │            │
│              └─────────────────────┘            │
└─────────────────────────────────────────────────┘
```

## 4. 配置

```python
@dataclass
class FileTransferConfig:
    """文件传输配置，所有参数可按场景调整"""
    inline_threshold: int = 4096      # 文件内联阈值（字节），默认4KB
    chunk_size: int = 1048576          # 分块大小（字节），默认1MB
    max_file_size: int = 5368709120   # 最大文件大小（字节），默认5GB
    max_chunks: int = 5120            # 最大块数（= max_file_size / chunk_size）
    default_ttl: int = 86400          # 文件默认TTL（秒），24小时
    parallel_downloads: int = 4       # 并行下载线程数
    retry_count: int = 3              // 块下载重试次数
```

不同场景的推荐配置：

| 场景 | inline_threshold | chunk_size | 说明 |
|------|-----------------|------------|------|
| 局域网 | 65536 (64KB) | 4194304 (4MB) | 高带宽低延迟 |
| 互联网 | 4096 (4KB) | 1048576 (1MB) | 保守默认值 |
| 移动网络 | 2048 (2KB) | 524288 (512KB) | 低带宽高延迟 |

## 5. 核心数据结构

### 5.1 FileManifest（文件清单）

包含完整的文件描述和加密信息：

```json
{
  "id": "file-uuid-xxx",
  "file_name": "report.pdf",
  "mime_type": "application/pdf",
  "total_size": 10485760,
  "total_chunks": 10,
  "chunk_size": 1048576,
  "content_hash": "sha256:abc123def456...",
  "encryption": {
    "algorithm": "xchacha20-poly1305",
    "key_id": "key-uuid-xxx",
    "nonce_prefix": "base64prefix..."
  },
  "chunks": [
    {
      "index": 0,
      "size": 1048576,
      "hash": "sha256:aaa111..."
    },
    {
      "index": 1,
      "size": 1048576,
      "hash": "sha256:bbb222..."
    }
  ],
  "created_at": "2026-04-22T12:00:00Z",
  "expires_at": "2026-04-23T12:00:00Z"
}
```

**关键设计**：
- `content_hash`：原文完整hash，用于端到端完整性校验
- `encryption.key_id`：密钥标识，Rekey后旧文件仍可解密
- `encryption.algorithm`：记录加密算法，支持算法演进

### 5.2 FileBlock（文件块）

```python
@dataclass
class FileBlock:
    index: int              # 块序号（0-based）
    data: bytes             # 加密后的密文
    nonce: bytes            # XChaCha20 nonce（24字节）
    auth_tag: bytes         # 认证标签（16字节）
    size: int               # 原文大小（字节）
    hash: str               # 原文SHA-256 hash
```

### 5.3 FileTransferProgress（传输进度）

```python
@dataclass
class FileTransferProgress:
    file_id: str
    file_name: str
    transferred_chunks: int
    total_chunks: int
    transferred_bytes: int
    total_bytes: int
    speed_bytes_per_sec: float
    is_complete: bool
```

## 6. 核心组件

### 6.1 FileTransferManager

```python
class FileTransferManager:
    """文件传输管理器 — 协调分块、加密、传输、重组"""

    def __init__(self, config: FileTransferConfig, store: FileStore):
        self._config = config
        self._store = store
        self._active_transfers: dict[str, FileTransferState] = {}

    async def send_file(self, file_path: str, recipient_id: str) -> FileRefPart:
        """发送文件：分块 → 加密 → 存储 → 返回引用"""

    async def receive_file(self, file_ref: FileRefPart) -> str:
        """接收文件：验证manifest → 下载块 → 解密 → 重组"""

    async def cancel_transfer(self, file_id: str) -> None:
        """取消传输"""

    def get_progress(self, file_id: str) -> FileTransferProgress | None:
        """获取传输进度"""

    def _should_inline(self, file_size: int) -> bool:
        """判断文件是否应内联"""
        return file_size < self._config.inline_threshold
```

### 6.2 FileStore（存储抽象）

```python
from abc import ABC, abstractmethod


class FileStore(ABC):
    """文件存储抽象接口"""

    @abstractmethod
    async def store_chunk(self, file_id: str, block: FileBlock) -> str:
        """存储加密块，返回块URL"""

    @abstractmethod
    async def retrieve_chunk(self, file_id: str, index: int) -> FileBlock:
        """检索加密块"""

    @abstractmethod
    async def store_manifest(self, manifest: FileManifest) -> str:
        """存储文件清单，返回清单URL"""

    @abstractmethod
    async def retrieve_manifest(self, url: str) -> FileManifest:
        """检索文件清单"""

    @abstractmethod
    async def delete(self, file_id: str) -> None:
        """删除文件及所有块"""

    @abstractmethod
    async def cleanup_expired(self) -> int:
        """清理过期文件，返回删除数量"""


class LocalFileStore(FileStore):
    """本地文件系统存储"""

    def __init__(self, base_path: str = "~/.openclaw/sip_files"):
        ...
```

### 6.3 FileTransport（传输抽象）

```python
class FileTransport(ABC):
    """文件块传输抽象"""

    @abstractmethod
    async def upload_chunk(self, block: FileBlock, file_id: str) -> str:
        """上传块到远程，返回可访问URL"""

    @abstractmethod
    async def download_chunk(self, url: str) -> FileBlock:
        """从URL下载块"""
```

## 7. 文件传输消息流

### 7.1 发送流程

```
1. 发送方调用 FileTransferManager.send_file(file_path, recipient_id)
2. Manager 判断文件大小 < inline_threshold？
   ├─ 是 → 直接返回 FileDataPart（base64内联）
   └─ 否 → 进入分块流程
3. 分块：按 chunk_size 切割文件
4. 计算每块原文 hash (SHA-256) 和整体 content_hash
5. 每块独立加密（XChaCha20-Poly1305，用唯一nonce）
6. 加密块存入 FileStore
7. 构建 FileManifest（含 key_id、每块hash）
8. FileManifest 存入 FileStore
9. 返回 FileRefPart（URL + hash + manifest引用）
10. FileRefPart 包装进 SIP Message Schema 发送
```

### 7.2 接收流程

```
1. 接收方收到包含 FileRefPart 的 SIP 消息
2. 调用 FileTransferManager.receive_file(file_ref)
3. 从 FileRefPart.url 检索 FileManifest
4. 验证 manifest.content_hash 完整性
5. 并行下载加密块（parallel_downloads 个线程）
6. 验证每块 hash
7. 用 key_id 对应的密钥解密每块
8. 按序号重组 → 写入本地文件
9. 验证整体 content_hash
10. 传输过程中定期发送 FILE_TRANSFER_PROGRESS 消息
```

## 8. 进度通知

通过 MessageType.FILE_TRANSFER_PROGRESS 发送传输进度：

```json
{
  "schema": "sip-msg/v1",
  "message_type": "file_transfer_progress",
  "sender_id": "agent-sender",
  "parts": [
    {
      "type": "data",
      "content_type": "application/sip-file-progress",
      "data": {
        "file_id": "file-uuid-xxx",
        "file_name": "report.pdf",
        "transferred_chunks": 5,
        "total_chunks": 10,
        "transferred_bytes": 5242880,
        "total_bytes": 10485760,
        "is_complete": false
      }
    }
  ]
}
```

## 9. 安全考虑

1. **块级加密** — 每个块独立加密，即使部分块泄露也不影响其他块
2. **key_id机制** — Rekey后旧文件仍可通过key_id找到对应密钥解密
3. **内容寻址** — SHA-256 hash防止篡改，下载后必须验证
4. **TTL过期** — 存储的文件块有默认24小时TTL，自动清理
5. **传输中保护** — 块传输通过SIP加密通道或FileTransport各自加密

## 10. 模块位置

```
python/src/sip_protocol/
├── file_transfer/
│   ├── __init__.py
│   ├── manager.py         # FileTransferManager
│   ├── store.py           # FileStore + LocalFileStore
│   ├── transport.py       # FileTransport 抽象
│   ├── manifest.py        # FileManifest 数据结构
│   └── config.py          # FileTransferConfig
```
