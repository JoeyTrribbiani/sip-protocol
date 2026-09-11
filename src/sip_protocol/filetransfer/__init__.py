"""
SIP加密文件传输模块
自包含加密工件（.sipft）：流式分块加密 + HKDF块独立密钥 + AEAD tag链防篡改重排

包含：
- pack_file: 文件 → 加密工件（transport之上的应用层，仅复用crypto原语）
- unpack_file: 加密工件 → 文件（逐块fail-fast校验）
"""

from .packer import ARTIFACT_SUFFIX, PackResult, pack_file
from .unpacker import UnpackResult, unpack_file

__all__ = [
    "ARTIFACT_SUFFIX",
    "PackResult",
    "pack_file",
    "UnpackResult",
    "unpack_file",
]
