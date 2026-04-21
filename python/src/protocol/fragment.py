"""
消息分片模块
支持大消息的自动分片和重组
"""

import json
import hashlib
import time
import base64
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass

MAX_MESSAGE_SIZE = 1024 * 1024  # 1MB
MAX_PAYLOAD_SIZE = 900 * 1024  # 900KB
FRAGMENT_TIMEOUT = 30  # 分片超时时间（秒）


@dataclass
class FragmentInfo:
    """分片信息"""

    fragment_id: str
    fragment_index: int
    fragment_total: int
    fragment_size: int


class FragmentBuffer:
    """分片缓冲区"""

    def __init__(self, timeout: int = FRAGMENT_TIMEOUT):
        self.fragments: Dict[str, List[Optional[bytes]]] = {}
        self.fragment_infos: Dict[str, FragmentInfo] = {}
        self.timestamps: Dict[str, float] = {}
        self.timeout = timeout

    def add_fragment(
        self,
        fragment_id: str,
        fragment_index: int,
        fragment_total: int,
        fragment_size: int,
        payload: bytes,
    ) -> bool:
        """
        添加一个分片

        Args:
            fragment_id: 分片ID
            fragment_index: 分片序号（从1开始）
            fragment_total: 分片总数
            fragment_size: 分片大小
            payload: 分片数据

        Returns:
            bool: 如果分片已完整返回True，否则返回False
        """
        current_time = time.time()

        # 初始化分片集合
        if fragment_id not in self.fragments:
            self.fragments[fragment_id] = [None] * fragment_total
            self.fragment_infos[fragment_id] = FragmentInfo(
                fragment_id=fragment_id,
                fragment_index=fragment_index,
                fragment_total=fragment_total,
                fragment_size=fragment_size,
            )
            self.timestamps[fragment_id] = current_time
        else:
            # 更新时间戳
            self.timestamps[fragment_id] = current_time

        # 添加分片
        if fragment_index < 1 or fragment_index > fragment_total:
            raise ValueError(f"Invalid fragment index: {fragment_index}")

        self.fragments[fragment_id][fragment_index - 1] = payload

        # 检查是否所有分片都已收集
        if all(p is not None for p in self.fragments[fragment_id]):
            return True

        return False

    def get_reassembled_payload(self, fragment_id: str) -> bytes:
        """
        获取重组后的payload

        Args:
            fragment_id: 分片ID

        Returns:
            bytes: 重组后的payload
        """
        if fragment_id not in self.fragments:
            raise ValueError(f"Fragment ID not found: {fragment_id}")

        fragments = self.fragments[fragment_id]
        if not all(p is not None for p in fragments):
            raise ValueError(f"Fragment incomplete: {fragment_id}")

        # 转换为List[bytes]以满足类型检查
        validated_fragments: List[bytes] = [f for f in fragments if f is not None]
        reassembled = b"".join(validated_fragments)
        return reassembled

    def cleanup_expired_fragments(self) -> int:
        """
        清理过期的分片

        Returns:
            int: 清理的分片数量
        """
        current_time = time.time()
        expired_ids = []

        for fragment_id, timestamp in self.timestamps.items():
            if current_time - timestamp > self.timeout:
                expired_ids.append(fragment_id)

        for fragment_id in expired_ids:
            del self.fragments[fragment_id]
            del self.fragment_infos[fragment_id]
            del self.timestamps[fragment_id]

        return len(expired_ids)

    def remove_fragment(self, fragment_id: str) -> None:
        """
        移除指定ID的分片

        Args:
            fragment_id: 分片ID
        """
        if fragment_id in self.fragments:
            del self.fragments[fragment_id]
        if fragment_id in self.fragment_infos:
            del self.fragment_infos[fragment_id]
        if fragment_id in self.timestamps:
            del self.timestamps[fragment_id]


def generate_fragment_id(message_counter: int, sender_id: str) -> str:
    """
    生成分片ID

    Args:
        message_counter: 消息计数器
        sender_id: 发送方ID

    Returns:
        str: 分片ID（16字符十六进制字符串）
    """
    data = f"{sender_id}:{message_counter}".encode()
    fragment_id = hashlib.sha256(data).hexdigest()[:16]
    return fragment_id


def fragment_message(message: dict, message_counter: int, sender_id: str) -> List[dict]:
    """
    分片消息

    Args:
        message: 原始消息
        message_counter: 消息计数器
        sender_id: 发送方ID

    Returns:
        List[dict]: 分片后的消息列表
    """
    # 提取payload
    payload_str = json.dumps(message["payload"])
    payload_bytes = payload_str.encode()

    # 计算消息总大小（JSON格式）
    message_size = len(payload_bytes)

    # 如果消息小于MAX_MESSAGE_SIZE，直接返回
    if message_size <= MAX_MESSAGE_SIZE:
        return [message]

    # 计算分片数量
    fragment_size = MAX_PAYLOAD_SIZE
    fragment_total = (message_size + fragment_size - 1) // fragment_size

    # 生成分片ID
    fragment_id = generate_fragment_id(message_counter, sender_id)

    # 分片
    fragments = []
    for i in range(fragment_total):
        start = i * fragment_size
        end = min(start + fragment_size, message_size)
        fragment_payload = payload_bytes[start:end]

        # 构建分片消息
        fragment_msg = {
            "version": message.get("version", "SIP-1.0"),
            "type": "message_fragment",
            "timestamp": message.get("timestamp", int(time.time() * 1000)),
            "sender_id": message.get("sender_id", sender_id),
            "recipient_id": message.get("recipient_id", ""),
            "message_counter": message_counter,
            "fragment_info": {
                "fragment_id": fragment_id,
                "fragment_index": i + 1,
                "fragment_total": fragment_total,
                "fragment_size": len(fragment_payload),
            },
            "iv": message.get("iv", ""),
            "payload": base64.b64encode(fragment_payload).decode(),
            "auth_tag": message.get("auth_tag", ""),
            "replay_tag": message.get("replay_tag", ""),
        }

        fragments.append(fragment_msg)

    return fragments


def reassemble_fragment(fragment_msg: dict, buffer: FragmentBuffer) -> Optional[bytes]:
    """
    重组分片

    Args:
        fragment_msg: 分片消息
        buffer: 分片缓冲区

    Returns:
        Optional[bytes]: 如果分片完整返回重组后的payload，否则返回None
    """
    fragment_info = fragment_msg["fragment_info"]
    fragment_id = fragment_info["fragment_id"]
    fragment_index = fragment_info["fragment_index"]
    fragment_total = fragment_info["fragment_total"]
    fragment_size = fragment_info["fragment_size"]

    # 解码payload
    payload = base64.b64decode(fragment_msg["payload"])

    # 添加分片到缓冲区
    is_complete = buffer.add_fragment(
        fragment_id=fragment_id,
        fragment_index=fragment_index,
        fragment_total=fragment_total,
        fragment_size=fragment_size,
        payload=payload,
    )

    # 如果分片完整，返回重组后的payload
    if is_complete:
        reassembled = buffer.get_reassembled_payload(fragment_id)
        buffer.remove_fragment(fragment_id)
        return reassembled

    return None
