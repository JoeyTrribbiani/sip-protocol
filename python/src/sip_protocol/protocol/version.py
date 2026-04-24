"""
协议版本协商模块
"""

import time
from typing import List, Optional

PROTOCOL_VERSIONS = ["SIP-1.0", "SIP-1.1", "SIP-1.2", "SIP-1.3"]
DEFAULT_VERSION = "SIP-1.0"


def negotiate_version(supported_versions: List[str], remote_supported: List[str]) -> Optional[str]:
    """
    协商协议版本

    Args:
        supported_versions: 本地支持的版本列表
        remote_supported: 远程支持的版本列表

    Returns:
        Optional[str]: 协商后的版本，如果没有共同版本则返回None
    """
    # 按版本号排序（从高到低）
    supported_sorted = sorted(supported_versions, reverse=True)

    # 找到双方都支持的最新版本
    for version in supported_sorted:
        if version in remote_supported:
            return version

    return None


def validate_version(version: str) -> bool:
    """
    验证版本号格式

    Args:
        version: 版本号字符串

    Returns:
        bool: 是否有效
    """
    if version not in PROTOCOL_VERSIONS:
        return False

    # 检查格式：SIP-{major}.{minor}
    parts = version.split("-")
    if len(parts) != 2:
        return False

    if parts[0] != "SIP":
        return False

    version_parts = parts[1].split(".")
    if len(version_parts) != 2:
        return False

    try:
        major = int(version_parts[0])
        minor = int(version_parts[1])
        return major >= 1 and minor >= 0
    except ValueError:
        return False


def version_compare(version1: str, version2: str) -> int:
    """
    比较两个版本号

    Args:
        version1: 版本号1
        version2: 版本号2

    Returns:
        int: 0表示相等，-1表示version1 < version2，1表示version1 > version2
    """
    v1_parts = version1.replace("SIP-", "").split(".")
    v2_parts = version2.replace("SIP-", "").split(".")

    v1_major, v1_minor = int(v1_parts[0]), int(v1_parts[1])
    v2_major, v2_minor = int(v2_parts[0]), int(v2_parts[1])

    if v1_major < v2_major:
        return -1
    if v1_major > v2_major:
        return 1
    if v1_minor < v2_minor:
        return -1
    if v1_minor > v2_minor:
        return 1
    return 0


def is_backward_compatible(old_version: str, new_version: str) -> bool:
    """
    检查新版本是否向后兼容旧版本

    Args:
        old_version: 旧版本号
        new_version: 新版本号

    Returns:
        bool: 是否向后兼容
    """
    # 主版本号必须相同，次版本号可以增加
    old_parts = old_version.replace("SIP-", "").split(".")
    new_parts = new_version.replace("SIP-", "").split(".")

    old_major, old_minor = int(old_parts[0]), int(old_parts[1])
    new_major, new_minor = int(new_parts[0]), int(new_parts[1])

    if old_major != new_major:
        return False

    return new_minor >= old_minor


def create_version_offer(supported_versions: List[str], sender_id: str) -> dict:
    """创建版本协商提议消息"""
    return {
        "version": DEFAULT_VERSION,
        "type": "version_offer",
        "timestamp": int(time.time() * 1000),
        "sender_id": sender_id,
        "supported_versions": supported_versions,
    }


def parse_version_response(data: dict) -> Optional[str]:
    """解析版本协商响应，返回协商结果版本

    Returns:
        协商后的版本，无共同版本返回 None
    """
    if data.get("type") != "version_response":
        return None
    selected = data.get("selected_version", "")
    supported = data.get("supported_versions", [])
    return negotiate_version(supported, [selected])


def create_version_not_supported(supported: List[str], remote_supported: List[str]) -> dict:
    """创建版本不支持的错误消息"""
    return {
        "version": DEFAULT_VERSION,
        "type": "error",
        "error_code": "VERSION_NOT_SUPPORTED",
        "error_message": f"No common version. Supported: {supported}",
        "timestamp": int(time.time() * 1000),
        "remote_versions": remote_supported,
    }


def create_version_response(
    selected_version: str, supported_versions: List[str], sender_id: str
) -> dict:
    """创建版本协商响应消息"""
    return {
        "version": selected_version,
        "type": "version_response",
        "timestamp": int(time.time() * 1000),
        "sender_id": sender_id,
        "selected_version": selected_version,
        "supported_versions": supported_versions,
    }
