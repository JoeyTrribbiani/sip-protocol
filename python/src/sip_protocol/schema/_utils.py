"""Schema 内部工具函数"""

import time
import uuid


def _generate_uuid7() -> str:
    """生成 UUID（暂用 uuid4 占位，后续替换为 uuid7）"""
    return str(uuid.uuid4())


def _iso_now() -> str:
    """返回当前 UTC 时间的 ISO 8601 格式字符串"""
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
