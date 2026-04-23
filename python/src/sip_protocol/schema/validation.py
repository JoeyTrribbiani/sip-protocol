"""SIP 消息 Schema 验证逻辑"""

from __future__ import annotations

from typing import Any


def validate_message(msg: dict[str, Any]) -> list[str]:
    """验证SIP消息的必填字段和业务规则

    返回错误列表，空列表表示验证通过。
    """
    errors: list[str] = []
    required_fields = (
        "id", "conversation_id", "schema", "message_type",
        "sender_id", "recipient_type", "timestamp", "parts",
    )
    for field_name in required_fields:
        if field_name not in msg:
            errors.append(f"missing required field: {field_name}")

    if not msg.get("parts"):
        errors.append("parts must not be empty")

    rt = msg.get("recipient_type", "")
    if rt == "direct" and not msg.get("recipient_id"):
        errors.append("DIRECT type requires recipient_id")
    if rt == "group" and not msg.get("recipient_group"):
        errors.append("GROUP type requires recipient_group")

    return errors


def validate_parts(parts: list[dict[str, Any]]) -> list[str]:
    """验证parts列表

    返回错误列表。遇到未知part类型时抛出ValueError。
    """
    if not parts:
        return ["parts must not be empty"]
    valid_types = {
        "text", "data", "file_ref", "file_data",
        "tool_request", "tool_response", "context", "stream",
    }
    for part in parts:
        part_type = part.get("type", "")
        if part_type not in valid_types:
            raise ValueError(f"Unknown part type: {part_type}")
    return []
