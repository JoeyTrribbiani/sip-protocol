"""SIP 消息 Schema 类型系统测试"""

import pytest
from sip_protocol.schema.types import (
    MessageType,
    Priority,
    RecipientType,
)


class TestMessageType:
    def test_all_values_are_strings(self):
        for mt in MessageType:
            assert isinstance(mt.value, str)

    def test_count(self):
        assert len(MessageType) == 9

    def test_values(self):
        assert MessageType.TEXT.value == "text"
        assert MessageType.TASK_DELEGATE.value == "task_delegate"
        assert MessageType.TASK_UPDATE.value == "task_update"
        assert MessageType.TASK_RESULT.value == "task_result"
        assert MessageType.CONTEXT_SHARE.value == "context_share"
        assert MessageType.CAPABILITY_ANNOUNCE.value == "capability_announce"
        assert MessageType.FILE_TRANSFER_PROGRESS.value == "file_transfer_progress"
        assert MessageType.HEARTBEAT.value == "heartbeat"
        assert MessageType.ERROR.value == "error"


class TestPriority:
    def test_values(self):
        assert Priority.LOW.value == "low"
        assert Priority.NORMAL.value == "normal"
        assert Priority.HIGH.value == "high"
        assert Priority.URGENT.value == "urgent"


class TestRecipientType:
    def test_values(self):
        assert RecipientType.DIRECT.value == "direct"
        assert RecipientType.GROUP.value == "group"
        assert RecipientType.BROADCAST.value == "broadcast"
