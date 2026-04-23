"""SIP 消息 Schema 类型系统测试"""

import pytest
from sip_protocol.schema.message import SIPMessage, create_message
from sip_protocol.schema.parts import (
    ContextPart,
    DataPart,
    FileDataPart,
    FileRefPart,
    StreamPart,
    TextPart,
    ToolRequestPart,
    ToolResponsePart,
    part_from_dict,
)
from sip_protocol.schema.types import (
    MessageType,
    Priority,
    RecipientType,
)
from sip_protocol.schema.validation import validate_message, validate_parts


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


# ==================== Part 类型测试 ====================


class TestTextPart:
    def test_type_property(self):
        part = TextPart(text="hello")
        assert part.type == "text"

    def test_to_dict(self):
        part = TextPart(text="hello")
        d = part.to_dict()
        assert d == {"type": "text", "text": "hello"}

    def test_from_dict(self):
        part = TextPart.from_dict({"type": "text", "text": "world"})
        assert part.text == "world"

    def test_from_dict_missing_text(self):
        part = TextPart.from_dict({})
        assert part.text == ""

    def test_round_trip(self):
        original = TextPart(text="round trip")
        restored = TextPart.from_dict(original.to_dict())
        assert restored.text == original.text


class TestDataPart:
    def test_type_property(self):
        part = DataPart(data={"key": "val"})
        assert part.type == "data"

    def test_default_content_type(self):
        part = DataPart()
        assert part.content_type == "application/json"

    def test_to_dict(self):
        part = DataPart(content_type="text/plain", data="raw")
        d = part.to_dict()
        assert d == {"type": "data", "content_type": "text/plain", "data": "raw"}

    def test_from_dict(self):
        part = DataPart.from_dict({"type": "data", "content_type": "text/csv", "data": "a,b,c"})
        assert part.content_type == "text/csv"
        assert part.data == "a,b,c"

    def test_from_dict_defaults(self):
        part = DataPart.from_dict({})
        assert part.content_type == "application/json"
        assert part.data is None

    def test_round_trip(self):
        original = DataPart(content_type="application/xml", data="<root/>")
        restored = DataPart.from_dict(original.to_dict())
        assert restored == original


class TestFileRefPart:
    def test_type_property(self):
        part = FileRefPart(url="https://example.com/file.bin")
        assert part.type == "file_ref"

    def test_defaults(self):
        part = FileRefPart()
        assert part.url == ""
        assert part.hash == ""
        assert part.name == ""
        assert part.size == 0
        assert part.mime_type == "application/octet-stream"

    def test_to_dict(self):
        part = FileRefPart(url="https://x.com/f", hash="abc123", name="f.bin", size=1024, mime_type="text/plain")
        d = part.to_dict()
        assert d["url"] == "https://x.com/f"
        assert d["hash"] == "abc123"
        assert d["name"] == "f.bin"
        assert d["size"] == 1024
        assert d["mime_type"] == "text/plain"

    def test_from_dict(self):
        part = FileRefPart.from_dict({"url": "http://a.com/b", "hash": "h", "name": "b", "size": 42, "mime_type": "image/png"})
        assert part.url == "http://a.com/b"
        assert part.hash == "h"
        assert part.name == "b"
        assert part.size == 42
        assert part.mime_type == "image/png"

    def test_round_trip(self):
        original = FileRefPart(url="ftp://f.com/g", hash="sha256", name="g.zip", size=9999, mime_type="application/zip")
        restored = FileRefPart.from_dict(original.to_dict())
        assert restored == original


class TestFileDataPart:
    def test_type_property(self):
        part = FileDataPart(data="base64data", name="f.bin")
        assert part.type == "file_data"

    def test_to_dict(self):
        part = FileDataPart(data="aGVsbG8=", name="hello.txt", mime_type="text/plain")
        d = part.to_dict()
        assert d == {"type": "file_data", "data": "aGVsbG8=", "name": "hello.txt", "mime_type": "text/plain"}

    def test_from_dict(self):
        part = FileDataPart.from_dict({"data": "abc", "name": "x", "mime_type": "text/html"})
        assert part.data == "abc"
        assert part.name == "x"
        assert part.mime_type == "text/html"

    def test_round_trip(self):
        original = FileDataPart(data="YmFzZTY0", name="file.dat", mime_type="application/octet-stream")
        restored = FileDataPart.from_dict(original.to_dict())
        assert restored == original


class TestToolRequestPart:
    def test_type_property(self):
        part = ToolRequestPart(call_id="c1", name="search", arguments={"q": "test"})
        assert part.type == "tool_request"

    def test_defaults(self):
        part = ToolRequestPart()
        assert part.call_id == ""
        assert part.name == ""
        assert part.arguments == {}

    def test_to_dict(self):
        part = ToolRequestPart(call_id="c2", name="calc", arguments={"x": 1})
        d = part.to_dict()
        assert d == {"type": "tool_request", "call_id": "c2", "name": "calc", "arguments": {"x": 1}}

    def test_from_dict(self):
        part = ToolRequestPart.from_dict({"call_id": "c3", "name": "echo", "arguments": {"msg": "hi"}})
        assert part.call_id == "c3"
        assert part.name == "echo"
        assert part.arguments == {"msg": "hi"}

    def test_round_trip(self):
        original = ToolRequestPart(call_id="c4", name="run", arguments={"cmd": "ls"})
        restored = ToolRequestPart.from_dict(original.to_dict())
        assert restored == original


class TestToolResponsePart:
    def test_type_property(self):
        part = ToolResponsePart(call_id="c1")
        assert part.type == "tool_response"

    def test_to_dict_with_result(self):
        part = ToolResponsePart(call_id="c1", result=42, error=None)
        d = part.to_dict()
        assert "result" in d
        assert d["result"] == 42
        assert "error" not in d

    def test_to_dict_with_error(self):
        part = ToolResponsePart(call_id="c1", result=None, error="something failed")
        d = part.to_dict()
        assert "error" in d
        assert d["error"] == "something failed"
        assert "result" not in d

    def test_from_dict_result(self):
        part = ToolResponsePart.from_dict({"call_id": "c1", "result": "ok"})
        assert part.result == "ok"
        assert part.error is None

    def test_from_dict_error(self):
        part = ToolResponsePart.from_dict({"call_id": "c1", "error": "fail"})
        assert part.error == "fail"
        assert part.result is None

    def test_round_trip_result(self):
        original = ToolResponsePart(call_id="c1", result={"key": "val"}, error=None)
        restored = ToolResponsePart.from_dict(original.to_dict())
        assert restored.call_id == original.call_id
        assert restored.result == original.result

    def test_round_trip_error(self):
        original = ToolResponsePart(call_id="c1", result=None, error="boom")
        restored = ToolResponsePart.from_dict(original.to_dict())
        assert restored.call_id == original.call_id
        assert restored.error == original.error


class TestContextPart:
    def test_type_property(self):
        part = ContextPart(key="k1", value="v1")
        assert part.type == "context"

    def test_defaults(self):
        part = ContextPart()
        assert part.key == ""
        assert part.value is None
        assert part.ttl == 86400

    def test_to_dict(self):
        part = ContextPart(key="session_id", value="abc", ttl=3600)
        d = part.to_dict()
        assert d == {"type": "context", "key": "session_id", "value": "abc", "ttl": 3600}

    def test_from_dict(self):
        part = ContextPart.from_dict({"key": "token", "value": "xyz", "ttl": 7200})
        assert part.key == "token"
        assert part.value == "xyz"
        assert part.ttl == 7200

    def test_round_trip(self):
        original = ContextPart(key="env", value="prod", ttl=0)
        restored = ContextPart.from_dict(original.to_dict())
        assert restored == original


class TestStreamPart:
    def test_type_property(self):
        part = StreamPart(chunk_index=0, is_final=False, data="chunk")
        assert part.type == "stream"

    def test_defaults(self):
        part = StreamPart()
        assert part.chunk_index == 0
        assert part.total_chunks is None
        assert part.is_final is False
        assert part.data is None

    def test_to_dict_with_total_chunks(self):
        part = StreamPart(chunk_index=1, total_chunks=10, is_final=False, data="part")
        d = part.to_dict()
        assert d["total_chunks"] == 10

    def test_to_dict_without_total_chunks(self):
        part = StreamPart(chunk_index=0, total_chunks=None, is_final=True, data="end")
        d = part.to_dict()
        assert "total_chunks" not in d

    def test_from_dict(self):
        part = StreamPart.from_dict({"chunk_index": 2, "total_chunks": 5, "is_final": False, "data": "x"})
        assert part.chunk_index == 2
        assert part.total_chunks == 5
        assert part.is_final is False
        assert part.data == "x"

    def test_round_trip(self):
        original = StreamPart(chunk_index=3, total_chunks=10, is_final=False, data="data3")
        restored = StreamPart.from_dict(original.to_dict())
        assert restored == original

    def test_round_trip_no_total(self):
        original = StreamPart(chunk_index=0, total_chunks=None, is_final=True, data="final")
        restored = StreamPart.from_dict(original.to_dict())
        assert restored.chunk_index == 0
        assert restored.total_chunks is None
        assert restored.is_final is True
        assert restored.data == "final"


class TestPartFromDict:
    def test_dispatch_text(self):
        part = part_from_dict({"type": "text", "text": "hi"})
        assert isinstance(part, TextPart)
        assert part.text == "hi"

    def test_dispatch_data(self):
        part = part_from_dict({"type": "data", "data": 123})
        assert isinstance(part, DataPart)

    def test_dispatch_file_ref(self):
        part = part_from_dict({"type": "file_ref", "url": "http://x.com"})
        assert isinstance(part, FileRefPart)

    def test_dispatch_file_data(self):
        part = part_from_dict({"type": "file_data", "data": "base64"})
        assert isinstance(part, FileDataPart)

    def test_dispatch_tool_request(self):
        part = part_from_dict({"type": "tool_request", "call_id": "c1"})
        assert isinstance(part, ToolRequestPart)

    def test_dispatch_tool_response(self):
        part = part_from_dict({"type": "tool_response", "call_id": "c1"})
        assert isinstance(part, ToolResponsePart)

    def test_dispatch_context(self):
        part = part_from_dict({"type": "context", "key": "k1"})
        assert isinstance(part, ContextPart)

    def test_dispatch_stream(self):
        part = part_from_dict({"type": "stream", "chunk_index": 0})
        assert isinstance(part, StreamPart)

    def test_unknown_type_raises(self):
        with pytest.raises(ValueError, match="Unknown part type: invalid"):
            part_from_dict({"type": "invalid"})

    def test_missing_type_raises(self):
        with pytest.raises(ValueError, match="Unknown part type: "):
            part_from_dict({})


# ==================== SIPMessage 测试 ====================


class TestSIPMessageDefaults:
    def test_default_schema_version(self):
        msg = SIPMessage(sender_id="alice")
        assert msg.schema == "sip-msg/v1"

    def test_default_message_type(self):
        msg = SIPMessage(sender_id="alice")
        assert msg.message_type == MessageType.TEXT

    def test_default_recipient_type(self):
        msg = SIPMessage(sender_id="alice")
        assert msg.recipient_type == RecipientType.DIRECT

    def test_default_parts_empty(self):
        msg = SIPMessage(sender_id="alice")
        assert msg.parts == []

    def test_default_metadata(self):
        msg = SIPMessage(sender_id="alice")
        assert msg.metadata["priority"] == "normal"
        assert msg.metadata["ttl"] == 0
        assert msg.metadata["custom"] == {}

    def test_auto_generated_id(self):
        msg = SIPMessage(sender_id="alice")
        assert msg.id != ""
        assert len(msg.id) > 0

    def test_auto_generated_conversation_id(self):
        msg = SIPMessage(sender_id="alice")
        assert msg.conversation_id != ""
        assert msg.conversation_id != msg.id  # 应该是独立的UUID

    def test_optional_fields_none_by_default(self):
        msg = SIPMessage(sender_id="alice")
        assert msg.parent_id is None
        assert msg.task_id is None
        assert msg.recipient_id is None
        assert msg.recipient_group is None


class TestSIPMessageToDict:
    def test_basic_fields(self):
        msg = SIPMessage(sender_id="alice", recipient_id="bob")
        d = msg.to_dict()
        assert d["sender_id"] == "alice"
        assert d["recipient_id"] == "bob"
        assert d["schema"] == "sip-msg/v1"
        assert d["message_type"] == "text"
        assert d["recipient_type"] == "direct"

    def test_optional_fields_omitted_when_none(self):
        msg = SIPMessage(sender_id="alice")
        d = msg.to_dict()
        assert "parent_id" not in d
        assert "task_id" not in d
        assert "recipient_id" not in d
        assert "recipient_group" not in d

    def test_optional_fields_included_when_set(self):
        msg = SIPMessage(
            sender_id="alice", parent_id="p1", task_id="t1",
            recipient_id="bob", recipient_group="team-a",
        )
        d = msg.to_dict()
        assert d["parent_id"] == "p1"
        assert d["task_id"] == "t1"
        assert d["recipient_id"] == "bob"
        assert d["recipient_group"] == "team-a"

    def test_parts_serialized(self):
        msg = SIPMessage(
            sender_id="alice",
            parts=[TextPart(text="hello"), DataPart(data={"key": "val"})],
        )
        d = msg.to_dict()
        assert len(d["parts"]) == 2
        assert d["parts"][0] == {"type": "text", "text": "hello"}
        assert d["parts"][1]["type"] == "data"

    def test_metadata_included(self):
        msg = SIPMessage(sender_id="alice")
        d = msg.to_dict()
        assert d["metadata"]["priority"] == "normal"

    def test_timestamp_present(self):
        msg = SIPMessage(sender_id="alice")
        d = msg.to_dict()
        assert "timestamp" in d
        # ISO 8601 格式校验
        assert d["timestamp"].endswith("Z")


class TestSIPMessageFromDict:
    def test_basic_deserialization(self):
        data = {
            "id": "msg-1", "conversation_id": "conv-1", "schema": "sip-msg/v1",
            "message_type": "text", "sender_id": "alice", "recipient_type": "direct",
            "timestamp": "2025-01-01T00:00:00Z", "parts": [], "metadata": {},
        }
        msg = SIPMessage.from_dict(data)
        assert msg.id == "msg-1"
        assert msg.conversation_id == "conv-1"
        assert msg.message_type == MessageType.TEXT
        assert msg.sender_id == "alice"

    def test_parts_deserialized(self):
        data = {
            "id": "m1", "conversation_id": "c1", "schema": "sip-msg/v1",
            "message_type": "text", "sender_id": "a", "recipient_type": "direct",
            "timestamp": "2025-01-01T00:00:00Z",
            "parts": [{"type": "text", "text": "hi"}], "metadata": {},
        }
        msg = SIPMessage.from_dict(data)
        assert len(msg.parts) == 1
        assert isinstance(msg.parts[0], TextPart)
        assert msg.parts[0].text == "hi"

    def test_optional_fields_deserialized(self):
        data = {
            "id": "m1", "conversation_id": "c1", "schema": "sip-msg/v1",
            "message_type": "task_delegate", "sender_id": "a",
            "recipient_type": "group", "recipient_group": "dev-team",
            "parent_id": "p1", "task_id": "t1",
            "timestamp": "2025-01-01T00:00:00Z", "parts": [], "metadata": {},
        }
        msg = SIPMessage.from_dict(data)
        assert msg.parent_id == "p1"
        assert msg.task_id == "t1"
        assert msg.recipient_group == "dev-team"
        assert msg.message_type == MessageType.TASK_DELEGATE
        assert msg.recipient_type == RecipientType.GROUP

    def test_round_trip(self):
        original = SIPMessage(
            sender_id="alice", recipient_id="bob",
            parts=[TextPart(text="hello")],
            metadata={"priority": "high", "ttl": 60, "custom": {"key": "val"}},
        )
        d = original.to_dict()
        restored = SIPMessage.from_dict(d)
        assert restored.sender_id == original.sender_id
        assert restored.recipient_id == original.recipient_id
        assert restored.parts[0].text == original.parts[0].text
        assert restored.metadata["priority"] == "high"
        assert restored.metadata["ttl"] == 60


class TestCreateMessage:
    def test_basic_creation(self):
        msg = create_message(sender_id="alice", recipient_id="bob")
        assert msg.sender_id == "alice"
        assert msg.recipient_id == "bob"
        assert msg.recipient_type == RecipientType.DIRECT
        assert msg.message_type == MessageType.TEXT

    def test_with_parts(self):
        parts = [TextPart(text="hello"), DataPart(data=42)]
        msg = create_message(sender_id="alice", parts=parts)
        assert len(msg.parts) == 2

    def test_with_priority(self):
        msg = create_message(sender_id="alice", priority=Priority.URGENT)
        assert msg.metadata["priority"] == "urgent"

    def test_with_ttl(self):
        msg = create_message(sender_id="alice", ttl=300)
        assert msg.metadata["ttl"] == 300

    def test_with_reply_to(self):
        msg = create_message(sender_id="alice", reply_to="msg-123")
        assert msg.metadata["reply_to"] == "msg-123"

    def test_with_custom_metadata(self):
        msg = create_message(sender_id="alice", custom_metadata={"source": "cli"})
        assert msg.metadata["custom"]["source"] == "cli"

    def test_group_message(self):
        msg = create_message(sender_id="alice", recipient_type=RecipientType.GROUP, recipient_group="dev")
        assert msg.recipient_type == RecipientType.GROUP
        assert msg.recipient_group == "dev"

    def test_task_delegate_message(self):
        msg = create_message(
            sender_id="alice", recipient_id="bob",
            message_type=MessageType.TASK_DELEGATE, task_id="task-1",
        )
        assert msg.message_type == MessageType.TASK_DELEGATE
        assert msg.task_id == "task-1"

    def test_recipient_type_as_string(self):
        msg = create_message(sender_id="alice", recipient_type="group", recipient_group="dev")
        assert msg.recipient_type == RecipientType.GROUP

    def test_auto_generated_ids(self):
        msg = create_message(sender_id="alice")
        assert msg.id != ""
        assert msg.conversation_id != ""

    def test_no_reply_to_by_default(self):
        msg = create_message(sender_id="alice")
        assert "reply_to" not in msg.metadata


# ==================== 验证逻辑测试 ====================


class TestValidateMessage:
    def test_valid_message(self):
        msg = {
            "id": "m1", "conversation_id": "c1", "schema": "sip-msg/v1",
            "message_type": "text", "sender_id": "a", "recipient_type": "direct",
            "recipient_id": "b", "timestamp": "2025-01-01T00:00:00Z",
            "parts": [{"type": "text", "text": "hi"}],
        }
        errors = validate_message(msg)
        assert errors == []

    def test_missing_required_fields(self):
        errors = validate_message({})
        assert any("missing required field: id" in e for e in errors)
        assert any("missing required field: sender_id" in e for e in errors)
        assert any("missing required field: parts" in e for e in errors)

    def test_empty_parts(self):
        msg = {
            "id": "m1", "conversation_id": "c1", "schema": "sip-msg/v1",
            "message_type": "text", "sender_id": "a", "recipient_type": "direct",
            "timestamp": "2025-01-01T00:00:00Z", "parts": [],
        }
        errors = validate_message(msg)
        assert any("parts must not be empty" in e for e in errors)

    def test_direct_without_recipient_id(self):
        msg = {
            "id": "m1", "conversation_id": "c1", "schema": "sip-msg/v1",
            "message_type": "text", "sender_id": "a", "recipient_type": "direct",
            "timestamp": "2025-01-01T00:00:00Z",
            "parts": [{"type": "text", "text": "hi"}],
        }
        errors = validate_message(msg)
        assert any("DIRECT type requires recipient_id" in e for e in errors)

    def test_group_without_recipient_group(self):
        msg = {
            "id": "m1", "conversation_id": "c1", "schema": "sip-msg/v1",
            "message_type": "text", "sender_id": "a", "recipient_type": "group",
            "timestamp": "2025-01-01T00:00:00Z",
            "parts": [{"type": "text", "text": "hi"}],
        }
        errors = validate_message(msg)
        assert any("GROUP type requires recipient_group" in e for e in errors)

    def test_broadcast_no_extra_requirement(self):
        msg = {
            "id": "m1", "conversation_id": "c1", "schema": "sip-msg/v1",
            "message_type": "text", "sender_id": "a", "recipient_type": "broadcast",
            "timestamp": "2025-01-01T00:00:00Z",
            "parts": [{"type": "text", "text": "hi"}],
        }
        errors = validate_message(msg)
        # broadcast 不要求 recipient_id 或 recipient_group
        assert not any("requires" in e for e in errors)

    def test_valid_direct_message(self):
        msg = {
            "id": "m1", "conversation_id": "c1", "schema": "sip-msg/v1",
            "message_type": "text", "sender_id": "a", "recipient_type": "direct",
            "recipient_id": "b", "timestamp": "2025-01-01T00:00:00Z",
            "parts": [{"type": "text", "text": "hi"}],
        }
        errors = validate_message(msg)
        assert errors == []

    def test_valid_group_message(self):
        msg = {
            "id": "m1", "conversation_id": "c1", "schema": "sip-msg/v1",
            "message_type": "text", "sender_id": "a", "recipient_type": "group",
            "recipient_group": "dev-team", "timestamp": "2025-01-01T00:00:00Z",
            "parts": [{"type": "text", "text": "hi"}],
        }
        errors = validate_message(msg)
        assert errors == []


class TestValidateParts:
    def test_valid_parts(self):
        parts = [{"type": "text", "text": "hi"}, {"type": "data", "data": 42}]
        errors = validate_parts(parts)
        assert errors == []

    def test_empty_parts(self):
        errors = validate_parts([])
        assert errors == ["parts must not be empty"]

    def test_unknown_part_type_raises(self):
        with pytest.raises(ValueError, match="Unknown part type: invalid_type"):
            validate_parts([{"type": "invalid_type"}])

    def test_all_valid_types(self):
        valid = [
            {"type": "text"}, {"type": "data"}, {"type": "file_ref"},
            {"type": "file_data"}, {"type": "tool_request"},
            {"type": "tool_response"}, {"type": "context"}, {"type": "stream"},
        ]
        errors = validate_parts(valid)
        assert errors == []
