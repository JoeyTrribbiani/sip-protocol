"""SIP 消息 Schema 类型系统测试"""

import pytest
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
