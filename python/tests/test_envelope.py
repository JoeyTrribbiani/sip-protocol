"""SIPEnvelope 信封数据类测试"""

import base64
import json

import pytest

from sip_protocol.schema.envelope import SIPEnvelope
from sip_protocol.schema.types import RecipientType


class TestEnvelopeDefaults:
    """默认值测试"""

    def test_minimal_creation(self):
        env = SIPEnvelope()
        assert env.id
        assert env.conversation_id
        assert env.sender_id == ""
        assert env.recipient_id is None
        assert env.recipient_group is None
        assert env.recipient_type == RecipientType.DIRECT
        assert env.timestamp
        assert env.schema == "sip-envelope/v1"
        assert env.content_type == "application/octet-stream"
        assert env.content_encoding == "identity"
        assert env.payload == b""
        assert env.headers == {}

    def test_no_parent_id_attribute(self):
        env = SIPEnvelope()
        assert not hasattr(
            env, "parent_id"
        ), "SIPEnvelope 不应有 parent_id — 消息引用关系属于 SIPMessage"

    def test_timestamp_format(self):
        env = SIPEnvelope()
        assert env.timestamp.endswith("Z")
        assert "T" in env.timestamp


class TestEnvelopeCreation:
    """带参数创建测试"""

    def test_creation_with_payload(self):
        env = SIPEnvelope(
            sender_id="alice",
            recipient_id="bob",
            payload=b"hello world",
        )
        assert env.sender_id == "alice"
        assert env.recipient_id == "bob"
        assert env.payload == b"hello world"

    def test_group_recipient(self):
        env = SIPEnvelope(
            recipient_group="team-alpha",
            recipient_type=RecipientType.GROUP,
        )
        assert env.recipient_group == "team-alpha"
        assert env.recipient_type == RecipientType.GROUP

    def test_broadcast_recipient(self):
        env = SIPEnvelope(recipient_type=RecipientType.BROADCAST)
        assert env.recipient_type == RecipientType.BROADCAST

    def test_content_encoding_gzip(self):
        env = SIPEnvelope(content_encoding="gzip")
        assert env.content_encoding == "gzip"

    def test_headers(self):
        env = SIPEnvelope(headers={"x-trace-id": "abc-123", "priority": "high"})
        assert env.headers == {"x-trace-id": "abc-123", "priority": "high"}


class TestEnvelopeToDict:
    """序列化测试"""

    def test_payload_is_base64_string(self):
        env = SIPEnvelope(payload=b"hello")
        d = env.to_dict()
        assert isinstance(d["payload"], str)
        assert d["payload"] == base64.b64encode(b"hello").decode("ascii")

    def test_optional_fields_omitted_when_none(self):
        env = SIPEnvelope()
        d = env.to_dict()
        assert "recipient_id" not in d
        assert "recipient_group" not in d

    def test_optional_fields_present_when_set(self):
        env = SIPEnvelope(
            recipient_id="bob",
            recipient_group="team",
        )
        d = env.to_dict()
        assert d["recipient_id"] == "bob"
        assert d["recipient_group"] == "team"

    def test_recipient_type_serialized_as_value(self):
        env = SIPEnvelope(recipient_type=RecipientType.GROUP)
        d = env.to_dict()
        assert d["recipient_type"] == "group"


class TestEnvelopeFromDict:
    """反序列化测试"""

    def test_roundtrip_preserves_bytes(self):
        original = SIPEnvelope(
            sender_id="alice",
            payload=b"\x00\x01\x02\xff",
            content_type="application/json",
        )
        d = original.to_dict()
        recovered = SIPEnvelope.from_dict(d)
        assert recovered.sender_id == "alice"
        assert recovered.payload == b"\x00\x01\x02\xff"
        assert recovered.content_type == "application/json"

    def test_empty_payload_roundtrip(self):
        original = SIPEnvelope()
        d = original.to_dict()
        recovered = SIPEnvelope.from_dict(d)
        assert recovered.payload == b""

    def test_binary_payload_roundtrip(self):
        binary_data = bytes(range(256))
        original = SIPEnvelope(payload=binary_data)
        d = original.to_dict()
        recovered = SIPEnvelope.from_dict(d)
        assert recovered.payload == binary_data

    def test_preserves_content_encoding(self):
        original = SIPEnvelope(content_encoding="gzip")
        d = original.to_dict()
        recovered = SIPEnvelope.from_dict(d)
        assert recovered.content_encoding == "gzip"

    def test_preserves_headers(self):
        original = SIPEnvelope(headers={"x-custom": "value"})
        d = original.to_dict()
        recovered = SIPEnvelope.from_dict(d)
        assert recovered.headers == {"x-custom": "value"}

    def test_preserves_recipient_type(self):
        original = SIPEnvelope(recipient_type=RecipientType.BROADCAST)
        d = original.to_dict()
        recovered = SIPEnvelope.from_dict(d)
        assert recovered.recipient_type == RecipientType.BROADCAST


class TestEnvelopeJson:
    """JSON 序列化测试"""

    def test_to_json_returns_bytes(self):
        env = SIPEnvelope(payload=b"hello")
        raw = env.to_json()
        assert isinstance(raw, bytes)
        parsed = json.loads(raw)
        assert parsed["payload"] == base64.b64encode(b"hello").decode("ascii")

    def test_from_json_roundtrip(self):
        original = SIPEnvelope(
            sender_id="alice",
            recipient_id="bob",
            payload=b"binary data here",
            headers={"key": "val"},
        )
        raw = original.to_json()
        recovered = SIPEnvelope.from_json(raw)
        assert recovered.sender_id == "alice"
        assert recovered.recipient_id == "bob"
        assert recovered.payload == b"binary data here"
        assert recovered.headers == {"key": "val"}

    def test_json_roundtrip_with_binary_payload(self):
        binary_data = b"\x00\xff\x80\x7f\x01\xfe"
        original = SIPEnvelope(payload=binary_data, content_encoding="deflate")
        raw = original.to_json()
        recovered = SIPEnvelope.from_json(raw)
        assert recovered.payload == binary_data
        assert recovered.content_encoding == "deflate"

    def test_invalid_json_raises_error(self):
        with pytest.raises(json.JSONDecodeError):
            SIPEnvelope.from_json(b"not valid json {{{")


class TestEnvelopeSchemaField:
    """schema 字段测试"""

    def test_default_schema(self):
        env = SIPEnvelope()
        assert env.schema == "sip-envelope/v1"

    def test_custom_schema(self):
        env = SIPEnvelope(schema="sip-envelope/v2")
        assert env.schema == "sip-envelope/v2"
        d = env.to_dict()
        assert d["schema"] == "sip-envelope/v2"
