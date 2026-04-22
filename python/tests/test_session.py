#!/usr/bin/env python3
"""
SessionState 测试模块
覆盖 serialize / deserialize / update_last_activity 及边界情况
"""

import sys
import os
import json
import base64
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sip_protocol.managers.session import SessionState, PROTOCOL_VERSION


class TestSessionStateInit:
    """SessionState 初始化测试"""

    def test_default_values(self):
        state = SessionState()
        assert state.version == PROTOCOL_VERSION
        assert state.agent_id == ""
        assert state.remote_agent_id == ""
        assert state.remote_public_key == ""
        assert state.encryption_key == ""
        assert state.auth_key == ""
        assert state.replay_key == ""
        assert state.message_counter == 0
        assert state.psk_hash == ""
        assert state.salt == ""
        assert state.local_nonce == ""
        assert state.remote_nonce == ""
        assert state.created_at > 0
        assert state.last_activity_at > 0

    def test_created_at_is_millis(self):
        before = int(time.time() * 1000)
        state = SessionState()
        after = int(time.time() * 1000)
        assert before <= state.created_at <= after


class TestSessionStateSerialize:
    """SessionState 序列化测试"""

    def test_serialize_returns_base64_json(self):
        state = SessionState()
        serialized = state.serialize()
        # Should be valid base64
        decoded = base64.b64decode(serialized)
        # Should be valid JSON
        data = json.loads(decoded)
        assert data["version"] == PROTOCOL_VERSION

    def test_serialize_string_keys(self):
        state = SessionState()
        state.encryption_key = ""
        state.auth_key = ""
        state.replay_key = ""
        state.psk_hash = ""
        state.salt = ""
        serialized = state.serialize()
        data = json.loads(base64.b64decode(serialized))
        assert data["encryption_key"] == ""
        assert data["auth_key"] == ""
        assert data["replay_key"] == ""
        assert data["psk_hash"] == ""
        assert data["salt"] == ""

    def test_serialize_bytes_keys(self):
        state = SessionState()
        state.encryption_key = b"\x01\x02\x03"
        state.auth_key = b"\x04\x05\x06"
        state.replay_key = b"\x07\x08\x09"
        state.psk_hash = b"\x0a\x0b\x0c"
        state.salt = b"\x0d\x0e\x0f"
        serialized = state.serialize()
        data = json.loads(base64.b64decode(serialized))
        # bytes should be base64-encoded
        assert base64.b64decode(data["encryption_key"]) == b"\x01\x02\x03"
        assert base64.b64decode(data["auth_key"]) == b"\x04\x05\x06"
        assert base64.b64decode(data["replay_key"]) == b"\x07\x08\x09"
        assert base64.b64decode(data["psk_hash"]) == b"\x0a\x0b\x0c"
        assert base64.b64decode(data["salt"]) == b"\x0d\x0e\x0f"

    def test_serialize_preserves_counter(self):
        state = SessionState()
        state.message_counter = 42
        serialized = state.serialize()
        data = json.loads(base64.b64decode(serialized))
        assert data["message_counter"] == 42

    def test_serialize_preserves_agent_ids(self):
        state = SessionState()
        state.agent_id = "agent-alice"
        state.remote_agent_id = "agent-bob"
        serialized = state.serialize()
        data = json.loads(base64.b64decode(serialized))
        assert data["agent_id"] == "agent-alice"
        assert data["remote_agent_id"] == "agent-bob"

    def test_serialize_preserves_nonces(self):
        state = SessionState()
        state.local_nonce = "local-nonce-val"
        state.remote_nonce = "remote-nonce-val"
        serialized = state.serialize()
        data = json.loads(base64.b64decode(serialized))
        assert data["local_nonce"] == "local-nonce-val"
        assert data["remote_nonce"] == "remote-nonce-val"

    def test_serialize_preserves_timestamps(self):
        state = SessionState()
        state.created_at = 1000000
        state.last_activity_at = 2000000
        serialized = state.serialize()
        data = json.loads(base64.b64decode(serialized))
        assert data["created_at"] == 1000000
        assert data["last_activity_at"] == 2000000


class TestSessionStateDeserialize:
    """SessionState 反序列化测试"""

    def test_roundtrip_string_keys(self):
        state = SessionState()
        state.agent_id = "alice"
        state.remote_agent_id = "bob"
        state.remote_public_key = "pub-key"
        state.message_counter = 10
        state.local_nonce = "ln"
        state.remote_nonce = "rn"

        serialized = state.serialize()
        restored = SessionState.deserialize(serialized)

        assert restored.version == state.version
        assert restored.agent_id == "alice"
        assert restored.remote_agent_id == "bob"
        assert restored.remote_public_key == "pub-key"
        assert restored.message_counter == 10
        assert restored.local_nonce == "ln"
        assert restored.remote_nonce == "rn"

    def test_roundtrip_bytes_keys(self):
        state = SessionState()
        state.encryption_key = os.urandom(32)
        state.auth_key = os.urandom(32)
        state.replay_key = os.urandom(32)
        state.psk_hash = os.urandom(32)
        state.salt = os.urandom(16)

        serialized = state.serialize()
        restored = SessionState.deserialize(serialized)

        assert restored.encryption_key == state.encryption_key
        assert restored.auth_key == state.auth_key
        assert restored.replay_key == state.replay_key
        assert restored.psk_hash == state.psk_hash
        assert restored.salt == state.salt

    def test_deserialize_from_raw_dict(self):
        """Manually construct serialized data and deserialize"""
        state_dict = {
            "version": PROTOCOL_VERSION,
            "agent_id": "a",
            "remote_agent_id": "b",
            "remote_public_key": "pk",
            "encryption_key": base64.b64encode(b"ek").decode(),
            "auth_key": base64.b64encode(b"ak").decode(),
            "replay_key": base64.b64encode(b"rk").decode(),
            "message_counter": 5,
            "psk_hash": base64.b64encode(b"ph").decode(),
            "salt": base64.b64encode(b"sl").decode(),
            "local_nonce": "ln",
            "remote_nonce": "rn",
            "created_at": 1000,
            "last_activity_at": 2000,
        }
        json_str = json.dumps(state_dict)
        serialized = base64.b64encode(json_str.encode()).decode()

        restored = SessionState.deserialize(serialized)
        assert restored.encryption_key == b"ek"
        assert restored.auth_key == b"ak"
        assert restored.replay_key == b"rk"
        assert restored.psk_hash == b"ph"
        assert restored.salt == b"sl"
        assert restored.message_counter == 5

    def test_deserialize_non_base64_keys_passthrough(self):
        """If encryption_key is not a string, it passes through unchanged"""
        state_dict = {
            "version": PROTOCOL_VERSION,
            "agent_id": "",
            "remote_agent_id": "",
            "remote_public_key": "",
            "encryption_key": 12345,  # not a str, not bytes
            "auth_key": 99999,
            "replay_key": None,
            "message_counter": 0,
            "psk_hash": None,
            "salt": None,
            "local_nonce": "",
            "remote_nonce": "",
            "created_at": 0,
            "last_activity_at": 0,
        }
        json_str = json.dumps(state_dict)
        serialized = base64.b64encode(json_str.encode()).decode()

        restored = SessionState.deserialize(serialized)
        assert restored.encryption_key == 12345
        assert restored.auth_key == 99999
        assert restored.replay_key is None
        assert restored.psk_hash is None
        assert restored.salt is None


class TestSessionStateUpdateActivity:
    """update_last_activity 测试"""

    def test_updates_timestamp(self):
        state = SessionState()
        old_ts = state.last_activity_at
        time.sleep(0.01)
        state.update_last_activity()
        assert state.last_activity_at >= old_ts

    def test_does_not_change_created_at(self):
        state = SessionState()
        created = state.created_at
        state.update_last_activity()
        assert state.created_at == created


class TestSessionStateRoundtrip:
    """完整序列化-反序列化往返测试"""

    def test_full_roundtrip_with_all_fields(self):
        state = SessionState()
        state.agent_id = "agent-1"
        state.remote_agent_id = "agent-2"
        state.remote_public_key = "remote-pk"
        state.encryption_key = os.urandom(32)
        state.auth_key = os.urandom(32)
        state.replay_key = os.urandom(32)
        state.message_counter = 99
        state.psk_hash = os.urandom(32)
        state.salt = os.urandom(16)
        state.local_nonce = "lnonce"
        state.remote_nonce = "rnonce"

        restored = SessionState.deserialize(state.serialize())

        assert restored.agent_id == "agent-1"
        assert restored.remote_agent_id == "agent-2"
        assert restored.remote_public_key == "remote-pk"
        assert restored.encryption_key == state.encryption_key
        assert restored.auth_key == state.auth_key
        assert restored.replay_key == state.replay_key
        assert restored.message_counter == 99
        assert restored.psk_hash == state.psk_hash
        assert restored.salt == state.salt
        assert restored.local_nonce == "lnonce"
        assert restored.remote_nonce == "rnonce"
        assert restored.created_at == state.created_at
        assert restored.last_activity_at == state.last_activity_at
