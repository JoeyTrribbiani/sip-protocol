#!/usr/bin/env python3
"""
group.py 补充覆盖率测试
覆盖 parse_group_message、validate_group_message_signature、
remove_member 错误路径、add_member 重复路径、is_admin 边界等
"""

import sys
import os
import json
import base64
import hmac
import hashlib
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sip_protocol.protocol.group import GroupManager, GROUP_PROTOCOL_VERSION
from sip_protocol.crypto.hkdf import hkdf


def _make_auth_key():
    return hkdf(b"auth", b"", b"auth-key", 32)


def _make_group(**kwargs):
    defaults = {
        "group_id": "g1",
        "root_key": hkdf(b"root", b"", b"root-key", 32),
        "admin_id": "admin",
    }
    defaults.update(kwargs)
    return GroupManager(**defaults)


def _sign(data: bytes, key: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


class TestParseGroupMessage:
    """parse_group_message 错误路径"""

    def test_invalid_version(self):
        gm = _make_group()
        msg = json.dumps({"version": "BAD", "type": "group_init"})
        try:
            gm.parse_group_message(msg)
            assert False, "Should have raised"
        except ValueError as e:
            assert "Invalid version" in str(e)

    def test_missing_type(self):
        gm = _make_group()
        msg = json.dumps({"version": GROUP_PROTOCOL_VERSION})
        try:
            gm.parse_group_message(msg)
            assert False, "Should have raised"
        except ValueError as e:
            assert "Missing message type" in str(e)

    def test_valid_message(self):
        gm = _make_group()
        msg = json.dumps(
            {
                "version": GROUP_PROTOCOL_VERSION,
                "type": "group_init",
                "data": "test",
            }
        )
        parsed = gm.parse_group_message(msg)
        assert parsed["type"] == "group_init"


class TestValidateGroupMessageSignature:
    """validate_group_message_signature 所有消息类型"""

    def _make_signed_message(self, msg_type, extra_fields, sender_id, auth_key):
        data_str = ":".join(str(v) for v in extra_fields) + ":"
        data = data_str.encode()
        sig = _sign(data, auth_key)
        msg = {
            "version": GROUP_PROTOCOL_VERSION,
            "type": msg_type,
            "signature": base64.b64encode(sig).decode(),
        }
        return msg, sig

    def test_empty_signature_returns_false(self):
        gm = _make_group()
        msg = {"type": "group_init", "signature": ""}
        assert gm.validate_group_message_signature(msg, b"key", "sender") is False

    def test_no_signature_key_returns_false(self):
        gm = _make_group()
        msg = {"type": "group_init"}
        assert gm.validate_group_message_signature(msg, b"key", "sender") is False

    def test_group_init_valid(self):
        gm = _make_group()
        auth_key = _make_auth_key()
        sender_id = "admin"
        data = f"{sender_id}:g1:{sender_id}:".encode()
        sig = _sign(data, auth_key)
        msg = {
            "type": "group_init",
            "group_id": "g1",
            "admin_id": sender_id,
            "signature": base64.b64encode(sig).decode(),
        }
        assert gm.validate_group_message_signature(msg, auth_key, sender_id) is True

    def test_group_init_wrong_key(self):
        gm = _make_group()
        auth_key = _make_auth_key()
        wrong_key = hkdf(b"wrong", b"", b"wrong-key", 32)
        sender_id = "admin"
        data = f"{sender_id}:g1:{sender_id}:".encode()
        sig = _sign(data, auth_key)
        msg = {
            "type": "group_init",
            "group_id": "g1",
            "admin_id": sender_id,
            "signature": base64.b64encode(sig).decode(),
        }
        assert gm.validate_group_message_signature(msg, wrong_key, sender_id) is False

    def test_group_join_ack_valid(self):
        gm = _make_group()
        auth_key = _make_auth_key()
        sender_id = "user1"
        data = f"{sender_id}:admin:g1:".encode()
        sig = _sign(data, auth_key)
        msg = {
            "type": "group_join_ack",
            "recipient_id": "admin",
            "group_id": "g1",
            "signature": base64.b64encode(sig).decode(),
        }
        assert gm.validate_group_message_signature(msg, auth_key, sender_id) is True

    def test_group_chain_key_valid(self):
        gm = _make_group()
        auth_key = _make_auth_key()
        sender_id = "admin"
        data = f"{sender_id}:user1:g1:".encode()
        sig = _sign(data, auth_key)
        msg = {
            "type": "group_chain_key",
            "recipient_id": "user1",
            "group_id": "g1",
            "signature": base64.b64encode(sig).decode(),
        }
        assert gm.validate_group_message_signature(msg, auth_key, sender_id) is True

    def test_group_chain_key_ack_valid(self):
        gm = _make_group()
        auth_key = _make_auth_key()
        sender_id = "user1"
        data = f"{sender_id}:admin:g1:".encode()
        sig = _sign(data, auth_key)
        msg = {
            "type": "group_chain_key_ack",
            "recipient_id": "admin",
            "group_id": "g1",
            "signature": base64.b64encode(sig).decode(),
        }
        assert gm.validate_group_message_signature(msg, auth_key, sender_id) is True

    def test_group_add_member_valid(self):
        gm = _make_group()
        auth_key = _make_auth_key()
        sender_id = "admin"
        data = f"{sender_id}:g1:user2:".encode()
        sig = _sign(data, auth_key)
        msg = {
            "type": "group_add_member",
            "group_id": "g1",
            "new_member": "user2",
            "signature": base64.b64encode(sig).decode(),
        }
        assert gm.validate_group_message_signature(msg, auth_key, sender_id) is True

    def test_group_join_request_valid(self):
        gm = _make_group()
        auth_key = _make_auth_key()
        sender_id = "user2"
        data = f"{sender_id}:admin:g1:".encode()
        sig = _sign(data, auth_key)
        msg = {
            "type": "group_join_request",
            "recipient_id": "admin",
            "group_id": "g1",
            "signature": base64.b64encode(sig).decode(),
        }
        assert gm.validate_group_message_signature(msg, auth_key, sender_id) is True

    def test_group_leave_valid(self):
        gm = _make_group()
        auth_key = _make_auth_key()
        sender_id = "user1"
        data = f"{sender_id}:g1:".encode()
        sig = _sign(data, auth_key)
        msg = {
            "type": "group_leave",
            "group_id": "g1",
            "signature": base64.b64encode(sig).decode(),
        }
        assert gm.validate_group_message_signature(msg, auth_key, sender_id) is True

    def test_group_leave_ack_valid(self):
        gm = _make_group()
        auth_key = _make_auth_key()
        sender_id = "admin"
        data = f"{sender_id}:user1:g1:".encode()
        sig = _sign(data, auth_key)
        msg = {
            "type": "group_leave_ack",
            "recipient_id": "user1",
            "group_id": "g1",
            "signature": base64.b64encode(sig).decode(),
        }
        assert gm.validate_group_message_signature(msg, auth_key, sender_id) is True

    def test_unknown_type_returns_false(self):
        gm = _make_group()
        auth_key = _make_auth_key()
        sig = _sign(b"data", auth_key)
        msg = {
            "type": "unknown_type",
            "signature": base64.b64encode(sig).decode(),
        }
        assert gm.validate_group_message_signature(msg, auth_key, "sender") is False


class TestAddMemberErrors:
    """add_member 错误路径"""

    def test_add_duplicate_member_raises(self):
        gm = _make_group()
        gm.add_member("user1")
        try:
            gm.add_member("user1")
            assert False, "Should have raised"
        except ValueError as e:
            assert "already exists" in str(e)

    def test_add_member_with_public_key(self):
        gm = _make_group()
        pub = os.urandom(32)
        gm.add_member("user1", public_key=pub)
        member = gm.members["user1"]
        assert member["public_key"] == base64.b64encode(pub).decode()

    def test_add_member_without_public_key(self):
        gm = _make_group()
        gm.add_member("user1")
        assert gm.members["user1"]["public_key"] == ""

    def test_add_member_with_admin_role(self):
        gm = _make_group()
        gm.add_member("user1", role="admin")
        assert gm.members["user1"]["role"] == "admin"

    def test_add_member_default_role(self):
        gm = _make_group()
        gm.add_member("user1")
        assert gm.members["user1"]["role"] == "member"

    def test_add_member_has_chain_keys(self):
        gm = _make_group()
        gm.add_member("user1")
        member = gm.members["user1"]
        assert "sending_chain" in member
        assert "receiving_chain" in member
        assert member["sending_chain"]["message_number"] == 0
        assert member["receiving_chain"]["message_number"] == 0


class TestRemoveMemberErrors:
    """remove_member 错误路径"""

    def test_remove_nonexistent_member_raises(self):
        gm = _make_group()
        try:
            gm.remove_member("ghost")
            assert False, "Should have raised"
        except ValueError as e:
            assert "not found" in str(e)

    def test_remove_member_updates_remaining_chains(self):
        gm = _make_group()
        gm.add_member("user1")
        gm.add_member("user2")
        old_user1_sending = gm.members["user1"]["sending_chain"]["chain_key"]
        gm.remove_member("user2")
        new_user1_sending = gm.members["user1"]["sending_chain"]["chain_key"]
        assert old_user1_sending != new_user1_sending


class TestIsAdmin:
    """is_admin 边界测试"""

    def test_admin_id_matches(self):
        gm = _make_group(admin_id="boss")
        assert gm.is_admin("boss") is True

    def test_member_with_admin_role(self):
        gm = _make_group(admin_id="boss")
        gm.add_member("delegated", role="admin")
        assert gm.is_admin("delegated") is True

    def test_regular_member_is_not_admin(self):
        gm = _make_group(admin_id="boss")
        gm.add_member("peasant", role="member")
        assert gm.is_admin("peasant") is False

    def test_non_member_is_not_admin(self):
        gm = _make_group(admin_id="boss")
        assert gm.is_admin("stranger") is False


class TestInitializeGroupChains:
    """initialize_group_chains 补充测试"""

    def test_empty_members(self):
        gm = _make_group()
        chains = gm.initialize_group_chains([], gm.root_key)
        assert chains == {}

    def test_chains_have_correct_structure(self):
        gm = _make_group()
        members = ["a", "b"]
        chains = gm.initialize_group_chains(members, gm.root_key)
        for m in members:
            assert "sending_chain" in chains[m]
            assert "receiving_chain" in chains[m]
            assert chains[m]["sending_chain"]["message_number"] == 0
            assert "skip_keys" in chains[m]["receiving_chain"]


class TestGroupMessageCreateEdgeCases:
    """创建消息的边界情况"""

    def test_group_init_without_signature(self):
        gm = _make_group()
        msg_json = gm.create_group_init_message(
            sender_id="admin",
            members=["a"],
            group_name="test",
        )
        msg = json.loads(msg_json)
        assert msg["signature"] == ""

    def test_group_error_without_details(self):
        gm = _make_group()
        msg_json = gm.create_group_error_message(
            error_code="ERR",
            error_message="something broke",
        )
        msg = json.loads(msg_json)
        assert msg["error_details"] == {}

    def test_group_error_with_details(self):
        gm = _make_group()
        msg_json = gm.create_group_error_message(
            error_code="ERR",
            error_message="bad",
            error_details={"foo": "bar"},
        )
        msg = json.loads(msg_json)
        assert msg["error_details"]["foo"] == "bar"

    def test_chain_key_message_with_skip_keys(self):
        gm = _make_group()
        chain_key = os.urandom(32)
        sending_chain = {"chain_key": chain_key, "message_number": 5}
        receiving_chain = {
            "chain_key": chain_key,
            "message_number": 3,
            "skip_keys": {1: os.urandom(32), 2: os.urandom(32)},
        }
        sig = os.urandom(32)
        msg_json = gm.create_group_chain_key_message(
            sender_id="admin",
            recipient_id="user1",
            sending_chain=sending_chain,
            receiving_chain=receiving_chain,
            signature=sig,
        )
        msg = json.loads(msg_json)
        assert msg["sending_chain"]["message_number"] == 5
        assert len(msg["receiving_chain"]["skip_keys"]) == 2


class TestReceiveGroupMessageErrors:
    """receive_group_message 错误路径"""

    def test_invalid_signature_raises(self):
        gm = _make_group()

        # 发送方和接收方使用同一 chain_key（群组共享链）
        shared_key = hkdf(b"shared", b"", b"shared-chain", 32)
        send_chain = {"chain_key": shared_key, "message_number": 0}
        recv_chain = {"chain_key": shared_key, "message_number": 0, "skip_keys": {}}

        msg_json, _ = gm.send_group_message("hello", send_chain, "alice")

        # 篡改签名
        msg = json.loads(msg_json)
        msg["sender_signature"] = base64.b64encode(os.urandom(32)).decode()
        tampered_json = json.dumps(msg)

        try:
            gm.receive_group_message(tampered_json, recv_chain, "alice")
            assert False, "Should have raised"
        except ValueError as e:
            assert "Invalid sender signature" in str(e)


class TestUpdateGroupRootKey:
    """update_group_root_key 测试"""

    def test_updates_root_key(self):
        gm = _make_group()
        old_key = gm.root_key
        new_pub = os.urandom(32)
        new_key = gm.update_group_root_key(old_key, new_pub)
        assert new_key != old_key
        assert gm.root_key == new_key

    def test_update_root_key_after_leave(self):
        gm = _make_group()
        old_key = gm.root_key
        new_key = gm.update_root_key_after_leave(old_key)
        assert new_key != old_key
        assert gm.root_key == new_key


class TestSendReceiveGroupMultipleMessages:
    """多消息发送接收覆盖（Double Ratchet）"""

    def test_sequential_messages_same_sender(self):
        gm = _make_group()

        # 群组共享链：发送方和接收方使用同一 chain_key
        shared_key = hkdf(b"shared-seq", b"", b"shared-chain", 32)
        send_chain = {"chain_key": shared_key, "message_number": 0}
        recv_chain = {"chain_key": shared_key, "message_number": 0, "skip_keys": {}}

        for i in range(5):
            plaintext = f"msg-{i}"
            msg_json, send_chain = gm.send_group_message(
                plaintext, send_chain, "alice"
            )
            decrypted, recv_chain = gm.receive_group_message(
                msg_json, recv_chain, "alice"
            )
            assert decrypted == plaintext

    def test_interleaved_senders(self):
        gm = _make_group()
        members = ["alice", "bob", "carol"]

        for sender in members:
            plaintext = f"hello from {sender}"

            # 每个发送者使用独立共享链
            sender_key = hkdf(f"{sender}-key".encode(), b"", b"sender-chain", 32)
            send_chain = {"chain_key": sender_key, "message_number": 0}

            msg_json, _ = gm.send_group_message(
                plaintext, send_chain, sender
            )

            for receiver in members:
                if receiver == sender:
                    continue
                recv_chain = {"chain_key": sender_key, "message_number": 0, "skip_keys": {}}
                decrypted, _ = gm.receive_group_message(
                    msg_json, recv_chain, sender
                )
                assert decrypted == plaintext
