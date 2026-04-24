"""群组 Double Ratchet 正确性测试"""

import json

import pytest

from sip_protocol.crypto.hkdf import hkdf
from sip_protocol.protocol.group import CHAIN_KEY_LENGTH, GroupManager, MESSAGE_KEY_LENGTH


def _make_manager(group_id: str = "test-group", root_key: bytes = b"x" * 32) -> GroupManager:
    return GroupManager(group_id=group_id, root_key=root_key)


class TestChainKeyAdvancement:
    def test_chain_key_advances_on_send(self):
        """发送消息后 chain_key 必须改变"""
        mgr = _make_manager()
        chain = {"chain_key": b"a" * CHAIN_KEY_LENGTH, "message_number": 0}
        _, updated = mgr.send_group_message("hello", chain, "alice")
        assert updated["chain_key"] != chain["chain_key"]
        assert updated["message_number"] == 1

    def test_chain_key_advances_on_receive(self):
        """接收消息后 chain_key 必须改变"""
        mgr = _make_manager()
        chain = {"chain_key": b"a" * CHAIN_KEY_LENGTH, "message_number": 0}
        msg, _ = mgr.send_group_message("hello", chain, "alice")
        recv_chain = {"chain_key": chain["chain_key"], "message_number": 0, "skip_keys": {}}
        _, updated = mgr.receive_group_message(msg, recv_chain, "alice")
        assert updated["chain_key"] != chain["chain_key"]
        assert updated["message_number"] == 1

    def test_different_chain_keys_produce_different_message_keys(self):
        """不同 chain_key 派生不同的 message_key"""
        key_a = hkdf(b"a" * CHAIN_KEY_LENGTH, b"", b"message-key", MESSAGE_KEY_LENGTH)
        key_b = hkdf(b"b" * CHAIN_KEY_LENGTH, b"", b"message-key", MESSAGE_KEY_LENGTH)
        assert key_a != key_b

    def test_send_receive_round_trip(self):
        """发送→接收 端到端正确"""
        mgr = _make_manager()
        send_chain = {"chain_key": b"initial" * 8, "message_number": 0}

        msg, new_send_chain = mgr.send_group_message("secret data", send_chain, "alice")

        # 接收方使用相同的初始 chain_key
        recv_chain = {"chain_key": send_chain["chain_key"], "message_number": 0, "skip_keys": {}}
        plaintext, new_recv_chain = mgr.receive_group_message(msg, recv_chain, "alice")

        assert plaintext == "secret data"
        assert new_recv_chain["chain_key"] == new_send_chain["chain_key"]

    def test_consecutive_messages_use_different_keys(self):
        """连续两条消息使用不同的 message_key"""
        mgr = _make_manager()
        chain = {"chain_key": b"initial" * 8, "message_number": 0}

        msg1, chain1 = mgr.send_group_message("msg1", chain, "alice")
        msg2, chain2 = mgr.send_group_message("msg2", chain1, "alice")

        assert chain1["chain_key"] != chain["chain_key"]
        assert chain2["chain_key"] != chain1["chain_key"]

    def test_three_message_round_trip(self):
        """三条消息连续发送接收"""
        mgr = _make_manager()
        send_chain = {"chain_key": b"init" * 8, "message_number": 0}

        messages = []
        for i in range(3):
            msg, send_chain = mgr.send_group_message(f"message-{i}", send_chain, "alice")
            messages.append(msg)

        recv_chain = {"chain_key": b"init" * 8, "message_number": 0, "skip_keys": {}}
        for i, msg in enumerate(messages):
            plaintext, recv_chain = mgr.receive_group_message(msg, recv_chain, "alice")
            assert plaintext == f"message-{i}"


class TestSkipRatchet:
    def test_skip_ratchet_handles_gap_of_one(self):
        """跳过一条消息后仍能正确解密"""
        mgr = _make_manager()
        send_chain = {"chain_key": b"init" * 8, "message_number": 0}

        # 发送 msg0, msg1, msg2
        msg0, send_chain = mgr.send_group_message("msg0", send_chain, "alice")
        msg1, send_chain = mgr.send_group_message("msg1", send_chain, "alice")
        msg2, _ = mgr.send_group_message("msg2", send_chain, "alice")

        # 接收端只收 msg0 和 msg2（跳过 msg1）
        recv_chain = {"chain_key": b"init" * 8, "message_number": 0, "skip_keys": {}}
        pt0, recv_chain = mgr.receive_group_message(msg0, recv_chain, "alice")
        assert pt0 == "msg0"

        # 跳过 msg1，直接收 msg2
        pt2, recv_chain = mgr.receive_group_message(msg2, recv_chain, "alice")
        assert pt2 == "msg2"
        assert recv_chain["message_number"] == 3

    def test_in_order_after_skip(self):
        """跳过后继续按序接收"""
        mgr = _make_manager()
        send_chain = {"chain_key": b"init" * 8, "message_number": 0}

        msg0, send_chain = mgr.send_group_message("m0", send_chain, "alice")
        msg1, send_chain = mgr.send_group_message("m1", send_chain, "alice")
        msg2, send_chain = mgr.send_group_message("m2", send_chain, "alice")
        msg3, _ = mgr.send_group_message("m3", send_chain, "alice")

        recv_chain = {"chain_key": b"init" * 8, "message_number": 0, "skip_keys": {}}
        _, recv_chain = mgr.receive_group_message(msg0, recv_chain, "alice")
        _, recv_chain = mgr.receive_group_message(msg2, recv_chain, "alice")  # skip msg1
        pt3, recv_chain = mgr.receive_group_message(
            msg3, recv_chain, "alice"
        )  # in-order after skip
        assert pt3 == "m3"


class TestAddMemberChainKeys:
    def test_add_member_creates_ratchet_chains(self):
        """add_member 创建的链支持 ratcheting"""
        mgr = _make_manager()
        mgr.add_member("bob")
        bob = mgr.members["bob"]

        chain = bob["sending_chain"]
        msg, new_chain = mgr.send_group_message("hello", chain, "bob")
        assert new_chain["chain_key"] != chain["chain_key"]

    def test_different_members_different_initial_chain_keys(self):
        """不同成员的初始 chain_key 不同"""
        mgr = _make_manager()
        mgr.add_member("alice")
        mgr.add_member("bob")

        assert (
            mgr.members["alice"]["sending_chain"]["chain_key"]
            != mgr.members["bob"]["sending_chain"]["chain_key"]
        )


class TestInitializeGroupChains:
    def test_initialize_creates_ratchet_compatible_chains(self):
        """initialize_group_chains 创建支持 ratcheting 的链"""
        mgr = _make_manager()
        chains = mgr.initialize_group_chains(["alice", "bob"], b"root" * 8)

        alice_send = chains["alice"]["sending_chain"]
        msg, new_chain = mgr.send_group_message("test", alice_send, "alice")
        assert new_chain["chain_key"] != alice_send["chain_key"]
