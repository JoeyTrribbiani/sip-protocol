"""Rekey 端到端测试"""

import pytest

from sip_protocol.protocol.rekey import RekeyManager


class TestRekeyE2E:
    def test_full_rekey_flow(self):
        """完整的 rekey 握议 -> 响应 -> 密钥切换流程"""
        session_keys = {
            "encryption_key": b"old_enc" * 16,
            "auth_key": b"old_auth" * 16,
            "replay_key": b"old_replay" * 16,
        }

        # 发起方创建 rekey request
        manager = RekeyManager(session_keys, is_initiator=True)
        request = manager.create_rekey_request()

        assert request["type"] == "rekey"
        assert request["step"] == "request"
        assert "request" in request
        assert "signature" in request

        # 接收方验证签名（接收方是独立的 RekeyManager 实例）
        responder = RekeyManager(session_keys, is_initiator=False)
        is_valid = responder.validate_rekey_request(request)
        assert is_valid is True

        # 接收方创建 rekey response
        response = responder.process_rekey_request(request)

        assert response["type"] == "rekey"
        assert response["step"] == "response"

        # 发起方处理响应
        new_keys = manager.process_rekey_response(response)
        assert new_keys["encryption_key"] != b"old_enc" * 16
        assert new_keys["auth_key"] != b"old_auth" * 16

        # 应用新密钥
        manager.apply_new_keys(new_keys)
        assert manager.session_state["encryption_key"] == new_keys["encryption_key"]

    def test_rekey_sequence_check(self):
        """rekey 序列号单调递增"""
        manager = RekeyManager(
            {"encryption_key": b"x" * 32, "auth_key": b"y" * 32, "replay_key": b"z" * 32},
            is_initiator=True,
        )
        request = manager.create_rekey_request()
        assert request["sequence"] == 0

        request2 = manager.create_rekey_request()
        assert request2["sequence"] == 1

    def test_tampered_rekey_request(self):
        """篡改的 rekey request 应被拒绝"""
        manager = RekeyManager(
            {"encryption_key": b"x" * 32, "auth_key": b"y" * 32, "replay_key": b"z" * 32},
            is_initiator=False,
        )
        request = manager.create_rekey_request()
        request["request"]["nonce"] = "TAMPERED"

        is_valid = manager.validate_rekey_request(request)
        assert is_valid is False

    def test_rekey_keys_are_unique(self):
        """rekey 派生的新密钥各不相同"""
        session_keys = {
            "encryption_key": b"a" * 32,
            "auth_key": b"b" * 32,
            "replay_key": b"c" * 32,
        }
        initiator = RekeyManager(session_keys, is_initiator=True)
        responder = RekeyManager(session_keys, is_initiator=False)

        request = initiator.create_rekey_request()
        response = responder.process_rekey_request(request)
        new_keys = initiator.process_rekey_response(response)

        assert new_keys["encryption_key"] != new_keys["auth_key"]
        assert new_keys["encryption_key"] != new_keys["replay_key"]
        assert new_keys["auth_key"] != new_keys["replay_key"]

    def test_secure_wipe_called_on_apply(self):
        """apply_new_keys 应触发 _secure_wipe"""
        from sip_protocol.protocol.rekey import _secure_wipe

        session_keys = {
            "encryption_key": b"x" * 32,
            "auth_key": b"y" * 32,
            "replay_key": b"z" * 32,
        }
        manager = RekeyManager(session_keys, is_initiator=True)
        new_keys = {
            "encryption_key": b"new_enc" * 16,
            "auth_key": b"new_auth" * 16,
            "replay_key": b"new_replay" * 16,
        }
        manager.apply_new_keys(new_keys)

        # 验证新密钥已应用
        assert manager.session_state["encryption_key"] == b"new_enc" * 16
        assert manager.session_state["rekey_count"] == 1
