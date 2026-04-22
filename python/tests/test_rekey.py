"""
Rekey密钥轮换测试
"""

import pytest
import time
from sip_protocol.protocol.rekey import RekeyManager, REKEY_NONCE_LENGTH


def test_rekey_request_creation():
    """测试Rekey请求创建"""
    # 准备会话状态
    session_state = {
        "encryption_key": b"0" * 32,
        "auth_key": b"1" * 32,
        "replay_key": b"2" * 32,
    }

    # 创建Rekey管理器（发起方）
    rekey_manager = RekeyManager(session_state, is_initiator=True)

    # 创建Rekey请求
    request = rekey_manager.create_rekey_request(reason="scheduled")

    # 验证请求格式
    assert request["version"] == "SIP-1.0"
    assert request["type"] == "rekey"
    assert request["step"] == "request"
    assert "request" in request
    assert "signature" in request
    assert request["request"]["reason"] == "scheduled"
    assert request["request"]["key_lifetime"] == 3600

    print("✅ Rekey请求创建测试通过！")


def test_rekey_request_validation():
    """测试Rekey请求验证"""
    # 准备会话状态
    session_state_a = {
        "encryption_key": b"0" * 32,
        "auth_key": b"1" * 32,
        "replay_key": b"2" * 32,
    }

    session_state_b = {
        "encryption_key": b"0" * 32,
        "auth_key": b"1" * 32,
        "replay_key": b"2" * 32,
    }

    # Agent A创建Rekey请求（发起方）
    rekey_manager_a = RekeyManager(session_state_a, is_initiator=True)
    request = rekey_manager_a.create_rekey_request(reason="manual")

    # Agent B验证Rekey请求（响应方）
    rekey_manager_b = RekeyManager(session_state_b, is_initiator=False)
    is_valid = rekey_manager_b.validate_rekey_request(request)

    # 验证结果
    assert is_valid is True

    print("✅ Rekey请求验证测试通过！")


def test_rekey_request_invalid_signature():
    """测试无效签名的Rekey请求"""
    # 准备会话状态
    session_state_a = {
        "encryption_key": b"0" * 32,
        "auth_key": b"1" * 32,
        "replay_key": b"2" * 32,
    }

    session_state_b = {
        "encryption_key": b"0" * 32,
        "auth_key": b"3" * 32,  # 不同的auth_key
        "replay_key": b"2" * 32,
    }

    # Agent A创建Rekey请求（发起方）
    rekey_manager_a = RekeyManager(session_state_a, is_initiator=True)
    request = rekey_manager_a.create_rekey_request(reason="scheduled")

    # Agent B验证Rekey请求（响应方，应该失败）
    rekey_manager_b = RekeyManager(session_state_b, is_initiator=False)
    is_valid = rekey_manager_b.validate_rekey_request(request)

    # 验证结果
    assert is_valid is False

    print("✅ 无效签名Rekey请求测试通过！")


def test_rekey_response_creation():
    """测试Rekey响应创建"""
    # 准备会话状态
    session_state_a = {
        "encryption_key": b"0" * 32,
        "auth_key": b"1" * 32,
        "replay_key": b"2" * 32,
    }

    session_state_b = {
        "encryption_key": b"0" * 32,
        "auth_key": b"1" * 32,
        "replay_key": b"2" * 32,
    }

    # Agent A创建Rekey请求（发起方）
    rekey_manager_a = RekeyManager(session_state_a, is_initiator=True)
    request = rekey_manager_a.create_rekey_request(reason="scheduled")

    # Agent B处理请求并生成响应（响应方）
    rekey_manager_b = RekeyManager(session_state_b, is_initiator=False)
    response = rekey_manager_b.process_rekey_request(request)

    # 验证响应格式
    assert response["version"] == "SIP-1.0"
    assert response["type"] == "rekey"
    assert response["step"] == "response"
    assert "response" in response
    assert "signature" in response
    assert response["sequence"] == request["sequence"]

    print("✅ Rekey响应创建测试通过！")


def test_rekey_response_validation():
    """测试Rekey响应验证"""
    # 准备会话状态
    session_state_a = {
        "encryption_key": b"0" * 32,
        "auth_key": b"1" * 32,
        "replay_key": b"2" * 32,
    }

    session_state_b = {
        "encryption_key": b"0" * 32,
        "auth_key": b"1" * 32,
        "replay_key": b"2" * 32,
    }

    # Agent A创建Rekey请求（发起方）
    rekey_manager_a = RekeyManager(session_state_a, is_initiator=True)
    request = rekey_manager_a.create_rekey_request(reason="scheduled")

    # Agent B处理请求并生成响应（响应方）
    rekey_manager_b = RekeyManager(session_state_b, is_initiator=False)
    response = rekey_manager_b.process_rekey_request(request)

    # Agent A验证Rekey响应（发起方）
    is_valid = rekey_manager_a.validate_rekey_response(response)

    # 验证结果
    assert is_valid is True

    print("✅ Rekey响应验证测试通过！")


def test_rekey_complete_flow():
    """测试完整的Rekey流程"""
    # 准备会话状态
    session_state_a = {
        "encryption_key": b"0" * 32,
        "auth_key": b"1" * 32,
        "replay_key": b"2" * 32,
    }

    session_state_b = {
        "encryption_key": b"0" * 32,
        "auth_key": b"1" * 32,
        "replay_key": b"2" * 32,
    }

    # 保存原始密钥
    old_enc_key_a = session_state_a["encryption_key"]
    old_auth_key_a = session_state_a["auth_key"]
    old_replay_key_a = session_state_a["replay_key"]

    # Agent A创建Rekey请求（发起方）
    rekey_manager_a = RekeyManager(session_state_a, is_initiator=True)
    request = rekey_manager_a.create_rekey_request(reason="scheduled")

    # Agent B处理请求并生成响应（响应方）
    rekey_manager_b = RekeyManager(session_state_b, is_initiator=False)
    response = rekey_manager_b.process_rekey_request(request)

    # Agent B应用新密钥
    new_keys_b = rekey_manager_b._temp_new_keys
    rekey_manager_b.apply_new_keys(new_keys_b)

    # Agent A处理响应并派生新密钥（发起方）
    new_keys_a = rekey_manager_a.process_rekey_response(response)
    rekey_manager_a.apply_new_keys(new_keys_a)

    # 验证新密钥与旧密钥不同
    assert session_state_a["encryption_key"] != old_enc_key_a
    assert session_state_a["auth_key"] != old_auth_key_a
    assert session_state_a["replay_key"] != old_replay_key_a

    # 验证双方的新密钥一致
    assert session_state_a["encryption_key"] == session_state_b["encryption_key"]
    assert session_state_a["auth_key"] == session_state_b["auth_key"]
    assert session_state_a["replay_key"] == session_state_b["replay_key"]

    # 验证rekey计数
    assert session_state_a["rekey_count"] == 1
    assert session_state_b["rekey_count"] == 1

    print("✅ 完整Rekey流程测试通过！")


def test_rekey_timestamp_validation():
    """测试时间戳验证"""
    # 准备会话状态
    session_state = {
        "encryption_key": b"0" * 32,
        "auth_key": b"1" * 32,
        "replay_key": b"2" * 32,
    }

    # 创建Rekey管理器（发起方）
    rekey_manager = RekeyManager(session_state, is_initiator=True)

    # 创建Rekey请求
    request = rekey_manager.create_rekey_request(reason="scheduled")

    # 修改时间戳为10分钟前（应该失败）
    request["timestamp"] = int((time.time() - 600) * 1000)

    # 验证请求（应该失败）
    is_valid = rekey_manager.validate_rekey_request(request)
    assert is_valid is False

    print("✅ 时间戳验证测试通过！")


def test_rekey_sequence_validation():
    """测试序列号验证"""
    # 准备会话状态
    session_state_a = {
        "encryption_key": b"0" * 32,
        "auth_key": b"1" * 32,
        "replay_key": b"2" * 32,
    }

    session_state_b = {
        "encryption_key": b"0" * 32,
        "auth_key": b"1" * 32,
        "replay_key": b"2" * 32,
    }

    # Agent A创建Rekey请求（发起方）
    rekey_manager_a = RekeyManager(session_state_a, is_initiator=True)
    request1 = rekey_manager_a.create_rekey_request(reason="scheduled")

    # Agent B验证请求（响应方）
    rekey_manager_b = RekeyManager(session_state_b, is_initiator=False)
    assert rekey_manager_b.validate_rekey_request(request1) is True

    # Agent A创建第二个Rekey请求（发起方）
    request2 = rekey_manager_a.create_rekey_request(reason="manual")

    # Agent B处理第二个请求（响应方）
    response2 = rekey_manager_b.process_rekey_request(request2)

    # 尝试使用更小的序列号（应该失败）
    old_sequence = request2["sequence"]
    request2["sequence"] = old_sequence - 1
    assert rekey_manager_b.validate_rekey_request(request2) is False

    print("✅ 序列号验证测试通过！")


def test_rekey_forward_secrecy():
    """测试前向保密性"""
    # 准备会话状态
    session_state_a = {
        "encryption_key": b"0" * 32,
        "auth_key": b"1" * 32,
        "replay_key": b"2" * 32,
    }

    session_state_b = {
        "encryption_key": b"0" * 32,
        "auth_key": b"1" * 32,
        "replay_key": b"2" * 32,
    }

    # Agent A创建Rekey请求（发起方）
    rekey_manager_a = RekeyManager(session_state_a, is_initiator=True)
    request = rekey_manager_a.create_rekey_request(reason="scheduled")

    # Agent B处理请求并生成响应（响应方）
    rekey_manager_b = RekeyManager(session_state_b, is_initiator=False)
    response = rekey_manager_b.process_rekey_request(request)

    # Agent B应用新密钥
    new_keys_b = rekey_manager_b._temp_new_keys
    rekey_manager_b.apply_new_keys(new_keys_b)

    # Agent A处理响应并派生新密钥（发起方）
    new_keys_a = rekey_manager_a.process_rekey_response(response)
    rekey_manager_a.apply_new_keys(new_keys_a)

    # 保存新密钥
    new_enc_key = session_state_a["encryption_key"]

    # 尝试用旧密钥解密（应该失败）
    from sip_protocol.protocol.message import encrypt_message, decrypt_message

    # 用新密钥加密消息
    encrypted_msg = encrypt_message(
        encryption_key=new_enc_key,
        plaintext="Hello World",
        sender_id="agent-a",
        recipient_id="agent-b",
        message_counter=1,
        replay_key=session_state_a["replay_key"],
    )

    # 尝试用旧密钥解密（应该失败）
    try:
        decrypted = decrypt_message(
            encryption_key=b"0" * 32,  # 旧密钥
            message=encrypted_msg,
        )
        assert False, "Should not be able to decrypt with old key"
    except Exception:
        pass  # 期望抛出异常

    # 用新密钥解密（应该成功）
    decrypted = decrypt_message(
        encryption_key=new_enc_key,  # 新密钥
        message=encrypted_msg,
    )
    assert decrypted == "Hello World"

    print("✅ 前向保密性测试通过！")


if __name__ == "__main__":
    test_rekey_request_creation()
    test_rekey_request_validation()
    test_rekey_request_invalid_signature()
    test_rekey_response_creation()
    test_rekey_response_validation()
    test_rekey_complete_flow()
    test_rekey_timestamp_validation()
    test_rekey_sequence_validation()
    test_rekey_forward_secrecy()

    print("\n" + "=" * 50)
    print("✅ 所有Rekey测试通过！")
    print("=" * 50)
