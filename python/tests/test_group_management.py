#!/usr/bin/env python3
"""
群组管理消息测试
测试群组初始化、成员加入/离开流程等
"""

import sys
import os
import json
import base64
import hmac
import hashlib

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.protocol.group import GroupManager, GROUP_PROTOCOL_VERSION
from src.crypto.hkdf import hkdf

# ==================== 辅助函数 ====================


def generate_signature(data: bytes, key: bytes) -> bytes:
    """生成HMAC-SHA256签名"""
    return hmac.new(key, data, hashlib.sha256).digest()


def parse_and_validate_message(
    message_json: str,
    expected_type: str,
) -> dict:
    """解析并验证消息"""
    msg = json.loads(message_json)
    assert msg["version"] == GROUP_PROTOCOL_VERSION
    assert msg["type"] == expected_type
    return msg


# ==================== 测试用例 ====================


def test_group_init_message():
    """测试群组初始化消息"""
    print("\n=== 测试1: 群组初始化消息 ===")

    group_id = "group:test-123"
    root_key = hkdf(b"test-root", b"", b"root-key", 32)
    admin_id = "agent:admin::session:abc"
    members = ["agent:admin::session:abc", "agent:user1::session:def", "agent:user2::session:ghi"]
    group_name = "Test Group"

    # 创建群组管理器
    gm = GroupManager(group_id, root_key, admin_id)

    # 创建签名
    signature_data = f"{admin_id}:{group_id}:{admin_id}:".encode()
    signature = generate_signature(signature_data, root_key)

    # 创建group_init消息
    message_json = gm.create_group_init_message(
        sender_id=admin_id,
        members=members,
        group_name=group_name,
        signature=signature,
    )

    # 验证消息
    msg = parse_and_validate_message(message_json, "group_init")
    assert msg["sender_id"] == admin_id
    assert msg["group_id"] == group_id
    assert msg["group_name"] == group_name
    assert msg["admin_id"] == admin_id
    assert msg["members"] == members
    assert base64.b64decode(msg["root_key"]) == root_key

    print(f"✅ 群组ID: {msg['group_id']}")
    print(f"✅ 群组名称: {msg['group_name']}")
    print(f"✅ 管理员: {msg['admin_id']}")
    print(f"✅ 成员数: {len(msg['members'])}")
    print("✅ 测试1通过!")


def test_group_join_ack_message():
    """测试成员接收邀请消息"""
    print("\n=== 测试2: 成员接收邀请消息 ===")

    group_id = "group:test-123"
    root_key = hkdf(b"test-root", b"", b"root-key", 32)
    sender_id = "agent:user1::session:def"
    recipient_id = "agent:admin::session:abc"
    public_key = hkdf(b"public-key", b"", b"public", 32)

    gm = GroupManager(group_id, root_key)

    # 创建签名
    signature_data = f"{sender_id}:{recipient_id}:{group_id}:".encode()
    signature = generate_signature(signature_data, root_key)

    # 创建group_join_ack消息
    message_json = gm.create_group_join_ack_message(
        sender_id=sender_id,
        recipient_id=recipient_id,
        public_key=public_key,
        signature=signature,
    )

    # 验证消息
    msg = parse_and_validate_message(message_json, "group_join_ack")
    assert msg["sender_id"] == sender_id
    assert msg["recipient_id"] == recipient_id
    assert msg["group_id"] == group_id
    assert base64.b64decode(msg["public_key"]) == public_key

    print(f"✅ 发送方: {msg['sender_id']}")
    print(f"✅ 接收方: {msg['recipient_id']}")
    print(f"✅ 公钥长度: {len(base64.b64decode(msg['public_key']))} bytes")
    print("✅ 测试2通过!")


def test_group_chain_key_message():
    """测试链密钥分配消息"""
    print("\n=== 测试3: 链密钥分配消息 ===")

    group_id = "group:test-123"
    root_key = hkdf(b"test-root", b"", b"root-key", 32)
    sender_id = "agent:admin::session:abc"
    recipient_id = "agent:user1::session:def"

    gm = GroupManager(group_id, root_key)

    # 准备链密钥
    sending_chain_key = hkdf(b"sending", b"", b"chain", 32)
    receiving_chain_key = hkdf(b"receiving", b"", b"chain", 32)

    sending_chain = {
        "chain_key": sending_chain_key,
        "message_number": 0,
    }
    receiving_chain = {
        "chain_key": receiving_chain_key,
        "message_number": 0,
        "skip_keys": {},
    }

    # 创建签名
    signature_data = f"{sender_id}:{recipient_id}:{group_id}:".encode()
    signature = generate_signature(signature_data, root_key)

    # 创建group_chain_key消息
    message_json = gm.create_group_chain_key_message(
        sender_id=sender_id,
        recipient_id=recipient_id,
        sending_chain=sending_chain,
        receiving_chain=receiving_chain,
        signature=signature,
    )

    # 验证消息
    msg = parse_and_validate_message(message_json, "group_chain_key")
    assert msg["sender_id"] == sender_id
    assert msg["recipient_id"] == recipient_id
    assert msg["group_id"] == group_id
    assert base64.b64decode(msg["sending_chain"]["chain_key"]) == sending_chain_key
    assert base64.b64decode(msg["receiving_chain"]["chain_key"]) == receiving_chain_key

    print(f"✅ 发送方: {msg['sender_id']}")
    print(f"✅ 接收方: {msg['recipient_id']}")
    print(f"✅ Sending chain key: {len(base64.b64decode(msg['sending_chain']['chain_key']))} bytes")
    print(
        f"✅ Receiving chain key: {len(base64.b64decode(msg['receiving_chain']['chain_key']))} bytes"
    )
    print("✅ 测试3通过!")


def test_group_chain_key_ack_message():
    """测试链密钥确认消息"""
    print("\n=== 测试4: 链密钥确认消息 ===")

    group_id = "group:test-123"
    root_key = hkdf(b"test-root", b"", b"root-key", 32)
    sender_id = "agent:user1::session:def"
    recipient_id = "agent:admin::session:abc"

    gm = GroupManager(group_id, root_key)

    # 创建签名
    signature_data = f"{sender_id}:{recipient_id}:{group_id}:".encode()
    signature = generate_signature(signature_data, root_key)

    # 创建group_chain_key_ack消息
    message_json = gm.create_group_chain_key_ack_message(
        sender_id=sender_id,
        recipient_id=recipient_id,
        signature=signature,
    )

    # 验证消息
    msg = parse_and_validate_message(message_json, "group_chain_key_ack")
    assert msg["sender_id"] == sender_id
    assert msg["recipient_id"] == recipient_id
    assert msg["group_id"] == group_id

    print(f"✅ 发送方: {msg['sender_id']}")
    print(f"✅ 接收方: {msg['recipient_id']}")
    print("✅ 测试4通过!")


def test_group_add_member_message():
    """测试邀请新成员消息"""
    print("\n=== 测试5: 邀请新成员消息 ===")

    group_id = "group:test-123"
    root_key = hkdf(b"test-root", b"", b"root-key", 32)
    sender_id = "agent:admin::session:abc"
    new_member = "agent:user3::session:jkl"

    gm = GroupManager(group_id, root_key)

    # 创建签名
    signature_data = f"{sender_id}:{group_id}:{new_member}:".encode()
    signature = generate_signature(signature_data, root_key)

    # 创建group_add_member消息
    message_json = gm.create_group_add_member_message(
        sender_id=sender_id,
        new_member=new_member,
        signature=signature,
    )

    # 验证消息
    msg = parse_and_validate_message(message_json, "group_add_member")
    assert msg["sender_id"] == sender_id
    assert msg["group_id"] == group_id
    assert msg["new_member"] == new_member

    print(f"✅ 发送方: {msg['sender_id']}")
    print(f"✅ 新成员: {msg['new_member']}")
    print("✅ 测试5通过!")


def test_group_join_request_message():
    """测试新成员接收邀请消息"""
    print("\n=== 测试6: 新成员接收邀请消息 ===")

    group_id = "group:test-123"
    root_key = hkdf(b"test-root", b"", b"root-key", 32)
    sender_id = "agent:user3::session:jkl"
    recipient_id = "agent:admin::session:abc"
    public_key = hkdf(b"public-key-3", b"", b"public", 32)

    gm = GroupManager(group_id, root_key)

    # 创建签名
    signature_data = f"{sender_id}:{recipient_id}:{group_id}:".encode()
    signature = generate_signature(signature_data, root_key)

    # 创建group_join_request消息
    message_json = gm.create_group_join_request_message(
        sender_id=sender_id,
        recipient_id=recipient_id,
        public_key=public_key,
        signature=signature,
    )

    # 验证消息
    msg = parse_and_validate_message(message_json, "group_join_request")
    assert msg["sender_id"] == sender_id
    assert msg["recipient_id"] == recipient_id
    assert msg["group_id"] == group_id
    assert base64.b64decode(msg["public_key"]) == public_key

    print(f"✅ 发送方: {msg['sender_id']}")
    print(f"✅ 接收方: {msg['recipient_id']}")
    print(f"✅ 公钥长度: {len(base64.b64decode(msg['public_key']))} bytes")
    print("✅ 测试6通过!")


def test_group_leave_message():
    """测试成员离开请求消息"""
    print("\n=== 测试7: 成员离开请求消息 ===")

    group_id = "group:test-123"
    root_key = hkdf(b"test-root", b"", b"root-key", 32)
    sender_id = "agent:user1::session:def"

    gm = GroupManager(group_id, root_key)

    # 创建签名
    signature_data = f"{sender_id}:{group_id}:".encode()
    signature = generate_signature(signature_data, root_key)

    # 创建group_leave消息
    message_json = gm.create_group_leave_message(
        sender_id=sender_id,
        signature=signature,
    )

    # 验证消息
    msg = parse_and_validate_message(message_json, "group_leave")
    assert msg["sender_id"] == sender_id
    assert msg["group_id"] == group_id

    print(f"✅ 发送方: {msg['sender_id']}")
    print("✅ 测试7通过!")


def test_group_leave_ack_message():
    """测试管理员确认离开消息"""
    print("\n=== 测试8: 管理员确认离开消息 ===")

    group_id = "group:test-123"
    root_key = hkdf(b"test-root", b"", b"root-key", 32)
    sender_id = "agent:admin::session:abc"
    recipient_id = "agent:user1::session:def"

    gm = GroupManager(group_id, root_key)

    # 创建签名
    signature_data = f"{sender_id}:{recipient_id}:{group_id}:".encode()
    signature = generate_signature(signature_data, root_key)

    # 创建group_leave_ack消息
    message_json = gm.create_group_leave_ack_message(
        sender_id=sender_id,
        recipient_id=recipient_id,
        signature=signature,
    )

    # 验证消息
    msg = parse_and_validate_message(message_json, "group_leave_ack")
    assert msg["sender_id"] == sender_id
    assert msg["recipient_id"] == recipient_id
    assert msg["group_id"] == group_id

    print(f"✅ 发送方: {msg['sender_id']}")
    print(f"✅ 接收方: {msg['recipient_id']}")
    print("✅ 测试8通过!")


def test_group_error_message():
    """测试群组错误消息"""
    print("\n=== 测试9: 群组错误消息 ===")

    group_id = "group:test-123"
    root_key = hkdf(b"test-root", b"", b"root-key", 32)

    gm = GroupManager(group_id, root_key)

    # 创建group_error消息
    message_json = gm.create_group_error_message(
        error_code="PERMISSION_DENIED",
        error_message="Only admin can perform this operation",
        error_details={"operation": "add_member", "requester": "user1"},
    )

    # 验证消息
    msg = parse_and_validate_message(message_json, "group_error")
    assert msg["group_id"] == group_id
    assert msg["error_code"] == "PERMISSION_DENIED"
    assert msg["error_message"] == "Only admin can perform this operation"
    assert msg["error_details"]["operation"] == "add_member"

    print(f"✅ 错误码: {msg['error_code']}")
    print(f"✅ 错误消息: {msg['error_message']}")
    print(f"✅ 错误详情: {msg['error_details']}")
    print("✅ 测试9通过!")


def test_add_member_flow():
    """测试添加成员流程"""
    print("\n=== 测试10: 添加成员流程 ===")

    group_id = "group:test-123"
    root_key = hkdf(b"test-root", b"", b"root-key", 32)
    admin_id = "agent:admin::session:abc"

    gm = GroupManager(group_id, root_key, admin_id)

    # 添加成员
    member_id = "agent:user1::session:def"
    public_key = hkdf(b"public-key-1", b"", b"public", 32)

    gm.add_member(member_id, public_key, role="member")

    # 验证成员已添加
    assert gm.is_member(member_id)
    assert not gm.is_admin(member_id)
    assert gm.is_admin(admin_id)

    print(f"✅ 成员已添加: {member_id}")
    print(f"✅ 成员角色: member")
    print(f"✅ 群组成员数: {len(gm.members)}")
    print("✅ 测试10通过!")


def test_remove_member_flow():
    """测试移除成员流程"""
    print("\n=== 测试11: 移除成员流程 ===")

    group_id = "group:test-123"
    root_key = hkdf(b"test-root", b"", b"root-key", 32)
    admin_id = "agent:admin::session:abc"

    gm = GroupManager(group_id, root_key, admin_id)

    # 添加成员
    member_id = "agent:user1::session:def"
    public_key = hkdf(b"public-key-1", b"", b"public", 32)
    gm.add_member(member_id, public_key, role="member")

    old_root_key = gm.root_key

    # 移除成员
    gm.remove_member(member_id)

    # 验证成员已移除
    assert not gm.is_member(member_id)
    # 验证root key已更新（前向保密）
    assert gm.root_key != old_root_key

    print(f"✅ 成员已移除: {member_id}")
    print(f"✅ Root key已更新（前向保密）")
    print(f"✅ 群组成员数: {len(gm.members)}")
    print("✅ 测试11通过!")


def test_full_member_join_flow():
    """测试完整的成员加入流程"""
    print("\n=== 测试12: 完整的成员加入流程 ===")

    group_id = "group:test-123"
    root_key = hkdf(b"test-root", b"", b"root-key", 32)
    admin_id = "agent:admin::session:abc"
    members = [admin_id]
    group_name = "Test Group"

    # 1. 管理员初始化群组
    gm_admin = GroupManager(group_id, root_key, admin_id)

    signature_data = f"{admin_id}:{group_id}:{admin_id}:".encode()
    signature = generate_signature(signature_data, root_key)

    init_message = gm_admin.create_group_init_message(
        sender_id=admin_id,
        members=members,
        group_name=group_name,
        signature=signature,
    )

    print(f"✅ 步骤1: 群组已初始化")

    # 2. 管理员邀请新成员
    new_member = "agent:user1::session:def"
    new_member_public_key = hkdf(b"public-key-1", b"", b"public", 32)

    signature_data = f"{admin_id}:{group_id}:{new_member}:".encode()
    signature = generate_signature(signature_data, root_key)

    add_member_message = gm_admin.create_group_add_member_message(
        sender_id=admin_id,
        new_member=new_member,
        signature=signature,
    )

    print(f"✅ 步骤2: 已邀请新成员 {new_member}")

    # 3. 新成员接收邀请并响应
    signature_data = f"{new_member}:{admin_id}:{group_id}:".encode()
    signature = generate_signature(signature_data, new_member_public_key)

    join_request_message = gm_admin.create_group_join_request_message(
        sender_id=new_member,
        recipient_id=admin_id,
        public_key=new_member_public_key,
        signature=signature,
    )

    print(f"✅ 步骤3: 新成员已响应邀请")

    # 4. 管理员更新root key（后向保密）并添加成员
    old_root_key = gm_admin.root_key
    new_root_key = gm_admin.update_group_root_key(old_root_key, new_member_public_key)
    assert new_root_key != old_root_key  # 后向保密

    gm_admin.add_member(new_member, new_member_public_key, role="member")

    print(f"✅ 步骤4: Root key已更新（后向保密）")
    print(f"✅ 步骤4: 成员已添加到群组")

    # 5. 管理员分配链密钥给新成员
    member_data = gm_admin.members[new_member]
    sending_chain = member_data["sending_chain"]
    receiving_chain = member_data["receiving_chain"]

    signature_data = f"{admin_id}:{new_member}:{group_id}:".encode()
    signature = generate_signature(signature_data, new_root_key)

    chain_key_message = gm_admin.create_group_chain_key_message(
        sender_id=admin_id,
        recipient_id=new_member,
        sending_chain=sending_chain,
        receiving_chain=receiving_chain,
        signature=signature,
    )

    print(f"✅ 步骤5: 链密钥已分配给新成员")

    # 6. 新成员确认接收链密钥
    signature_data = f"{new_member}:{admin_id}:{group_id}:".encode()
    signature = generate_signature(signature_data, new_member_public_key)

    chain_key_ack_message = gm_admin.create_group_chain_key_ack_message(
        sender_id=new_member,
        recipient_id=admin_id,
        signature=signature,
    )

    print(f"✅ 步骤6: 新成员已确认接收链密钥")

    # 验证
    assert gm_admin.is_member(new_member)
    assert gm_admin.root_key == new_root_key

    print(f"✅ 完整流程测试通过!")
    print(f"✅ 新成员已成功加入群组")
    print("✅ 测试12通过!")


def test_full_member_leave_flow():
    """测试完整的成员离开流程"""
    print("\n=== 测试13: 完整的成员离开流程 ===")

    group_id = "group:test-123"
    root_key = hkdf(b"test-root", b"", b"root-key", 32)
    admin_id = "agent:admin::session:abc"
    member_id = "agent:user1::session:def"

    # 1. 创建群组并添加成员
    gm_admin = GroupManager(group_id, root_key, admin_id)
    member_public_key = hkdf(b"public-key-1", b"", b"public", 32)
    gm_admin.add_member(member_id, member_public_key, role="member")

    print(f"✅ 步骤1: 群组已创建，成员已添加")

    # 2. 成员发送离开请求
    signature_data = f"{member_id}:{group_id}:".encode()
    signature = generate_signature(signature_data, member_public_key)

    leave_message = gm_admin.create_group_leave_message(
        sender_id=member_id,
        signature=signature,
    )

    print(f"✅ 步骤2: 成员已发送离开请求")

    # 3. 管理员确认离开并更新群组
    signature_data = f"{admin_id}:{member_id}:{group_id}:".encode()
    signature = generate_signature(signature_data, root_key)

    leave_ack_message = gm_admin.create_group_leave_ack_message(
        sender_id=admin_id,
        recipient_id=member_id,
        signature=signature,
    )

    print(f"✅ 步骤3: 管理员已确认离开")

    # 4. 管理员更新root key（前向保密）并移除成员
    old_root_key = gm_admin.root_key
    gm_admin.remove_member(member_id)
    new_root_key = gm_admin.root_key
    assert new_root_key != old_root_key  # 前向保密

    print(f"✅ 步骤4: Root key已更新（前向保密）")
    print(f"✅ 步骤4: 成员已从群组移除")

    # 验证
    assert not gm_admin.is_member(member_id)

    print(f"✅ 完整流程测试通过!")
    print(f"✅ 成员已成功离开群组")
    print("✅ 测试13通过!")


# ==================== 主函数 ====================


def main():
    """运行所有测试"""
    print("\n" + "=" * 60)
    print("群组管理消息测试套件 v1.0")
    print("=" * 60)

    try:
        # 测试1-9: 群组管理消息
        test_group_init_message()
        test_group_join_ack_message()
        test_group_chain_key_message()
        test_group_chain_key_ack_message()
        test_group_add_member_message()
        test_group_join_request_message()
        test_group_leave_message()
        test_group_leave_ack_message()
        test_group_error_message()

        # 测试10-11: 成员管理
        test_add_member_flow()
        test_remove_member_flow()

        # 测试12-13: 完整流程
        test_full_member_join_flow()
        test_full_member_leave_flow()

        print("\n" + "=" * 60)
        print("✅ 所有测试通过！")
        print("=" * 60 + "\n")

    except Exception as e:
        print(f"\n❌ 测试失败：{e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
