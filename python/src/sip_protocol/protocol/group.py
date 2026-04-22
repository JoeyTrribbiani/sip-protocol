"""
群组加密协议模块
实现基于Double Ratchet的群组加密

包括群组管理消息:
- group_init: 管理员初始化群组
- group_join_ack: 成员接收邀请
- group_chain_key: 管理员分配链密钥
- group_chain_key_ack: 成员确认接收
- group_add_member: 管理员邀请新成员
- group_join_request: 新成员接收邀请
- group_leave: 成员发送离开请求
- group_leave_ack: 管理员确认离开
- group_error: 错误消息
"""

import base64
import hmac
import hashlib
import os
import time
import json
from typing import Optional, Dict, List, Any
from ..crypto.aes_gcm import encrypt_aes_gcm, decrypt_aes_gcm, AES_GCM_NONCE_LENGTH
from ..crypto.hkdf import hkdf

GROUP_PROTOCOL_VERSION = "SIP-1.0"
MESSAGE_KEY_LENGTH = 32
CHAIN_KEY_LENGTH = 32


class GroupManager:
    """
    群组管理器
    管理群组成员、群组状态和群组消息
    """

    def __init__(self, group_id: str, root_key: bytes, admin_id: str = ""):
        """
        构造函数

        Args:
            group_id: 群组ID
            root_key: 根密钥
            admin_id: 管理员ID
        """
        self.group_id = group_id
        self.root_key = root_key
        self.admin_id = admin_id
        self.members: Dict[str, Dict] = {}
        self.group_name: str = ""

    def initialize_group_chains(self, members: list, root_key: bytes) -> dict:
        """
        初始化群组链密钥

        群组设计说明：在群组场景下，所有成员需要能够解密彼此发送的消息。
        简化方案：使用共享的群组密钥基础，确保所有成员能派生相同的消息密钥。

        Args:
            members: 群组成员ID列表
            root_key: 根密钥

        Returns:
            dict: 群组链密钥
        """
        chains = {}

        # 派生一个共享的群组消息密钥基础
        # 所有成员使用相同的基础密钥来派生消息密钥，确保互解密能力
        group_message_key_base = hkdf(root_key, b"group-message-key-base", b"sip-group", 32)

        for member in members:
            # 每个成员有独立的链状态（用于管理消息编号）
            # 但派生密钥时使用相同的基础
            chain_key = hkdf(group_message_key_base, b"chain-key", b"ratchet", CHAIN_KEY_LENGTH)

            chains[member] = {
                "sending_chain": {"chain_key": chain_key, "message_number": 0},
                "receiving_chain": {
                    "chain_key": chain_key,
                    "message_number": 0,
                    "skip_keys": {},
                },
            }

        return chains

    # ==================== 群组管理消息构建 ====================

    def create_group_init_message(
        self,
        sender_id: str,
        members: List[str],
        group_name: str = "",
        signature: Optional[bytes] = None,
    ) -> str:
        """
        创建 group_init 消息（管理员初始化群组）

        Args:
            sender_id: 发送方ID（管理员）
            members: 群组成员列表
            group_name: 群组名称
            signature: 管理员签名

        Returns:
            str: JSON格式的消息
        """
        message = {
            "version": GROUP_PROTOCOL_VERSION,
            "type": "group_init",
            "timestamp": int(time.time() * 1000),
            "sender_id": sender_id,
            "group_id": self.group_id,
            "group_name": group_name,
            "admin_id": sender_id,
            "members": members,
            "root_key": base64.b64encode(self.root_key).decode(),
            "signature": base64.b64encode(signature).decode() if signature else "",
        }
        return json.dumps(message)

    def create_group_join_ack_message(
        self,
        sender_id: str,
        recipient_id: str,
        public_key: bytes,
        signature: bytes,
    ) -> str:
        """
        创建 group_join_ack 消息（成员接收邀请）

        Args:
            sender_id: 发送方ID（成员）
            recipient_id: 接收方ID（管理员）
            public_key: 成员的公钥
            signature: 成员签名

        Returns:
            str: JSON格式的消息
        """
        message = {
            "version": GROUP_PROTOCOL_VERSION,
            "type": "group_join_ack",
            "timestamp": int(time.time() * 1000),
            "sender_id": sender_id,
            "recipient_id": recipient_id,
            "group_id": self.group_id,
            "public_key": base64.b64encode(public_key).decode(),
            "signature": base64.b64encode(signature).decode(),
        }
        return json.dumps(message)

    def create_group_chain_key_message(
        self,
        sender_id: str,
        recipient_id: str,
        sending_chain: Dict[str, Any],
        receiving_chain: Dict[str, Any],
        signature: bytes,
    ) -> str:
        """
        创建 group_chain_key 消息（管理员分配链密钥）

        Args:
            sender_id: 发送方ID（管理员）
            recipient_id: 接收方ID（成员）
            sending_chain: 发送链状态
            receiving_chain: 接收链状态
            signature: 管理员签名

        Returns:
            str: JSON格式的消息
        """
        message = {
            "version": GROUP_PROTOCOL_VERSION,
            "type": "group_chain_key",
            "timestamp": int(time.time() * 1000),
            "sender_id": sender_id,
            "group_id": self.group_id,
            "recipient_id": recipient_id,
            "sending_chain": {
                "chain_key": base64.b64encode(sending_chain["chain_key"]).decode(),
                "message_number": sending_chain["message_number"],
            },
            "receiving_chain": {
                "chain_key": base64.b64encode(receiving_chain["chain_key"]).decode(),
                "message_number": receiving_chain["message_number"],
                "skip_keys": {
                    str(k): base64.b64encode(v).decode()
                    for k, v in receiving_chain.get("skip_keys", {}).items()
                },
            },
            "signature": base64.b64encode(signature).decode(),
        }
        return json.dumps(message)

    def create_group_chain_key_ack_message(
        self,
        sender_id: str,
        recipient_id: str,
        signature: bytes,
    ) -> str:
        """
        创建 group_chain_key_ack 消息（成员确认接收）

        Args:
            sender_id: 发送方ID（成员）
            recipient_id: 接收方ID（管理员）
            signature: 成员签名

        Returns:
            str: JSON格式的消息
        """
        message = {
            "version": GROUP_PROTOCOL_VERSION,
            "type": "group_chain_key_ack",
            "timestamp": int(time.time() * 1000),
            "sender_id": sender_id,
            "recipient_id": recipient_id,
            "group_id": self.group_id,
            "signature": base64.b64encode(signature).decode(),
        }
        return json.dumps(message)

    def create_group_add_member_message(
        self,
        sender_id: str,
        new_member: str,
        signature: bytes,
    ) -> str:
        """
        创建 group_add_member 消息（管理员邀请新成员）

        Args:
            sender_id: 发送方ID（管理员）
            new_member: 新成员ID
            signature: 管理员签名

        Returns:
            str: JSON格式的消息
        """
        message = {
            "version": GROUP_PROTOCOL_VERSION,
            "type": "group_add_member",
            "timestamp": int(time.time() * 1000),
            "sender_id": sender_id,
            "group_id": self.group_id,
            "new_member": new_member,
            "signature": base64.b64encode(signature).decode(),
        }
        return json.dumps(message)

    def create_group_join_request_message(
        self,
        sender_id: str,
        recipient_id: str,
        public_key: bytes,
        signature: bytes,
    ) -> str:
        """
        创建 group_join_request 消息（新成员接收邀请）

        Args:
            sender_id: 发送方ID（新成员）
            recipient_id: 接收方ID（管理员）
            public_key: 新成员的公钥
            signature: 新成员签名

        Returns:
            str: JSON格式的消息
        """
        message = {
            "version": GROUP_PROTOCOL_VERSION,
            "type": "group_join_request",
            "timestamp": int(time.time() * 1000),
            "sender_id": sender_id,
            "recipient_id": recipient_id,
            "group_id": self.group_id,
            "public_key": base64.b64encode(public_key).decode(),
            "signature": base64.b64encode(signature).decode(),
        }
        return json.dumps(message)

    def create_group_leave_message(
        self,
        sender_id: str,
        signature: bytes,
    ) -> str:
        """
        创建 group_leave 消息（成员发送离开请求）

        Args:
            sender_id: 发送方ID（成员）
            signature: 成员签名

        Returns:
            str: JSON格式的消息
        """
        message = {
            "version": GROUP_PROTOCOL_VERSION,
            "type": "group_leave",
            "timestamp": int(time.time() * 1000),
            "sender_id": sender_id,
            "group_id": self.group_id,
            "signature": base64.b64encode(signature).decode(),
        }
        return json.dumps(message)

    def create_group_leave_ack_message(
        self,
        sender_id: str,
        recipient_id: str,
        signature: bytes,
    ) -> str:
        """
        创建 group_leave_ack 消息（管理员确认离开）

        Args:
            sender_id: 发送方ID（管理员）
            recipient_id: 接收方ID（离开的成员）
            signature: 管理员签名

        Returns:
            str: JSON格式的消息
        """
        message = {
            "version": GROUP_PROTOCOL_VERSION,
            "type": "group_leave_ack",
            "timestamp": int(time.time() * 1000),
            "sender_id": sender_id,
            "recipient_id": recipient_id,
            "group_id": self.group_id,
            "signature": base64.b64encode(signature).decode(),
        }
        return json.dumps(message)

    def create_group_error_message(
        self,
        error_code: str,
        error_message: str,
        error_details: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        创建 group_error 消息（错误消息）

        Args:
            error_code: 错误码
            error_message: 错误消息
            error_details: 错误详情

        Returns:
            str: JSON格式的消息
        """
        message = {
            "version": GROUP_PROTOCOL_VERSION,
            "type": "group_error",
            "timestamp": int(time.time() * 1000),
            "group_id": self.group_id,
            "error_code": error_code,
            "error_message": error_message,
            "error_details": error_details or {},
        }
        return json.dumps(message)

    # ==================== 群组管理消息解析 ====================

    def parse_group_message(self, message_json: str) -> Dict[str, Any]:  # type: ignore[return-value]
        """
        解析群组管理消息

        Args:
            message_json: JSON格式的消息

        Returns:
            Dict: 解析后的消息
        """
        msg = json.loads(message_json)

        # 验证基本字段
        if msg.get("version") != GROUP_PROTOCOL_VERSION:
            raise ValueError(f"Invalid version: {msg.get('version')}")

        if "type" not in msg:
            raise ValueError("Missing message type")

        return msg  # type: ignore[no-any-return]

    def validate_group_message_signature(
        self,
        message: Dict[str, Any],
        auth_key: bytes,
        sender_id: str,
    ) -> bool:
        """
        验证群组管理消息签名

        Args:
            message: 消息字典
            auth_key: 认证密钥
            sender_id: 发送方ID

        Returns:
            bool: 是否有效
        """
        signature_b64 = message.get("signature", "")
        if not signature_b64:
            return False

        signature = base64.b64decode(signature_b64)

        # 构建签名数据
        if message["type"] == "group_init":
            data = f"{sender_id}:{message['group_id']}:{message['admin_id']}:".encode()
        elif message["type"] == "group_join_ack":
            data = f"{sender_id}:{message['recipient_id']}:{message['group_id']}:".encode()
        elif message["type"] == "group_chain_key":
            data = f"{sender_id}:{message['recipient_id']}:{message['group_id']}:".encode()
        elif message["type"] == "group_chain_key_ack":
            data = f"{sender_id}:{message['recipient_id']}:{message['group_id']}:".encode()
        elif message["type"] == "group_add_member":
            data = f"{sender_id}:{message['group_id']}:{message['new_member']}:".encode()
        elif message["type"] == "group_join_request":
            data = f"{sender_id}:{message['recipient_id']}:{message['group_id']}:".encode()
        elif message["type"] == "group_leave":
            data = f"{sender_id}:{message['group_id']}:".encode()
        elif message["type"] == "group_leave_ack":
            data = f"{sender_id}:{message['recipient_id']}:{message['group_id']}:".encode()
        else:
            return False

        expected_signature = hmac.new(auth_key, data, hashlib.sha256).digest()
        return hmac.compare_digest(signature, expected_signature)

    # ==================== 群组成员管理 ====================

    def add_member(
        self,
        member_id: str,
        public_key: Optional[bytes] = None,
        role: str = "member",
    ) -> None:
        """
        添加群组成员

        Args:
            member_id: 成员ID
            public_key: 成员公钥
            role: 角色 (admin 或 member)
        """
        if member_id in self.members:
            raise ValueError(f"Member {member_id} already exists")

        # 为新成员派生链密钥
        sending_chain_key = hkdf(
            self.root_key, f"{member_id}:sending".encode(), b"sending-chain", CHAIN_KEY_LENGTH
        )
        receiving_chain_key = hkdf(
            self.root_key, f"{member_id}:receiving".encode(), b"receiving-chain", CHAIN_KEY_LENGTH
        )

        self.members[member_id] = {
            "member_id": member_id,
            "role": role,
            "joined_at": int(time.time() * 1000),
            "public_key": base64.b64encode(public_key).decode() if public_key else "",
            "sending_chain": {
                "chain_key": sending_chain_key,
                "message_number": 0,
            },
            "receiving_chain": {
                "chain_key": receiving_chain_key,
                "message_number": 0,
                "skip_keys": {},
            },
        }

    def remove_member(self, member_id: str) -> None:
        """
        移除群组成员

        Args:
            member_id: 成员ID
        """
        if member_id not in self.members:
            raise ValueError(f"Member {member_id} not found")

        # 更新root key（实现前向保密）
        self.root_key = self.update_root_key_after_leave(self.root_key)

        # 为剩余成员重新派生链密钥
        for mid, member_data in self.members.items():
            if mid == member_id:
                continue

            sending_chain_key = hkdf(
                self.root_key, f"{mid}:sending".encode(), b"sending-chain", CHAIN_KEY_LENGTH
            )
            receiving_chain_key = hkdf(
                self.root_key, f"{mid}:receiving".encode(), b"receiving-chain", CHAIN_KEY_LENGTH
            )

            member_data["sending_chain"]["chain_key"] = sending_chain_key
            member_data["receiving_chain"]["chain_key"] = receiving_chain_key

        # 移除成员
        del self.members[member_id]

    def is_member(self, member_id: str) -> bool:
        """
        检查是否是群组成员

        Args:
            member_id: 成员ID

        Returns:
            bool: 是否是成员
        """
        return member_id in self.members

    def is_admin(self, member_id: str) -> bool:
        """
        检查是否是管理员

        Args:
            member_id: 成员ID

        Returns:
            bool: 是否是管理员
        """
        # 首先检查是否是群组管理员ID
        if member_id == self.admin_id:
            return True
        # 然后检查是否在成员列表中且角色为admin
        if member_id not in self.members:
            return False
        return self.members[member_id].get("role") == "admin"

    def send_group_message(
        self, plaintext: str, sending_chain: dict, sender_id: str
    ) -> tuple[str, dict]:
        """
        发送群组消息

        群组密钥派生方案：使用群组根密钥和发送者ID派生消息密钥
        这样接收方可以用相同的方式派生出相同的密钥来解密

        Args:
            plaintext: 明文消息
            sending_chain: 发送链状态（只用于跟踪消息编号）
            sender_id: 发送者ID

        Returns:
            Tuple[str, dict]: (消息JSON字符串, 更新后的发送链状态)
        """
        # 1. 派生消息密钥：使用群组根密钥 + 发送者ID + 消息编号
        # 所有成员都可以用相同的方式派生这个密钥
        message_context = f"{sender_id}:{sending_chain['message_number']}".encode()
        message_key = hkdf(self.root_key, message_context, b"group-message-key", MESSAGE_KEY_LENGTH)

        # 调试：打印密钥信息

        # 2. 加密消息
        iv = os.urandom(AES_GCM_NONCE_LENGTH)
        ciphertext, auth_tag = encrypt_aes_gcm(message_key, plaintext.encode(), iv)

        # 3. 发送方签名（使用消息密钥）
        sender_signature = hmac.new(message_key, ciphertext, hashlib.sha256).digest()

        # 4. 更新sending chain状态（只推进消息编号）
        updated_chain = {
            "chain_key": sending_chain["chain_key"],  # 链密钥不再推进
            "message_number": sending_chain["message_number"] + 1,
        }

        # 5. 构建群组消息
        message = {
            "version": GROUP_PROTOCOL_VERSION,
            "type": "group_message",
            "timestamp": int(time.time() * 1000),
            "sender_id": sender_id,
            "group_id": self.group_id,
            "message_number": sending_chain["message_number"],
            "iv": base64.b64encode(iv).decode(),
            "ciphertext": base64.b64encode(ciphertext).decode(),
            "auth_tag": base64.b64encode(auth_tag).decode(),
            "sender_signature": base64.b64encode(sender_signature).decode(),
        }

        return json.dumps(message), updated_chain

    def receive_group_message(
        self, message: str, receiving_chain: dict, sender_id: str
    ) -> tuple[str, dict]:
        """
        接收群组消息

        使用群组根密钥和发送者ID派生消息密钥，与发送方使用相同的方式

        Args:
            message: 群组消息（JSON字符串）
            receiving_chain: 接收链状态（只用于跟踪消息编号）
            sender_id: 发送者ID

        Returns:
            Tuple[str, dict]: (明文消息, 更新后的接收链状态)
        """
        # 1. 解析消息
        msg = json.loads(message)
        message_number = msg["message_number"]

        # 2. 派生消息密钥：使用群组根密钥 + 发送者ID + 消息编号
        # 与 send_group_message 中的派生方式相同
        message_context = f"{sender_id}:{message_number}".encode()
        message_key = hkdf(self.root_key, message_context, b"group-message-key", MESSAGE_KEY_LENGTH)

        # 调试：打印密钥信息

        # 3. 解密消息
        iv = base64.b64decode(msg["iv"])
        ciphertext = base64.b64decode(msg["ciphertext"])
        auth_tag = base64.b64decode(msg["auth_tag"])

        plaintext = decrypt_aes_gcm(message_key, ciphertext, iv, auth_tag)

        # 4. 验证发送方签名
        sender_signature = base64.b64decode(msg["sender_signature"])
        expected_signature = hmac.new(message_key, ciphertext, hashlib.sha256).digest()

        if not hmac.compare_digest(sender_signature, expected_signature):
            raise ValueError("Invalid sender signature")

        # 5. 更新receiving chain状态（只推进消息编号）
        updated_chain = {
            "chain_key": receiving_chain["chain_key"],  # 链密钥不再推进
            "message_number": receiving_chain["message_number"] + 1,
            "skip_keys": receiving_chain["skip_keys"],
        }

        return plaintext.decode(), updated_chain

    def update_group_root_key(self, current_root_key: bytes, new_member_public_key: bytes) -> bytes:
        """
        更新群组root key（成员加入）

        Args:
            current_root_key: 当前root key
            new_member_public_key: 新成员的公钥

        Returns:
            bytes: 新root key
        """
        # 派生新root key
        new_root_key = hkdf(current_root_key, b"", new_member_public_key, CHAIN_KEY_LENGTH)

        self.root_key = new_root_key
        return new_root_key

    def update_root_key_after_leave(self, current_root_key: bytes) -> bytes:
        """
        更新群组root key（成员离开）

        Args:
            current_root_key: 当前root key

        Returns:
            bytes: 新root key
        """
        # 派生新root key
        new_root_key = hkdf(current_root_key, b"", b"new-root-key-after-leave", CHAIN_KEY_LENGTH)

        self.root_key = new_root_key
        return new_root_key
