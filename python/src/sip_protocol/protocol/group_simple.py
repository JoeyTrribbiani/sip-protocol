"""
简化的群组加密协议
所有成员共享同一个群组加密密钥
"""

import base64
import hmac
import hashlib
import os
import time
import json
from ..crypto.aes_gcm import encrypt_aes_gcm, decrypt_aes_gcm, AES_GCM_NONCE_LENGTH
from ..crypto.hkdf import hkdf

GROUP_PROTOCOL_VERSION = "SIP-1.0"
MESSAGE_KEY_LENGTH = 32
GROUP_KEY_LENGTH = 32


class SimpleGroupManager:
    """
    简化的群组管理器
    所有成员共享同一个群组加密密钥
    """

    def __init__(self, group_id: str, root_key: bytes):
        """
        构造函数

        Args:
            group_id: 群组ID
            root_key: 根密钥
        """
        self.group_id = group_id
        self.root_key = root_key
        self.members: dict = {}
        self.group_encryption_key = hkdf(
            root_key, group_id.encode(), b"group-encryption-key", GROUP_KEY_LENGTH
        )

    def add_member(self, member_id: str):
        """
        添加成员到群组

        Args:
            member_id: 成员ID
        """
        self.members[member_id] = {
            "joined_at": int(time.time() * 1000),
            "message_counter": 0,
        }

    def remove_member(self, member_id: str):
        """
        从群组移除成员

        Args:
            member_id: 成员ID
        """
        if member_id in self.members:
            del self.members[member_id]

    def send_group_message(self, plaintext: str, sender_id: str) -> str:
        """
        发送群组消息

        Args:
            plaintext: 明文消息
            sender_id: 发送者ID

        Returns:
            str: 消息JSON字符串
        """
        # 1. 加密消息
        iv = os.urandom(AES_GCM_NONCE_LENGTH)
        ciphertext, auth_tag = encrypt_aes_gcm(self.group_encryption_key, plaintext.encode(), iv)

        # 2. 发送方签名
        sender_signature = hmac.new(self.group_encryption_key, ciphertext, hashlib.sha256).digest()

        # 3. 更新发送者的消息计数器
        if sender_id in self.members:
            message_number = self.members[sender_id]["message_counter"]
            self.members[sender_id]["message_counter"] += 1
        else:
            message_number = 0

        # 4. 构建群组消息
        message = {
            "version": GROUP_PROTOCOL_VERSION,
            "type": "group_message",
            "timestamp": int(time.time() * 1000),
            "sender_id": sender_id,
            "group_id": self.group_id,
            "message_number": message_number,
            "iv": base64.b64encode(iv).decode(),
            "ciphertext": base64.b64encode(ciphertext).decode(),
            "auth_tag": base64.b64encode(auth_tag).decode(),
            "sender_signature": base64.b64encode(sender_signature).decode(),
        }

        return json.dumps(message)

    def receive_group_message(self, message: str) -> str:
        """
        接收群组消息

        Args:
            message: 群组消息（JSON字符串）

        Returns:
            str: 明文消息
        """
        # 1. 解析消息
        msg = json.loads(message)

        # 2. 解密消息
        iv = base64.b64decode(msg["iv"])
        ciphertext = base64.b64decode(msg["ciphertext"])
        auth_tag = base64.b64decode(msg["auth_tag"])

        plaintext = decrypt_aes_gcm(self.group_encryption_key, ciphertext, iv, auth_tag)

        return plaintext.decode() if isinstance(plaintext, bytes) else plaintext

    def get_member_count(self) -> int:
        """获取成员数量"""
        return len(self.members)

    def get_members(self) -> list:
        """获取成员列表"""
        return list(self.members.keys())
