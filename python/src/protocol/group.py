"""
群组加密协议模块
实现基于Double Ratchet的群组加密
"""

import base64
import hmac
import hashlib
import time
import json
from ..crypto.aes_gcm import encrypt_aes_gcm, decrypt_aes_gcm, AES_GCM_NONCE_LENGTH
from ..crypto.hkdf import hkdf

GROUP_PROTOCOL_VERSION = "SIP-1.0"
MESSAGE_KEY_LENGTH = 32
CHAIN_KEY_LENGTH = 32


class GroupManager:
    """
    群组管理器
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
        self.members = {}

    def initialize_group_chains(self, members: list, root_key: bytes) -> dict:
        """
        初始化群组链密钥

        Args:
            members: 群组成员ID列表
            root_key: 根密钥

        Returns:
            dict: 群组链密钥
        """
        chains = {}

        for member in members:
            # 派生sending chain key
            sending_chain_key = hkdf(
                root_key,
                f"{member}:sending".encode(),
                b"sending-chain",
                CHAIN_KEY_LENGTH
            )

            # 派生receiving chain key
            receiving_chain_key = hkdf(
                root_key,
                f"{member}:receiving".encode(),
                b"receiving-chain",
                CHAIN_KEY_LENGTH
            )

            chains[member] = {
                "sending_chain": {
                    "chain_key": sending_chain_key,
                    "message_number": 0
                },
                "receiving_chain": {
                    "chain_key": receiving_chain_key,
                    "message_number": 0,
                    "skip_keys": {}
                }
            }

        return chains

    def send_group_message(self, plaintext: str, sending_chain: dict) -> tuple[str, dict]:
        """
        发送群组消息

        Args:
            plaintext: 明文消息
            sending_chain: 发送链状态

        Returns:
            Tuple[str, dict]: (消息JSON字符串, 更新后的发送链状态)
        """
        import os

        # 1. 派生消息密钥
        message_key = hkdf(
            sending_chain["chain_key"],
            b"",
            b"message-key",
            MESSAGE_KEY_LENGTH
        )

        # 2. 推进链密钥
        next_chain_key = hkdf(
            sending_chain["chain_key"],
            b"",
            b"chain-key",
            CHAIN_KEY_LENGTH
        )

        # 3. 加密消息
        iv = os.urandom(AES_GCM_NONCE_LENGTH)
        ciphertext, auth_tag = encrypt_aes_gcm(
            message_key,
            plaintext.encode(),
            iv
        )

        # 4. 发送方签名
        sender_signature = hmac.new(
            message_key,
            ciphertext,
            hashlib.sha256
        ).digest()

        # 5. 更新sending chain状态
        updated_chain = {
            "chain_key": next_chain_key,
            "message_number": sending_chain["message_number"] + 1
        }

        # 6. 构建群组消息
        message = {
            "version": GROUP_PROTOCOL_VERSION,
            "type": "group_message",
            "timestamp": int(time.time() * 1000),
            "sender_id": "agent:decision-agent::session:abc",
            "group_id": "group:abc123",
            "message_number": sending_chain["message_number"],
            "iv": base64.b64encode(iv).decode(),
            "ciphertext": base64.b64encode(ciphertext).decode(),
            "auth_tag": base64.b64encode(auth_tag).decode(),
            "sender_signature": base64.b64encode(sender_signature).decode()
        }

        return json.dumps(message), updated_chain

    def receive_group_message(
        self,
        message: str,
        receiving_chain: dict
    ) -> tuple[str, dict]:
        """
        接收群组消息（完整版，支持乱序消息）

        Args:
            message: 群组消息（JSON字符串）
            receiving_chain: 接收链状态

        Returns:
            Tuple[str, dict]: (明文消息, 更新后的接收链状态)
        """
        # 1. 解析消息
        msg = json.loads(message)
        message_number = msg["message_number"]

        expected_msg_num = receiving_chain["message_number"]

        # 2. 检查消息类型并派生消息密钥
        if message_number > expected_msg_num:
            # 乱序消息，预先生成跳跃密钥（Skip Ratchet算法）
            for i in range(expected_msg_num, message_number):
                if i not in receiving_chain["skip_keys"]:
                    # 为每一条缺失的消息生成跳跃密钥
                    skipped_key = hkdf(
                        receiving_chain["chain_key"],
                        b"",
                        b"message-key",
                        MESSAGE_KEY_LENGTH
                    )
                    receiving_chain["skip_keys"][i] = skipped_key

                    # 推进链密钥
                    next_chain_key = hkdf(
                        receiving_chain["chain_key"],
                        b"",
                        b"chain-key",
                        CHAIN_KEY_LENGTH
                    )
                    receiving_chain["chain_key"] = next_chain_key

            # 使用目标message_number对应的跳跃密钥
            message_key = receiving_chain["skip_keys"][message_number]

            # 清理已使用的跳跃密钥
            del receiving_chain["skip_keys"][message_number]

        elif message_number == expected_msg_num:
            # 顺序消息，使用当前链密钥
            message_key = hkdf(
                receiving_chain["chain_key"],
                b"",
                b"message-key",
                MESSAGE_KEY_LENGTH
            )

            # 推进链密钥
            next_chain_key = hkdf(
                receiving_chain["chain_key"],
                b"",
                b"chain-key",
                CHAIN_KEY_LENGTH
            )
            receiving_chain["chain_key"] = next_chain_key

        else:
            # 重复消息或过期消息，拒绝
            raise ValueError(f"Invalid message number: {message_number}, expected: {expected_msg_num}")

        # 3. 解密消息
        iv = base64.b64decode(msg["iv"])
        ciphertext = base64.b64decode(msg["ciphertext"])
        auth_tag = base64.b64decode(msg["auth_tag"])

        plaintext = decrypt_aes_gcm(
            message_key,
            ciphertext,
            iv,
            auth_tag
        )

        # 4. 验证发送方签名
        sender_signature = base64.b64decode(msg["sender_signature"])
        expected_signature = hmac.new(
            message_key,
            ciphertext,
            hashlib.sha256
        ).digest()

        if not hmac.compare_digest(sender_signature, expected_signature):
            raise ValueError("Invalid sender signature")

        # 5. 更新receiving chain状态
        updated_chain = {
            "chain_key": receiving_chain["chain_key"],
            "message_number": receiving_chain["message_number"] + 1,
            "skip_keys": receiving_chain["skip_keys"]
        }

        return plaintext.decode(), updated_chain

    def update_group_root_key(
        self,
        current_root_key: bytes,
        new_member_public_key: bytes
    ) -> bytes:
        """
        更新群组root key（成员加入）

        Args:
            current_root_key: 当前root key
            new_member_public_key: 新成员的公钥

        Returns:
            bytes: 新root key
        """
        # 派生新root key
        new_root_key = hkdf(
            current_root_key,
            b"",
            new_member_public_key,
            CHAIN_KEY_LENGTH
        )

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
        new_root_key = hkdf(
            current_root_key,
            b"",
            b"new-root-key-after-leave",
            CHAIN_KEY_LENGTH
        )

        self.root_key = new_root_key
        return new_root_key
