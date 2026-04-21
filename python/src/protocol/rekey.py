"""
Rekey密钥轮换模块
实现密钥轮换流程（前向保密）
"""

import os
import time
import hmac
import hashlib
import base64
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization
from ..crypto.dh import generate_keypair, dh_exchange
from ..crypto.hkdf import hkdf

REKEY_NONCE_LENGTH = 16
PROTOCOL_VERSION = "SIP-1.0"


class RekeyManager:
    """
    Rekey管理器
    """

    def __init__(self, session_state, is_initiator: bool = False):
        """
        构造函数

        Args:
            session_state: 当前会话状态（包含encryption_key, auth_key, replay_key）
            is_initiator: 是否为发起方（影响nonce排列顺序）
        """
        self.session_state = session_state
        self.rekey_sequence = 0
        self.is_initiator = is_initiator

    def create_rekey_request(self, reason: str = "scheduled", key_lifetime: int = 3600) -> dict:
        """
        创建Rekey请求

        Args:
            reason: Rekey原因（scheduled, manual, message_limit）
            key_lifetime: 密钥生命周期（秒）

        Returns:
            dict: Rekey请求消息
        """
        # 1. 生成新临时密钥对
        new_ephemeral_private_key, new_ephemeral_public_key = generate_keypair()

        # 2. 生成nonce
        nonce = os.urandom(REKEY_NONCE_LENGTH)

        # 3. 序列化公钥
        new_ephemeral_pub_bytes = new_ephemeral_public_key.public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )

        # 4. 构建请求数据
        request_data = {
            "ephemeral_pub": base64.b64encode(new_ephemeral_pub_bytes).decode(),
            "nonce": base64.b64encode(nonce).decode(),
            "reason": reason,
            "key_lifetime": key_lifetime,
        }

        # 5. 使用当前auth_key签名
        signature_data = (
            f"{REKEY_NONCE_LENGTH}:{request_data['ephemeral_pub']}:"
            f"{request_data['nonce']}:"
            f"{reason}:{key_lifetime}"
        ).encode()
        signature = hmac.new(
            self.session_state["auth_key"], signature_data, hashlib.sha256
        ).digest()
        signature_b64 = base64.b64encode(signature).decode()

        # 6. 构建Rekey_Request消息
        rekey_request = {
            "version": PROTOCOL_VERSION,
            "type": "rekey",
            "step": "request",
            "timestamp": int(time.time() * 1000),
            "sequence": self.rekey_sequence,
            "request": request_data,
            "signature": signature_b64,
        }

        # 7. 保存临时密钥（用于后续密钥派生）
        self._temp_new_ephemeral_private_key = new_ephemeral_private_key
        self._temp_new_ephemeral_nonce = nonce
        self.rekey_sequence += 1

        return rekey_request

    def validate_rekey_request(self, rekey_request: dict) -> bool:
        """
        验证Rekey请求

        Args:
            rekey_request: Rekey请求消息

        Returns:
            bool: 是否有效
        """
        try:
            # 1. 验证时间戳（±5分钟）
            timestamp = rekey_request["timestamp"]
            current_time = int(time.time() * 1000)
            if abs(current_time - timestamp) > 300000:  # 5分钟
                return False

            # 2. 验证签名
            signature = base64.b64decode(rekey_request["signature"])
            request_data = rekey_request["request"]

            signature_data = (
                f"{REKEY_NONCE_LENGTH}:{request_data['ephemeral_pub']}:"
                f"{request_data['nonce']}:"
                f"{request_data['reason']}:"
                f"{request_data['key_lifetime']}"
            ).encode()

            expected_signature = hmac.new(
                self.session_state["auth_key"], signature_data, hashlib.sha256
            ).digest()

            if not hmac.compare_digest(signature, expected_signature):
                return False

            # 3. 验证序列号（第一次可以是0，之后必须严格递增）
            if self.rekey_sequence > 0 and rekey_request["sequence"] <= self.rekey_sequence:
                return False

            return True

        except (ValueError, KeyError, AttributeError):
            return False

    def process_rekey_request(self, rekey_request: dict) -> dict:
        """
        处理Rekey请求并生成响应

        Args:
            rekey_request: Rekey请求消息

        Returns:
            dict: Rekey响应消息
        """
        # 1. 验证请求
        if not self.validate_rekey_request(rekey_request):
            raise ValueError("Invalid rekey request")

        # 更新rekey_sequence
        self.rekey_sequence = rekey_request["sequence"]

        # 2. 生成新临时密钥对
        new_ephemeral_private_key, new_ephemeral_public_key = generate_keypair()

        # 3. 生成nonce
        nonce = os.urandom(REKEY_NONCE_LENGTH)

        # 4. 序列化公钥
        new_ephemeral_pub_bytes = new_ephemeral_public_key.public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )

        # 5. 解析对方的临时公钥
        peer_ephemeral_pub_bytes = base64.b64decode(rekey_request["request"]["ephemeral_pub"])
        peer_ephemeral_public_key = x25519.X25519PublicKey.from_public_bytes(
            peer_ephemeral_pub_bytes
        )

        # 6. 执行DH密钥交换
        shared_secret = dh_exchange(new_ephemeral_private_key, peer_ephemeral_public_key)

        # 7. 派生新密钥（响应方：发起方nonce在前，响应方nonce在后）
        initiator_nonce = base64.b64decode(rekey_request["request"]["nonce"])
        responder_nonce = nonce
        new_keys = self._derive_new_keys(
            shared_secret=shared_secret,
            initiator_nonce=initiator_nonce,
            responder_nonce=responder_nonce,
        )

        # 8. 构建响应数据
        response_data = {
            "ephemeral_pub": base64.b64encode(new_ephemeral_pub_bytes).decode(),
            "nonce": base64.b64encode(nonce).decode(),
        }

        # 9. 使用当前auth_key签名
        signature_data = (
            f"{REKEY_NONCE_LENGTH}:{response_data['ephemeral_pub']}:" f"{response_data['nonce']}"
        ).encode()
        signature = hmac.new(
            self.session_state["auth_key"], signature_data, hashlib.sha256
        ).digest()
        signature_b64 = base64.b64encode(signature).decode()

        # 10. 构建Rekey_Response消息
        rekey_response = {
            "version": PROTOCOL_VERSION,
            "type": "rekey",
            "step": "response",
            "timestamp": int(time.time() * 1000),
            "sequence": rekey_request["sequence"],
            "response": response_data,
            "signature": signature_b64,
        }

        # 11. 保存临时数据（用于后续密钥切换）
        self._temp_new_keys = new_keys
        self._temp_new_ephemeral_private_key = new_ephemeral_private_key
        self._temp_new_ephemeral_nonce = nonce

        return rekey_response

    def validate_rekey_response(self, rekey_response: dict) -> bool:
        """
        验证Rekey响应

        Args:
            rekey_response: Rekey响应消息

        Returns:
            bool: 是否有效
        """
        try:
            # 1. 验证时间戳（±5分钟）
            timestamp = rekey_response["timestamp"]
            current_time = int(time.time() * 1000)
            if abs(current_time - timestamp) > 300000:  # 5分钟
                return False

            # 2. 验证签名
            signature = base64.b64decode(rekey_response["signature"])
            response_data = rekey_response["response"]

            signature_data = (
                f"{REKEY_NONCE_LENGTH}:{response_data['ephemeral_pub']}:"
                f"{response_data['nonce']}"
            ).encode()

            expected_signature = hmac.new(
                self.session_state["auth_key"], signature_data, hashlib.sha256
            ).digest()

            if not hmac.compare_digest(signature, expected_signature):
                return False

            # 3. 验证序列号
            if rekey_response["sequence"] != self.rekey_sequence - 1:
                return False

            return True

        except (ValueError, KeyError, AttributeError):
            return False

    def process_rekey_response(self, rekey_response: dict) -> dict:
        """
        处理Rekey响应并派生新密钥

        Args:
            rekey_response: Rekey响应消息

        Returns:
            dict: 新密钥
        """
        # 1. 验证响应
        if not self.validate_rekey_response(rekey_response):
            raise ValueError("Invalid rekey response")

        # 2. 解析对方的临时公钥
        peer_ephemeral_pub_bytes = base64.b64decode(rekey_response["response"]["ephemeral_pub"])
        peer_ephemeral_public_key = x25519.X25519PublicKey.from_public_bytes(
            peer_ephemeral_pub_bytes
        )

        # 3. 执行DH密钥交换
        shared_secret = dh_exchange(self._temp_new_ephemeral_private_key, peer_ephemeral_public_key)

        # 4. 派生新密钥（发起方：发起方nonce在前，响应方nonce在后）
        initiator_nonce = self._temp_new_ephemeral_nonce
        responder_nonce = base64.b64decode(rekey_response["response"]["nonce"])
        new_keys = self._derive_new_keys(
            shared_secret=shared_secret,
            initiator_nonce=initiator_nonce,
            responder_nonce=responder_nonce,
        )

        # 5. 清理临时数据
        del self._temp_new_ephemeral_private_key
        del self._temp_new_ephemeral_nonce

        return new_keys

    def apply_new_keys(self, new_keys: dict):
        """
        应用新密钥到会话状态

        Args:
            new_keys: 新密钥字典
        """
        # 更新会话密钥
        self.session_state["encryption_key"] = new_keys["encryption_key"]
        self.session_state["auth_key"] = new_keys["auth_key"]
        self.session_state["replay_key"] = new_keys["replay_key"]

        # 增加rekey计数
        if "rekey_count" not in self.session_state:
            self.session_state["rekey_count"] = 0
        self.session_state["rekey_count"] += 1

    def _derive_new_keys(
        self, shared_secret: bytes, initiator_nonce: bytes, responder_nonce: bytes
    ) -> dict:
        """
        派生新密钥

        Args:
            shared_secret: DH共享密钥
            initiator_nonce: 发起方的nonce
            responder_nonce: 响应方的nonce

        Returns:
            dict: 新密钥字典
        """
        # 组合输入（确保双方使用相同的顺序）
        combined = (
            shared_secret
            + self.session_state["encryption_key"]
            + self.session_state["auth_key"]
            + self.session_state["replay_key"]
            + initiator_nonce  # 发起方nonce在前
            + responder_nonce  # 响应方nonce在后
        )

        # 使用HKDF派生新密钥
        salt = b"SIPRekey"
        info = b"SIP-rekey"
        output_length = 96  # 32 + 32 + 32

        derived_keys = hkdf(combined, salt, info, output_length)

        # 分割密钥
        encryption_key = derived_keys[0:32]
        auth_key = derived_keys[32:64]
        replay_key = derived_keys[64:96]

        return {
            "encryption_key": encryption_key,
            "auth_key": auth_key,
            "replay_key": replay_key,
        }
