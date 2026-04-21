"""
会话状态管理模块
"""

import json
import base64

PROTOCOL_VERSION = "SIP-1.0"


class SessionState:
    """
    会话状态类
    """

    def __init__(self):
        self.version = PROTOCOL_VERSION
        self.agent_id = ""
        self.remote_agent_id = ""
        self.remote_public_key = ""
        self.encryption_key = ""
        self.auth_key = ""
        self.replay_key = ""
        self.message_counter = 0
        self.psk_hash = ""
        self.salt = ""
        self.local_nonce = ""
        self.remote_nonce = ""
        self.created_at = int(time.time() * 1000)
        self.last_activity_at = int(time.time() * 1000)

    def serialize(self) -> str:
        """
        序列化会话状态为JSON字符串

        Returns:
            str: Base64编码的JSON字符串
        """
        import time

        state_dict = {
            "version": self.version,
            "agent_id": self.agent_id,
            "remote_agent_id": self.remote_agent_id,
            "remote_public_key": self.remote_public_key,
            "encryption_key": (
                base64.b64encode(self.encryption_key).decode()
                if isinstance(self.encryption_key, bytes)
                else self.encryption_key
            ),
            "auth_key": (
                base64.b64encode(self.auth_key).decode()
                if isinstance(self.auth_key, bytes)
                else self.auth_key
            ),
            "replay_key": (
                base64.b64encode(self.replay_key).decode()
                if isinstance(self.replay_key, bytes)
                else self.replay_key
            ),
            "message_counter": self.message_counter,
            "psk_hash": (
                base64.b64encode(self.psk_hash).decode()
                if isinstance(self.psk_hash, bytes)
                else self.psk_hash
            ),
            "salt": (
                base64.b64encode(self.salt).decode() if isinstance(self.salt, bytes) else self.salt
            ),
            "local_nonce": self.local_nonce,
            "remote_nonce": self.remote_nonce,
            "created_at": self.created_at,
            "last_activity_at": self.last_activity_at,
        }
        json_str = json.dumps(state_dict)
        serialized = base64.b64encode(json_str.encode()).decode()
        return serialized

    @classmethod
    def deserialize(cls, serialized: str) -> "SessionState":
        """
        反序列化会话状态

        Args:
            serialized: Base64编码的JSON字符串

        Returns:
            SessionState: 会话状态对象
        """
        import time

        json_str = base64.b64decode(serialized).decode()
        state_dict = json.loads(json_str)

        state = cls()
        state.version = state_dict["version"]
        state.agent_id = state_dict["agent_id"]
        state.remote_agent_id = state_dict["remote_agent_id"]
        state.remote_public_key = state_dict["remote_public_key"]
        state.encryption_key = (
            base64.b64decode(state_dict["encryption_key"])
            if isinstance(state_dict["encryption_key"], str)
            else state_dict["encryption_key"]
        )
        state.auth_key = (
            base64.b64decode(state_dict["auth_key"])
            if isinstance(state_dict["auth_key"], str)
            else state_dict["auth_key"]
        )
        state.replay_key = (
            base64.b64decode(state_dict["replay_key"])
            if isinstance(state_dict["replay_key"], str)
            else state_dict["replay_key"]
        )
        state.message_counter = state_dict["message_counter"]
        state.psk_hash = (
            base64.b64decode(state_dict["psk_hash"])
            if isinstance(state_dict["psk_hash"], str)
            else state_dict["psk_hash"]
        )
        state.salt = (
            base64.b64decode(state_dict["salt"])
            if isinstance(state_dict["salt"], str)
            else state_dict["salt"]
        )
        state.local_nonce = state_dict["local_nonce"]
        state.remote_nonce = state_dict["remote_nonce"]
        state.created_at = state_dict["created_at"]
        state.last_activity_at = state_dict["last_activity_at"]

        return state

    def update_last_activity(self) -> None:
        """
        更新最后活动时间
        """
        import time

        self.last_activity_at = int(time.time() * 1000)
