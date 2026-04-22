#!/usr/bin/env python3
"""
SIP MCP Server 独立启动脚本

解决相对导入问题，可从任意位置运行。

用法:
    python3 sip_mcp_server_standalone.py --psk <密钥> [--agent-id <ID>]

或配置为MCP Server:
    {
        "command": "python3",
        "args": ["sip_mcp_server_standalone.py", "--psk", "<密钥>", "--agent-id", "hermes"]
    }
"""

import argparse
import base64
import json
import os
import sys
import time
from typing import Any, Dict, Optional

# 将包根目录添加到路径
_SRC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "src")
if _SRC_DIR not in sys.path:
    sys.path.insert(0, _SRC_DIR)

# 导入需要的模块
from crypto.xchacha20_poly1305 import (
    encrypt_xchacha20_poly1305,
    decrypt_xchacha20_poly1305,
    generate_nonce,
)
from crypto.hkdf import hkdf

# ──────────────── JSON-RPC 2.0 ────────────────

PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603
SIP_NOT_INITIALIZED = -32001
SIP_HANDSHAKE_REQUIRED = -32002
SIP_ENCRYPTION_FAILED = -32003
SIP_DECRYPTION_FAILED = -32004
SIP_HANDSHAKE_FAILED = -32005


class JSONRPCError(Exception):
    def __init__(self, code: int, message: str):
        self.code = code
        self.message = message
        super().__init__(message)


def make_response(request_id: Any, result: Any) -> str:
    return json.dumps({"jsonrpc": "2.0", "id": request_id, "result": result})


def make_error(request_id: Any, code: int, message: str) -> str:
    return json.dumps(
        {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}
    )


# ──────────────── 简化版加密通道 ────────────────


class SimpleEncryptedChannel:
    """简化版加密通道，使用PSK直接派生密钥"""

    def __init__(self, agent_id: str, psk: bytes):
        self.agent_id = agent_id
        self._keys = self._derive_keys(psk)
        self._send_nonce = 0
        self._recv_nonce = 0
        self.is_established = True

    def _derive_keys(self, psk: bytes) -> Dict[str, bytes]:
        """从PSK派生加密密钥"""
        enc_key = hkdf(psk, b"", b"sip-encryption-key", 32)
        auth_key = hkdf(psk, b"", b"sip-auth-key", 32)
        return {"encryption_key": enc_key, "auth_key": auth_key}

    def encrypt(self, plaintext: str, recipient_id: str = "") -> Dict[str, Any]:
        """加密消息"""
        nonce = generate_nonce()
        ct, tag = encrypt_xchacha20_poly1305(
            self._keys["encryption_key"], plaintext.encode(), nonce
        )
        msg = {
            "id": f"msg-{int(time.time()*1000)}",
            "sender_id": self.agent_id,
            "recipient_id": recipient_id,
            "type": "encrypted",
            "payload": base64.b64encode(ct).decode(),
            "nonce": base64.b64encode(nonce).decode(),
            "tag": base64.b64encode(tag).decode(),
            "sequence": self._send_nonce,
            "timestamp": time.time(),
        }
        self._send_nonce += 1
        return msg

    def decrypt(self, msg: Dict[str, Any]) -> str:
        """解密消息"""
        ct = base64.b64decode(msg["payload"])
        nonce = base64.b64decode(msg["nonce"])
        tag = base64.b64decode(msg.get("tag", ""))
        pt = decrypt_xchacha20_poly1305(self._keys["encryption_key"], ct, nonce, tag)
        return pt.decode()


# ──────────────── MCP工具定义 ────────────────

MCP_TOOLS = [
    {
        "name": "sip_encrypt",
        "description": "使用SIP协议加密一条消息。返回加密后的payload（base64编码的JSON）。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "plaintext": {"type": "string", "description": "要加密的明文消息"},
                "recipient_id": {"type": "string", "description": "接收方Agent ID"},
            },
            "required": ["plaintext"],
        },
    },
    {
        "name": "sip_decrypt",
        "description": "使用SIP协议解密一条消息。输入加密消息的JSON字符串，返回解密后的明文。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "encrypted_message": {"type": "string", "description": "加密消息的JSON字符串"},
            },
            "required": ["encrypted_message"],
        },
    },
]


# ──────────────── MCP Server ────────────────


class SipMcpServerStandalone:
    """独立版SIP MCP Server，不依赖相对导入"""

    def __init__(self, psk: bytes, agent_id: str):
        self._channel = SimpleEncryptedChannel(agent_id, psk)
        self._agent_id = agent_id

    def handle_initialize(self, _params: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "protocolVersion": "2024-11-05",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "sip-mcp-server", "version": "1.0.0"},
        }

    def handle_tools_list(self, _params: Dict[str, Any]) -> Dict[str, Any]:
        return {"tools": MCP_TOOLS}

    def handle_tools_call(self, params: Dict[str, Any]) -> Any:
        name = params.get("name", "")
        args = params.get("arguments", {})

        if name == "sip_encrypt":
            return self._encrypt(args)
        if name == "sip_decrypt":
            return self._decrypt(args)
        raise JSONRPCError(METHOD_NOT_FOUND, f"未知工具: {name}")

    def _encrypt(self, args: Dict[str, Any]) -> Dict[str, Any]:
        plaintext = args.get("plaintext", "")
        if not plaintext:
            raise JSONRPCError(INVALID_PARAMS, "plaintext参数必填")
        try:
            msg = self._channel.encrypt(plaintext, args.get("recipient_id", ""))
            msg_json = json.dumps(msg, ensure_ascii=False)
            msg_b64 = base64.b64encode(msg_json.encode()).decode()
            return {
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps(
                            {"success": True, "encrypted_message": msg_b64}, ensure_ascii=False
                        ),
                    }
                ]
            }
        except (ValueError, RuntimeError, OSError) as e:
            raise JSONRPCError(SIP_ENCRYPTION_FAILED, f"加密失败: {e}") from e

    def _decrypt(self, args: Dict[str, Any]) -> Dict[str, Any]:
        encrypted_message = args.get("encrypted_message", "")
        if not encrypted_message:
            raise JSONRPCError(INVALID_PARAMS, "encrypted_message参数必填")
        try:
            try:
                msg_json = base64.b64decode(encrypted_message).decode()
            except (ValueError, TypeError):
                msg_json = encrypted_message
            msg = json.loads(msg_json)
            plaintext = self._channel.decrypt(msg)
            return {
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps(
                            {
                                "success": True,
                                "plaintext": plaintext,
                                "sender_id": msg.get("sender_id", ""),
                            },
                            ensure_ascii=False,
                        ),
                    }
                ]
            }
        except (ValueError, RuntimeError, OSError, KeyError) as e:
            raise JSONRPCError(SIP_DECRYPTION_FAILED, f"解密失败: {e}") from e

    def handle_request(self, request: Dict[str, Any]) -> str:
        request_id = request.get("id")
        if request.get("jsonrpc") != "2.0":
            return make_error(request_id, INVALID_REQUEST, "无效的JSON-RPC请求")

        method = request.get("method", "")
        params = request.get("params", {})

        if method == "notifications/initialized":
            return ""

        method_map = {
            "initialize": self.handle_initialize,
            "tools/list": self.handle_tools_list,
            "tools/call": self.handle_tools_call,
        }

        handler = method_map.get(method)
        if handler is None:
            return make_error(request_id, METHOD_NOT_FOUND, f"未知方法: {method}")

        try:
            result = handler(params)
            return make_response(request_id, result)
        except JSONRPCError as e:
            return make_error(request_id, e.code, e.message)
        except (ValueError, RuntimeError, OSError, KeyError) as e:
            return make_error(request_id, INTERNAL_ERROR, f"内部错误: {e}")


def run_stdio(psk: bytes, agent_id: str) -> None:
    """以stdio模式运行"""
    server = SipMcpServerStandalone(psk=psk, agent_id=agent_id)
    print(f"SIP MCP Server started (agent_id={agent_id})", file=sys.stderr)

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            request = json.loads(line)
        except json.JSONDecodeError as e:
            sys.stdout.write(make_error(None, PARSE_ERROR, f"JSON解析错误: {e}") + "\n")
            sys.stdout.flush()
            continue

        response = server.handle_request(request)
        if response:
            sys.stdout.write(response + "\n")
            sys.stdout.flush()


def main() -> None:
    parser = argparse.ArgumentParser(description="SIP MCP Server (独立版)")
    parser.add_argument("--psk", required=True, help="预共享密钥")
    parser.add_argument("--agent-id", default="mcp-agent", help="Agent ID")
    args = parser.parse_args()
    run_stdio(psk=args.psk.encode("utf-8"), agent_id=args.agent_id)


if __name__ == "__main__":
    main()
