"""
SIP MCP Server模块
让Agent能通过MCP协议调用SIP加密通道

实现MCP tool:
- sip_encrypt: 加密消息
- sip_decrypt: 解密消息
- sip_handshake: 握手（发起/响应/完成）
- sip_rekey: 密钥轮换

使用stdio JSON-RPC 2.0协议通信。

启动方式:
    python -m sip_protocol.transport.sip_mcp_server --psk <shared-key>
"""

import argparse
import base64
import json
import sys
import traceback
from typing import Any, Dict, Optional

from .encrypted_channel import EncryptedChannel, ChannelConfig, ChannelState
from .message import AgentMessage, MessageType, ControlAction

# ──────────────── JSON-RPC 2.0 ────────────────


class JSONRPCError(Exception):
    """JSON-RPC 错误"""

    def __init__(self, code: int, message: str, data: Any = None):
        self.code = code
        self.message = message
        self.data = data
        super().__init__(message)


# Standard JSON-RPC error codes
PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603

# SIP-specific error codes
SIP_NOT_INITIALIZED = -32001
SIP_HANDSHAKE_REQUIRED = -32002
SIP_ENCRYPTION_FAILED = -32003
SIP_DECRYPTION_FAILED = -32004
SIP_HANDSHAKE_FAILED = -32005
SIP_REKEY_FAILED = -32006


def make_response(request_id: Any, result: Any) -> str:
    """构建JSON-RPC成功响应"""
    return json.dumps({"jsonrpc": "2.0", "id": request_id, "result": result})


def make_error(request_id: Any, code: int, message: str, data: Any = None) -> str:
    """构建JSON-RPC错误响应"""
    error: Dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        error["data"] = data
    return json.dumps({"jsonrpc": "2.0", "id": request_id, "error": error})


# ──────────────── MCP Tool定义 ────────────────


MCP_TOOLS = [
    {
        "name": "sip_encrypt",
        "description": (
            "使用SIP协议加密一条消息。要求通道已通过sip_handshake建立。"
            "返回加密后的payload（base64编码的JSON）。"
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "plaintext": {
                    "type": "string",
                    "description": "要加密的明文消息",
                },
                "recipient_id": {
                    "type": "string",
                    "description": "接收方Agent ID（可选，默认使用握手时的对方）",
                },
            },
            "required": ["plaintext"],
        },
    },
    {
        "name": "sip_decrypt",
        "description": (
            "使用SIP协议解密一条消息。要求通道已通过sip_handshake建立。"
            "输入加密消息的JSON字符串，返回解密后的明文。"
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "encrypted_message": {
                    "type": "string",
                    "description": "加密消息的JSON字符串（AgentMessage的JSON表示）",
                },
            },
            "required": ["encrypted_message"],
        },
    },
    {
        "name": "sip_handshake",
        "description": (
            "执行SIP握手协议的三重DH密钥交换。"
            "支持三种角色：initiator（发起方）、responder（响应方）、complete（发起方完成）。"
            "initiator: 返回握手Hello消息，等待对方的Auth响应。"
            "responder: 输入收到的Hello消息，返回Auth响应并完成握手。"
            "complete: 输入收到的Auth消息，完成发起方握手。"
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "role": {
                    "type": "string",
                    "enum": ["initiator", "responder", "complete"],
                    "description": "握手角色",
                },
                "agent_id": {
                    "type": "string",
                    "description": "本地Agent ID",
                },
                "message": {
                    "type": "string",
                    "description": (
                        "对于responder: 收到的Hello消息JSON；" "对于complete: 收到的Auth消息JSON"
                    ),
                },
            },
            "required": ["role", "agent_id"],
        },
    },
    {
        "name": "sip_rekey",
        "description": (
            "执行SIP密钥轮换（Rekey），实现前向保密。"
            "要求通道已通过sip_handshake建立。"
            "支持initiator（发起轮换）和responder（响应轮换）两种角色。"
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "role": {
                    "type": "string",
                    "enum": ["initiator", "responder"],
                    "description": "Rekey角色",
                },
                "message": {
                    "type": "string",
                    "description": "对于responder: 收到的rekey请求消息JSON",
                },
            },
            "required": ["role"],
        },
    },
]


# ──────────────── SIP MCP Server ────────────────


class SipMcpServer:
    """
    SIP MCP Server

    通过MCP协议暴露SIP加密通道功能给Agent使用。
    使用stdio JSON-RPC 2.0通信。

    生命周期：
    1. initialize → 收到PSK和agent_id
    2. sip_handshake → 建立加密通道
    3. sip_encrypt / sip_decrypt → 加密通信
    4. sip_rekey → 密钥轮换（可选）
    """

    def __init__(self, psk: bytes, agent_id: str = "mcp-agent"):
        self._channel = EncryptedChannel(
            agent_id=agent_id,
            psk=psk,
            config=ChannelConfig(
                rekey_after_messages=10000,
                rekey_after_seconds=3600,
            ),
        )
        self._agent_id = agent_id
        self._psk = psk
        self._initialized = False

        # Rekey状态
        self._rekey_request_json: Optional[str] = None

    # ──────────────── MCP协议方法 ────────────────

    def handle_initialize(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """处理MCP initialize请求"""
        self._initialized = True
        return {
            "protocolVersion": "2024-11-05",
            "capabilities": {
                "tools": {},
            },
            "serverInfo": {
                "name": "sip-mcp-server",
                "version": "1.0.0",
            },
        }

    def handle_tools_list(self, _params: Dict[str, Any]) -> Dict[str, Any]:
        """返回可用工具列表"""
        return {"tools": MCP_TOOLS}

    def handle_tools_call(self, params: Dict[str, Any]) -> Any:
        """处理工具调用"""
        tool_name = params.get("name", "")
        arguments = params.get("arguments", {})

        handler_map = {
            "sip_encrypt": self._handle_encrypt,
            "sip_decrypt": self._handle_decrypt,
            "sip_handshake": self._handle_handshake,
            "sip_rekey": self._handle_rekey,
        }

        handler = handler_map.get(tool_name)
        if handler is None:
            raise JSONRPCError(
                METHOD_NOT_FOUND,
                f"未知工具: {tool_name}",
            )

        return handler(arguments)

    # ──────────────── Tool实现 ────────────────

    def _handle_encrypt(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """sip_encrypt工具实现"""
        plaintext = args.get("plaintext")
        if not plaintext:
            raise JSONRPCError(INVALID_PARAMS, "plaintext参数必填")

        if not self._channel.is_established:
            raise JSONRPCError(
                SIP_HANDSHAKE_REQUIRED,
                "加密通道未建立，请先调用sip_handshake",
            )

        try:
            recipient_id = args.get("recipient_id")
            encrypted_msg = self._channel.send(plaintext, recipient_id)

            # 序列化加密后的消息
            msg_json = encrypted_msg.to_json()
            msg_b64 = base64.b64encode(msg_json.encode()).decode()

            return {
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps(
                            {
                                "success": True,
                                "message_id": encrypted_msg.id,
                                "encrypted_message": msg_b64,
                                "message_type": encrypted_msg.type.value,
                            },
                            ensure_ascii=False,
                        ),
                    }
                ],
            }
        except Exception as e:
            raise JSONRPCError(
                SIP_ENCRYPTION_FAILED,
                f"加密失败: {e}",
            ) from e

    def _handle_decrypt(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """sip_decrypt工具实现"""
        encrypted_message = args.get("encrypted_message")
        if not encrypted_message:
            raise JSONRPCError(INVALID_PARAMS, "encrypted_message参数必填")

        if not self._channel.is_established:
            raise JSONRPCError(
                SIP_HANDSHAKE_REQUIRED,
                "加密通道未建立，请先调用sip_handshake",
            )

        try:
            # 解码消息
            # 支持base64编码和直接JSON两种格式
            try:
                msg_json = base64.b64decode(encrypted_message).decode()
            except Exception:
                msg_json = encrypted_message

            agent_msg = AgentMessage.from_json(msg_json)

            plaintext = self._channel.receive(agent_msg)

            return {
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps(
                            {
                                "success": True,
                                "plaintext": plaintext,
                                "sender_id": agent_msg.sender_id,
                            },
                            ensure_ascii=False,
                        ),
                    }
                ],
            }
        except Exception as e:
            raise JSONRPCError(
                SIP_DECRYPTION_FAILED,
                f"解密失败: {e}",
            ) from e

    def _handle_handshake(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """sip_handshake工具实现"""
        role = args.get("role")
        agent_id = args.get("agent_id", self._agent_id)

        if not role:
            raise JSONRPCError(INVALID_PARAMS, "role参数必填")

        if role == "initiator":
            return self._handshake_initiator(agent_id)
        elif role == "responder":
            message = args.get("message")
            if not message:
                raise JSONRPCError(
                    INVALID_PARAMS,
                    "responder角色需要提供message参数（Hello消息）",
                )
            return self._handshake_responder(agent_id, message)
        elif role == "complete":
            message = args.get("message")
            if not message:
                raise JSONRPCError(
                    INVALID_PARAMS,
                    "complete角色需要提供message参数（Auth消息）",
                )
            return self._handshake_complete(message)
        else:
            raise JSONRPCError(
                INVALID_PARAMS,
                f"未知握手角色: {role}，支持: initiator, responder, complete",
            )

    def _handshake_initiator(self, agent_id: str) -> Dict[str, Any]:
        """发起握手"""
        try:
            hello_msg = self._channel.initiate()
            hello_json = hello_msg.to_json()
            hello_b64 = base64.b64encode(hello_json.encode()).decode()

            return {
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps(
                            {
                                "success": True,
                                "role": "initiator",
                                "state": self._channel.state.value,
                                "hello_message": hello_b64,
                                "instruction": (
                                    "请将hello_message发送给对方Agent，"
                                    "对方需要用role=responder处理，"
                                    "然后用role=complete完成握手。"
                                ),
                            },
                            ensure_ascii=False,
                        ),
                    }
                ],
            }
        except Exception as e:
            raise JSONRPCError(
                SIP_HANDSHAKE_FAILED,
                f"发起握手失败: {e}",
            ) from e

    def _handshake_responder(self, agent_id: str, message: str) -> Dict[str, Any]:
        """响应握手"""
        try:
            # 解码对方发来的Hello消息
            try:
                msg_json = base64.b64decode(message).decode()
            except Exception:
                msg_json = message

            hello_msg = AgentMessage.from_json(msg_json)
            auth_msg = self._channel.respond_to_handshake(hello_msg)
            auth_json = auth_msg.to_json()
            auth_b64 = base64.b64encode(auth_json.encode()).decode()

            return {
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps(
                            {
                                "success": True,
                                "role": "responder",
                                "state": self._channel.state.value,
                                "auth_message": auth_b64,
                                "remote_agent_id": hello_msg.sender_id,
                                "instruction": (
                                    "通道已建立！请将auth_message发回给发起方，"
                                    "发起方需要用role=complete完成握手。"
                                ),
                            },
                            ensure_ascii=False,
                        ),
                    }
                ],
            }
        except Exception as e:
            raise JSONRPCError(
                SIP_HANDSHAKE_FAILED,
                f"响应握手失败: {e}",
            ) from e

    def _handshake_complete(self, message: str) -> Dict[str, Any]:
        """完成握手（发起方）"""
        try:
            # 解码Auth消息
            try:
                msg_json = base64.b64decode(message).decode()
            except Exception:
                msg_json = message

            auth_msg = AgentMessage.from_json(msg_json)
            self._channel.complete_handshake(auth_msg)

            return {
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps(
                            {
                                "success": True,
                                "role": "initiator",
                                "state": self._channel.state.value,
                                "remote_agent_id": auth_msg.sender_id,
                                "message": "握手完成，加密通道已建立！",
                            },
                            ensure_ascii=False,
                        ),
                    }
                ],
            }
        except Exception as e:
            raise JSONRPCError(
                SIP_HANDSHAKE_FAILED,
                f"完成握手失败: {e}",
            ) from e

    def _handle_rekey(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """sip_rekey工具实现"""
        role = args.get("role")

        if not role:
            raise JSONRPCError(INVALID_PARAMS, "role参数必填")

        if not self._channel.is_established:
            raise JSONRPCError(
                SIP_HANDSHAKE_REQUIRED,
                "加密通道未建立，请先调用sip_handshake",
            )

        if role == "initiator":
            return self._rekey_initiator()
        elif role == "responder":
            message = args.get("message")
            if not message:
                raise JSONRPCError(
                    INVALID_PARAMS,
                    "responder角色需要提供message参数（rekey请求）",
                )
            return self._rekey_responder(message)
        else:
            raise JSONRPCError(
                INVALID_PARAMS,
                f"未知rekey角色: {role}",
            )

    def _rekey_initiator(self) -> Dict[str, Any]:
        """发起密钥轮换"""
        try:
            # 通过channel内部触发rekey
            # 由于EncryptedChannel的rekey是内部机制，
            # 我们直接操作session_keys来模拟密钥轮换
            if self._channel._session_keys is None:
                raise JSONRPCError(SIP_REKEY_FAILED, "无活动会话密钥")

            from ..protocol.rekey import RekeyManager

            session_state_dict = {
                "encryption_key": self._channel._session_keys["encryption_key"],
                "auth_key": self._channel._session_keys["auth_key"],
                "replay_key": self._channel._session_keys["replay_key"],
            }
            manager = RekeyManager(session_state_dict, is_initiator=True)
            rekey_request = manager.create_rekey_request()

            # 保存rekey状态
            self._rekey_request_json = json.dumps(rekey_request)
            self._rekey_manager = manager

            request_b64 = base64.b64encode(self._rekey_request_json.encode()).decode()

            return {
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps(
                            {
                                "success": True,
                                "role": "initiator",
                                "rekey_request": request_b64,
                                "instruction": (
                                    "请将rekey_request发送给对方Agent，"
                                    "对方需要用role=responder处理。"
                                ),
                            },
                            ensure_ascii=False,
                        ),
                    }
                ],
            }
        except JSONRPCError:
            raise
        except Exception as e:
            raise JSONRPCError(
                SIP_REKEY_FAILED,
                f"发起密钥轮换失败: {e}",
            ) from e

    def _rekey_responder(self, message: str) -> Dict[str, Any]:
        """响应密钥轮换"""
        try:
            # 解码rekey请求
            try:
                msg_json = base64.b64decode(message).decode()
            except Exception:
                msg_json = message

            rekey_request = json.loads(msg_json)

            if self._channel._session_keys is None:
                raise JSONRPCError(SIP_REKEY_FAILED, "无活动会话密钥")

            from ..protocol.rekey import RekeyManager

            session_state_dict = {
                "encryption_key": self._channel._session_keys["encryption_key"],
                "auth_key": self._channel._session_keys["auth_key"],
                "replay_key": self._channel._session_keys["replay_key"],
            }
            manager = RekeyManager(session_state_dict, is_initiator=False)

            # 验证请求
            if not manager.validate_rekey_request(rekey_request):
                raise JSONRPCError(SIP_REKEY_FAILED, "rekey请求验证失败")

            # 处理请求并生成响应
            rekey_response = manager.process_rekey_request(rekey_request)

            # 应用新密钥
            new_keys = manager._temp_new_keys
            manager.apply_new_keys(new_keys)

            # 更新channel的session_keys
            self._channel._session_keys.update(
                {
                    "encryption_key": new_keys["encryption_key"],
                    "auth_key": new_keys["auth_key"],
                    "replay_key": new_keys["replay_key"],
                }
            )

            response_b64 = base64.b64encode(json.dumps(rekey_response).encode()).decode()

            return {
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps(
                            {
                                "success": True,
                                "role": "responder",
                                "rekey_response": response_b64,
                                "message": "密钥已轮换（响应方）",
                            },
                            ensure_ascii=False,
                        ),
                    }
                ],
            }
        except JSONRPCError:
            raise
        except Exception as e:
            raise JSONRPCError(
                SIP_REKEY_FAILED,
                f"响应密钥轮换失败: {e}",
            ) from e

    # ──────────────── JSON-RPC路由 ────────────────

    def handle_request(self, request: Dict[str, Any]) -> str:
        """处理单个JSON-RPC请求，返回响应JSON字符串"""
        request_id = request.get("id")

        # 验证JSON-RPC版本
        if request.get("jsonrpc") != "2.0":
            return make_error(request_id, INVALID_REQUEST, "无效的JSON-RPC请求")

        method = request.get("method", "")
        params = request.get("params", {})

        # 路由表
        method_map = {
            "initialize": self.handle_initialize,
            "notifications/initialized": lambda p: None,  # 通知，无响应
            "tools/list": self.handle_tools_list,
            "tools/call": self.handle_tools_call,
        }

        handler = method_map.get(method)
        if handler is None:
            return make_error(
                request_id,
                METHOD_NOT_FOUND,
                f"未知方法: {method}",
            )

        # 通知不需要响应
        if method == "notifications/initialized":
            return ""

        try:
            result = handler(params)
            return make_response(request_id, result)
        except JSONRPCError as e:
            return make_error(request_id, e.code, e.message, e.data)
        except Exception as e:
            return make_error(
                request_id,
                INTERNAL_ERROR,
                f"内部错误: {e}",
            )


# ──────────────── Stdio运行器 ────────────────


def run_stdio_server(psk: bytes, agent_id: str = "mcp-agent") -> None:
    """
    以stdio模式运行MCP Server

    从stdin读取JSON-RPC请求，向stdout写出JSON-RPC响应。
    日志输出到stderr。
    """
    server = SipMcpServer(psk=psk, agent_id=agent_id)

    print(
        f"SIP MCP Server started (agent_id={agent_id})",
        file=sys.stderr,
    )

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
        if response:  # 空字符串表示通知，不需要响应
            sys.stdout.write(response + "\n")
            sys.stdout.flush()


# ──────────────── CLI入口 ────────────────


def main() -> None:
    """CLI入口"""
    parser = argparse.ArgumentParser(description="SIP MCP Server")
    parser.add_argument(
        "--psk",
        required=True,
        help="预共享密钥（字符串）",
    )
    parser.add_argument(
        "--agent-id",
        default="mcp-agent",
        help="Agent ID（默认: mcp-agent）",
    )
    args = parser.parse_args()

    run_stdio_server(
        psk=args.psk.encode("utf-8"),
        agent_id=args.agent_id,
    )


if __name__ == "__main__":
    main()
