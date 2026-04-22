"""
SIP MCP Server测试
测试MCP协议封装的SIP加密通道功能
"""

import base64
import json
import pytest
from unittest.mock import patch

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.transport.sip_mcp_server import (
    SipMcpServer,
    JSONRPCError,
    make_response,
    make_error,
    run_stdio_server,
    PARSE_ERROR,
    INVALID_REQUEST,
    METHOD_NOT_FOUND,
    INVALID_PARAMS,
    INTERNAL_ERROR,
    SIP_HANDSHAKE_REQUIRED,
    SIP_ENCRYPTION_FAILED,
    SIP_DECRYPTION_FAILED,
    SIP_HANDSHAKE_FAILED,
)
from src.transport.message import AgentMessage, MessageType, ControlAction
from src.transport.encrypted_channel import ChannelState

# ──────────────── 测试辅助 ────────────────


PSK = b"test-psk-key-for-mcp-testing!!"


def _create_paired_servers():
    """创建一对配对的MCP Server（模拟两方通信）"""
    server_a = SipMcpServer(psk=PSK, agent_id="agent-a")
    server_b = SipMcpServer(psk=PSK, agent_id="agent-b")
    return server_a, server_b


def _perform_handshake(server_a, server_b):
    """在两个server之间完成完整握手"""
    # Agent A 发起握手
    result_a = server_a._handle_handshake({"role": "initiator", "agent_id": "agent-a"})
    hello_b64 = json.loads(result_a["content"][0]["text"])["hello_message"]

    # Agent B 响应握手
    result_b = server_b._handle_handshake(
        {
            "role": "responder",
            "agent_id": "agent-b",
            "message": hello_b64,
        }
    )
    auth_b64 = json.loads(result_b["content"][0]["text"])["auth_message"]

    # Agent A 完成握手
    server_a._handle_handshake(
        {
            "role": "complete",
            "message": auth_b64,
        }
    )


def _get_text_from_content(result):
    """从MCP响应的content中提取text"""
    return json.loads(result["content"][0]["text"])


# ──────────────── JSON-RPC辅助测试 ────────────────


class TestJSONRPCHelpers:
    """JSON-RPC工具函数测试"""

    def test_make_response(self):
        resp = make_response(1, {"status": "ok"})
        parsed = json.loads(resp)
        assert parsed["jsonrpc"] == "2.0"
        assert parsed["id"] == 1
        assert parsed["result"] == {"status": "ok"}

    def test_make_error(self):
        resp = make_error(2, -32600, "Invalid Request")
        parsed = json.loads(resp)
        assert parsed["jsonrpc"] == "2.0"
        assert parsed["id"] == 2
        assert parsed["error"]["code"] == -32600
        assert parsed["error"]["message"] == "Invalid Request"

    def test_make_error_with_data(self):
        resp = make_error(3, -32000, "Custom Error", data={"detail": "info"})
        parsed = json.loads(resp)
        assert parsed["error"]["data"] == {"detail": "info"}

    def test_make_response_null_id(self):
        resp = make_response(None, "ok")
        parsed = json.loads(resp)
        assert parsed["id"] is None


# ──────────────── MCP协议方法测试 ────────────────


class TestMCPInitialize:
    """MCP initialize测试"""

    def test_initialize(self):
        server = SipMcpServer(psk=PSK)
        result = server.handle_initialize({})
        assert result["protocolVersion"] == "2024-11-05"
        assert "tools" in result["capabilities"]
        assert result["serverInfo"]["name"] == "sip-mcp-server"
        assert server._initialized is True


class TestMCPToolsList:
    """MCP tools/list测试"""

    def test_tools_list(self):
        server = SipMcpServer(psk=PSK)
        result = server.handle_tools_list({})
        tools = result["tools"]
        tool_names = [t["name"] for t in tools]
        assert "sip_encrypt" in tool_names
        assert "sip_decrypt" in tool_names
        assert "sip_handshake" in tool_names
        assert "sip_rekey" in tool_names
        assert len(tools) == 4

    def test_tool_has_input_schema(self):
        server = SipMcpServer(psk=PSK)
        result = server.handle_tools_list({})
        for tool in result["tools"]:
            assert "inputSchema" in tool
            assert "properties" in tool["inputSchema"]


# ──────────────── 握手测试 ────────────────


class TestSIPHandshake:
    """SIP握手测试"""

    def test_initiator_handshake(self):
        server = SipMcpServer(psk=PSK, agent_id="agent-a")
        result = server._handle_handshake({"role": "initiator", "agent_id": "agent-a"})
        data = _get_text_from_content(result)

        assert data["success"] is True
        assert data["role"] == "initiator"
        assert "hello_message" in data
        assert data["state"] == "handshaking"

    def test_full_handshake(self):
        server_a, server_b = _create_paired_servers()

        # A发起握手
        result_a = server_a._handle_handshake({"role": "initiator", "agent_id": "agent-a"})
        data_a = _get_text_from_content(result_a)
        assert data_a["success"] is True

        # B响应握手
        result_b = server_b._handle_handshake(
            {
                "role": "responder",
                "agent_id": "agent-b",
                "message": data_a["hello_message"],
            }
        )
        data_b = _get_text_from_content(result_b)
        assert data_b["success"] is True
        assert data_b["state"] == "established"

        # A完成握手
        result_a2 = server_a._handle_handshake(
            {
                "role": "complete",
                "message": data_b["auth_message"],
            }
        )
        data_a2 = _get_text_from_content(result_a2)
        assert data_a2["success"] is True
        assert data_a2["state"] == "established"

    def test_handshake_responder_missing_message(self):
        server = SipMcpServer(psk=PSK)
        with pytest.raises(JSONRPCError) as exc_info:
            server._handle_handshake({"role": "responder", "agent_id": "a"})
        assert exc_info.value.code == INVALID_PARAMS

    def test_handshake_complete_missing_message(self):
        server = SipMcpServer(psk=PSK)
        with pytest.raises(JSONRPCError) as exc_info:
            server._handle_handshake({"role": "complete", "agent_id": "a"})
        assert exc_info.value.code == INVALID_PARAMS

    def test_handshake_invalid_role(self):
        server = SipMcpServer(psk=PSK)
        with pytest.raises(JSONRPCError) as exc_info:
            server._handle_handshake({"role": "invalid", "agent_id": "a"})
        assert exc_info.value.code == INVALID_PARAMS

    def test_handshake_missing_role(self):
        server = SipMcpServer(psk=PSK)
        with pytest.raises(JSONRPCError) as exc_info:
            server._handle_handshake({"agent_id": "a"})
        assert exc_info.value.code == INVALID_PARAMS


# ──────────────── 加密/解密测试 ────────────────


class TestSIPEncryptDecrypt:
    """SIP加密/解密测试"""

    def test_encrypt_without_handshake(self):
        server = SipMcpServer(psk=PSK)
        with pytest.raises(JSONRPCError) as exc_info:
            server._handle_encrypt({"plaintext": "hello"})
        assert exc_info.value.code == SIP_HANDSHAKE_REQUIRED

    def test_decrypt_without_handshake(self):
        server = SipMcpServer(psk=PSK)
        with pytest.raises(JSONRPCError) as exc_info:
            server._handle_decrypt({"encrypted_message": "some-data"})
        assert exc_info.value.code == SIP_HANDSHAKE_REQUIRED

    def test_encrypt_missing_plaintext(self):
        server = SipMcpServer(psk=PSK)
        with pytest.raises(JSONRPCError) as exc_info:
            server._handle_encrypt({})
        assert exc_info.value.code == INVALID_PARAMS

    def test_decrypt_missing_message(self):
        server = SipMcpServer(psk=PSK)
        with pytest.raises(JSONRPCError) as exc_info:
            server._handle_decrypt({})
        assert exc_info.value.code == INVALID_PARAMS

    def test_encrypt_decrypt_roundtrip(self):
        server_a, server_b = _create_paired_servers()
        _perform_handshake(server_a, server_b)

        # A加密消息
        plaintext = "Hello from Agent A via MCP!"
        result_enc = server_a._handle_encrypt({"plaintext": plaintext})
        data_enc = _get_text_from_content(result_enc)

        assert data_enc["success"] is True
        assert "encrypted_message" in data_enc
        assert "message_id" in data_enc

        # B解密消息
        result_dec = server_b._handle_decrypt({"encrypted_message": data_enc["encrypted_message"]})
        data_dec = _get_text_from_content(result_dec)

        assert data_dec["success"] is True
        assert data_dec["plaintext"] == plaintext

    def test_encrypt_with_recipient_id(self):
        server_a, server_b = _create_paired_servers()
        _perform_handshake(server_a, server_b)

        result = server_a._handle_encrypt(
            {
                "plaintext": "hello",
                "recipient_id": "agent-b",
            }
        )
        data = _get_text_from_content(result)
        assert data["success"] is True

    def test_multiple_messages(self):
        server_a, server_b = _create_paired_servers()
        _perform_handshake(server_a, server_b)

        messages = [f"Message {i}" for i in range(10)]
        for msg_text in messages:
            enc = server_a._handle_encrypt({"plaintext": msg_text})
            enc_data = _get_text_from_content(enc)

            dec = server_b._handle_decrypt({"encrypted_message": enc_data["encrypted_message"]})
            dec_data = _get_text_from_content(dec)

            assert dec_data["plaintext"] == msg_text

    def test_decrypt_invalid_base64(self):
        server_a, server_b = _create_paired_servers()
        _perform_handshake(server_a, server_b)

        # 无效的消息数据
        with pytest.raises(JSONRPCError) as exc_info:
            server_b._handle_decrypt({"encrypted_message": "not-valid-json"})
        assert exc_info.value.code == SIP_DECRYPTION_FAILED


# ──────────────── 密钥轮换测试 ────────────────


class TestSIPRekey:
    """SIP密钥轮换测试"""

    def test_rekey_without_handshake(self):
        server = SipMcpServer(psk=PSK)
        with pytest.raises(JSONRPCError) as exc_info:
            server._handle_rekey({"role": "initiator"})
        assert exc_info.value.code == SIP_HANDSHAKE_REQUIRED

    def test_rekey_missing_role(self):
        server = SipMcpServer(psk=PSK)
        with pytest.raises(JSONRPCError) as exc_info:
            server._handle_rekey({})
        assert exc_info.value.code == INVALID_PARAMS

    def test_rekey_invalid_role(self):
        server_a, server_b = _create_paired_servers()
        _perform_handshake(server_a, server_b)

        with pytest.raises(JSONRPCError) as exc_info:
            server_a._handle_rekey({"role": "invalid"})
        assert exc_info.value.code == INVALID_PARAMS

    def test_rekey_initiator(self):
        server_a, server_b = _create_paired_servers()
        _perform_handshake(server_a, server_b)

        result = server_a._handle_rekey({"role": "initiator"})
        data = _get_text_from_content(result)

        assert data["success"] is True
        assert data["role"] == "initiator"
        assert "rekey_request" in data

    def test_rekey_responder_missing_message(self):
        server_a, server_b = _create_paired_servers()
        _perform_handshake(server_a, server_b)

        with pytest.raises(JSONRPCError) as exc_info:
            server_b._handle_rekey({"role": "responder"})
        assert exc_info.value.code == INVALID_PARAMS

    def test_rekey_roundtrip(self):
        """测试完整的密钥轮换流程"""
        server_a, server_b = _create_paired_servers()
        _perform_handshake(server_a, server_b)

        # 先加密一条消息（轮换前）
        enc_before = server_a._handle_encrypt({"plaintext": "before rekey"})
        enc_data_before = _get_text_from_content(enc_before)

        # A发起rekey
        rekey_result_a = server_a._handle_rekey({"role": "initiator"})
        rekey_data_a = _get_text_from_content(rekey_result_a)
        assert rekey_data_a["success"] is True

        # B响应rekey
        rekey_result_b = server_b._handle_rekey(
            {
                "role": "responder",
                "message": rekey_data_a["rekey_request"],
            }
        )
        rekey_data_b = _get_text_from_content(rekey_result_b)
        assert rekey_data_b["success"] is True


# ──────────────── JSON-RPC路由测试 ────────────────


class TestJSONRPCRouting:
    """JSON-RPC请求路由测试"""

    def test_handle_initialize_request(self):
        server = SipMcpServer(psk=PSK)
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {},
        }
        response = server.handle_request(request)
        parsed = json.loads(response)
        assert parsed["id"] == 1
        assert "result" in parsed
        assert parsed["result"]["serverInfo"]["name"] == "sip-mcp-server"

    def test_handle_tools_list_request(self):
        server = SipMcpServer(psk=PSK)
        request = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {},
        }
        response = server.handle_request(request)
        parsed = json.loads(response)
        assert parsed["id"] == 2
        assert "tools" in parsed["result"]

    def test_handle_tools_call_request(self):
        server = SipMcpServer(psk=PSK)
        request = {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "sip_handshake",
                "arguments": {"role": "initiator", "agent_id": "test"},
            },
        }
        response = server.handle_request(request)
        parsed = json.loads(response)
        assert parsed["id"] == 3
        assert "result" in parsed

    def test_unknown_method(self):
        server = SipMcpServer(psk=PSK)
        request = {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "nonexistent/method",
            "params": {},
        }
        response = server.handle_request(request)
        parsed = json.loads(response)
        assert "error" in parsed
        assert parsed["error"]["code"] == METHOD_NOT_FOUND

    def test_invalid_jsonrpc_version(self):
        server = SipMcpServer(psk=PSK)
        request = {
            "jsonrpc": "1.0",
            "id": 5,
            "method": "initialize",
            "params": {},
        }
        response = server.handle_request(request)
        parsed = json.loads(response)
        assert "error" in parsed
        assert parsed["error"]["code"] == INVALID_REQUEST

    def test_notification_no_response(self):
        server = SipMcpServer(psk=PSK)
        request = {
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
            "params": {},
        }
        response = server.handle_request(request)
        assert response == ""

    def test_unknown_tool_call(self):
        server = SipMcpServer(psk=PSK)
        request = {
            "jsonrpc": "2.0",
            "id": 6,
            "method": "tools/call",
            "params": {
                "name": "nonexistent_tool",
                "arguments": {},
            },
        }
        response = server.handle_request(request)
        parsed = json.loads(response)
        assert "error" in parsed
        assert parsed["error"]["code"] == METHOD_NOT_FOUND

    def test_tool_call_error_handling(self):
        server = SipMcpServer(psk=PSK)
        request = {
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/call",
            "params": {
                "name": "sip_encrypt",
                "arguments": {"plaintext": "test"},
            },
        }
        response = server.handle_request(request)
        parsed = json.loads(response)
        assert "error" in parsed
        assert parsed["error"]["code"] == SIP_HANDSHAKE_REQUIRED


# ──────────────── 集成测试 ────────────────


class TestMCPIntegration:
    """MCP完整流程集成测试"""

    def test_full_flow_handshake_encrypt_decrypt(self):
        """完整流程：握手 → 加密 → 解密"""
        server_a, server_b = _create_paired_servers()

        # 通过JSON-RPC接口调用（而非直接调用handler）
        # 1. 握手 - A发起
        req_a1 = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "sip_handshake",
                "arguments": {"role": "initiator", "agent_id": "agent-a"},
            },
        }
        resp_a1 = json.loads(server_a.handle_request(req_a1))
        hello_b64 = json.loads(resp_a1["result"]["content"][0]["text"])["hello_message"]

        # 2. 握手 - B响应
        req_b1 = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "sip_handshake",
                "arguments": {
                    "role": "responder",
                    "agent_id": "agent-b",
                    "message": hello_b64,
                },
            },
        }
        resp_b1 = json.loads(server_b.handle_request(req_b1))
        auth_b64 = json.loads(resp_b1["result"]["content"][0]["text"])["auth_message"]

        # 3. 握手 - A完成
        req_a2 = {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "sip_handshake",
                "arguments": {"role": "complete", "message": auth_b64},
            },
        }
        resp_a2 = json.loads(server_a.handle_request(req_a2))
        assert json.loads(resp_a2["result"]["content"][0]["text"])["state"] == "established"

        # 4. A加密消息
        req_a3 = {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "sip_encrypt",
                "arguments": {"plaintext": "Secret message via MCP!"},
            },
        }
        resp_a3 = json.loads(server_a.handle_request(req_a3))
        enc_data = json.loads(resp_a3["result"]["content"][0]["text"])
        assert enc_data["success"] is True

        # 5. B解密消息
        req_b2 = {
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {
                "name": "sip_decrypt",
                "arguments": {"encrypted_message": enc_data["encrypted_message"]},
            },
        }
        resp_b2 = json.loads(server_b.handle_request(req_b2))
        dec_data = json.loads(resp_b2["result"]["content"][0]["text"])
        assert dec_data["plaintext"] == "Secret message via MCP!"
