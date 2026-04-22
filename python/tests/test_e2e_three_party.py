#!/usr/bin/env python3
"""SIP三方加密通信端到端测试"""

import json
import subprocess
import sys
import os

PYTHON = os.path.expanduser("~/.local/bin/python3.11")
MCP_CMD = [PYTHON, "-m", "sip_protocol"]
PSK = "6e9d598c5b04450153c69858a969c7ebece32ffe632bea02e5532a636595fe93"


def call_mcp(agent_id, requests):
    """调用MCP Server"""
    input_lines = "\n".join(json.dumps(r) for r in requests) + "\n"
    result = subprocess.run(
        MCP_CMD + ["--psk", PSK, "--agent-id", agent_id],
        input=input_lines,
        capture_output=True,
        text=True,
        timeout=10,
    )
    responses = []
    for line in result.stdout.strip().split("\n"):
        if line.strip():
            responses.append(json.loads(line))
    return responses


def get_tool_result(response):
    """提取工具调用结果"""
    return json.loads(response["result"]["content"][0]["text"])


def main():
    print("=" * 50)
    print("SIP 三方加密通信端到端测试")
    print("=" * 50)

    # Step 1: 发起方发起握手
    print("\n[Step 1] OpenClaw Agent 发起握手...")
    init_req = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
    hello_req = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "sip_handshake",
            "arguments": {"role": "initiator", "agent_id": "openclaw-agent"},
        },
    }
    resp = call_mcp("openclaw-agent", [init_req, hello_req])
    hello_result = get_tool_result(resp[1])
    assert hello_result["success"], f"握手发起失败: {hello_result}"
    hello_msg = hello_result["hello_message"]
    print(f"  ✅ Hello消息已生成 ({len(hello_msg)} chars)")

    # Step 2: 响应方处理握手
    print("\n[Step 2] Hermes 响应握手...")
    resp = call_mcp(
        "hermes",
        [
            init_req,
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "sip_handshake",
                    "arguments": {"role": "responder", "agent_id": "hermes", "message": hello_msg},
                },
            },
        ],
    )
    auth_result = get_tool_result(resp[1])
    assert auth_result["success"], f"握手响应失败: {auth_result}"
    auth_msg = auth_result["auth_message"]
    print(f"  ✅ Auth消息已生成 ({len(auth_msg)} chars)")

    # Step 3: 发起方完成握手 + 加密消息
    print("\n[Step 3] OpenClaw Agent 完成握手 + 加密消息...")
    resp = call_mcp(
        "openclaw-agent",
        [
            init_req,
            hello_req,
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "sip_handshake",
                    "arguments": {"role": "complete", "message": auth_msg},
                },
            },
        ],
    )
    complete_result = get_tool_result(resp[2])
    assert complete_result["success"], f"握手完成失败: {complete_result}"
    print(f"  ✅ 握手完成: {complete_result['message']}")

    # Step 4: 加密消息
    print("\n[Step 4] 加密消息...")
    resp = call_mcp(
        "openclaw-agent",
        [
            init_req,
            hello_req,
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "sip_handshake",
                    "arguments": {"role": "complete", "message": auth_msg},
                },
            },
            {
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {
                    "name": "sip_encrypt",
                    "arguments": {"plaintext": "三方加密通信测试成功！", "recipient_id": "hermes"},
                },
            },
        ],
    )
    enc_result = get_tool_result(resp[3])
    assert enc_result["success"], f"加密失败: {enc_result}"
    encrypted_msg = enc_result["encrypted_message"]
    print(f"  ✅ 消息已加密 ({len(encrypted_msg)} chars)")

    # Step 5: 响应方解密
    print("\n[Step 5] Hermes 解密消息...")
    resp = call_mcp(
        "hermes",
        [
            init_req,
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "sip_handshake",
                    "arguments": {"role": "responder", "agent_id": "hermes", "message": hello_msg},
                },
            },
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "sip_decrypt",
                    "arguments": {"encrypted_message": encrypted_msg},
                },
            },
        ],
    )
    dec_result = get_tool_result(resp[2])
    assert dec_result["success"], f"解密失败: {dec_result}"
    plaintext = dec_result["plaintext"]
    sender = dec_result["sender_id"]
    print(f'  ✅ 解密成功: "{plaintext}"')
    print(f"  ✅ 发送方: {sender}")

    assert plaintext == "三方加密通信测试成功！", f"解密结果不匹配: {plaintext}"

    print("\n" + "=" * 50)
    print("🎉 全部测试通过！SIP三方加密通信端到端验证成功！")
    print("=" * 50)


if __name__ == "__main__":
    main()
