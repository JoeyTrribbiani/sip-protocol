#!/usr/bin/env python3
"""SIP端到端加密通信测试（MCP长驻进程模式，与OpenClaw生产用法一致）

通过 stdio JSON-RPC 驱动两个长驻 MCP Server 进程完成:
握手 → 加密 → 解密 → Rekey → Rekey后继续加密

注意: 握手 complete 依赖同进程的 initiator 状态（auth 绑定发起方临时密钥），
因此必须使用持久进程逐条收发，而非一次性批量注入后关闭 stdin。

运行方式:
    cd python
    .venv/bin/python tests/test_e2e_three_party.py
"""

import json
import subprocess
import sys
import os

PYTHON = os.path.expanduser("~/.local/bin/python3.11")
MCP_CMD = [PYTHON, "-m", "sip_protocol"]
# 独立测试 PSK，与生产配置无关
PSK = "746573742d70736b2d6f6e6c792d666f722d653265652d746573742d3031"


class McpSession:
    """长驻 MCP 进程会话，按行收发 JSON-RPC"""

    def __init__(self, agent_id):
        self.proc = subprocess.Popen(
            MCP_CMD + ["--psk", PSK, "--agent-id", agent_id],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        self._id = 0

    def request(self, method, params=None):
        self._id += 1
        req = {"jsonrpc": "2.0", "id": self._id, "method": method}
        if params is not None:
            req["params"] = params
        self.proc.stdin.write(json.dumps(req) + "\n")
        self.proc.stdin.flush()
        line = self.proc.stdout.readline()
        return json.loads(line)

    def call_tool(self, name, arguments):
        resp = self.request("tools/call", {"name": name, "arguments": arguments})
        if "error" in resp:
            raise AssertionError(f"工具 {name} 调用失败: {resp['error']}")
        return json.loads(resp["result"]["content"][0]["text"])

    def close(self):
        self.proc.stdin.close()
        self.proc.wait(timeout=5)


def main():
    print("=" * 50)
    print("SIP 端到端加密通信测试（MCP长驻进程）")
    print("=" * 50)

    a = McpSession("openclaw-agent")
    b = McpSession("hermes")

    # Step 1: 双方 initialize
    for s in (a, b):
        info = s.request("initialize", {})
        assert info["result"]["serverInfo"]["name"] == "sip-mcp-server"
    print("\n✅ [Step 1] 双方 MCP Server 初始化完成")

    # Step 2: 发起方发起握手
    init_result = a.call_tool("sip_handshake", {"role": "initiator", "agent_id": "openclaw-agent"})
    assert init_result["success"], f"握手发起失败: {init_result}"
    hello = init_result["hello_message"]
    print(f"\n✅ [Step 2] Hello消息已生成 ({len(hello)} chars)")

    # Step 3: 响应方处理握手
    resp_result = b.call_tool("sip_handshake", {"role": "responder", "agent_id": "hermes", "message": hello})
    assert resp_result["success"], f"握手响应失败: {resp_result}"
    auth = resp_result["auth_message"]
    print(f"✅ [Step 3] Auth消息已生成 ({len(auth)} chars)")

    # Step 4: 发起方完成握手（同一进程，initiator 状态仍在）
    complete_result = a.call_tool("sip_handshake", {"role": "complete", "message": auth})
    assert complete_result["success"], f"握手完成失败: {complete_result}"
    assert complete_result["state"] == "established"
    print(f"✅ [Step 4] 握手完成: {complete_result['message']}")

    # Step 5: 加密 → 解密 往返
    plaintext_expected = "端到端加密通信测试成功！"
    enc = a.call_tool("sip_encrypt", {"plaintext": plaintext_expected, "recipient_id": "hermes"})
    assert enc["success"], f"加密失败: {enc}"
    dec = b.call_tool("sip_decrypt", {"encrypted_message": enc["encrypted_message"]})
    assert dec["success"], f"解密失败: {dec}"
    assert dec["plaintext"] == plaintext_expected, f"解密结果不匹配: {dec['plaintext']}"
    assert dec["sender_id"] == "openclaw-agent"
    print(f"\n✅ [Step 5] 加解密往返成功: \"{dec['plaintext']}\"")

    # Step 6: Rekey 双角色
    rk = a.call_tool("sip_rekey", {"role": "initiator"})
    assert rk["success"], f"Rekey发起失败: {rk}"
    rk_resp = b.call_tool("sip_rekey", {"role": "responder", "message": rk["rekey_request"]})
    assert rk_resp["success"], f"Rekey响应失败: {rk_resp}"
    print(f"\n✅ [Step 6] 密钥轮换完成: {rk_resp['message']}")

    # Step 7: Rekey 后继续加密通信
    enc2 = a.call_tool("sip_encrypt", {"plaintext": "rekey后的消息", "recipient_id": "hermes"})
    assert enc2["success"], f"Rekey后加密失败: {enc2}"
    print(f"✅ [Step 7] Rekey后加密正常")

    a.close()
    b.close()

    print("\n" + "=" * 50)
    print("🎉 全部测试通过！SIP端到端加密通信验证成功！")
    print("=" * 50)


if __name__ == "__main__":
    main()
