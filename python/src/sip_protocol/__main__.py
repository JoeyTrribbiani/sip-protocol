"""
SIP MCP Server入口

用法: python -m sip_protocol --psk <密钥> [--agent-id <ID>]
"""

from sip_protocol.transport.sip_mcp_server import main

if __name__ == "__main__":
    main()
