"""版本协商协议测试"""

import pytest

from sip_protocol.protocol.version import (
    PROTOCOL_VERSIONS,
    create_version_not_supported,
    create_version_offer,
    create_version_response,
    negotiate_version,
    parse_version_response,
    validate_version,
)


class TestVersionOffer:
    def test_create_version_offer_structure(self):
        offer = create_version_offer(PROTOCOL_VERSIONS, "agent-a")
        assert offer["type"] == "version_offer"
        assert offer["supported_versions"] == PROTOCOL_VERSIONS
        assert offer["sender_id"] == "agent-a"
        assert offer["version"] == "SIP-1.0"
        assert "timestamp" in offer

    def test_create_version_offer_custom_versions(self):
        offer = create_version_offer(["SIP-1.0"], "agent-b")
        assert offer["supported_versions"] == ["SIP-1.0"]


class TestVersionResponse:
    def test_create_version_response_structure(self):
        resp = create_version_response("SIP-1.2", PROTOCOL_VERSIONS, "agent-b")
        assert resp["type"] == "version_response"
        assert resp["selected_version"] == "SIP-1.2"
        assert resp["sender_id"] == "agent-b"

    def test_parse_version_response_success(self):
        resp = create_version_response("SIP-1.1", PROTOCOL_VERSIONS, "agent-b")
        result = parse_version_response(resp)
        assert result == "SIP-1.1"

    def test_parse_version_response_wrong_type(self):
        resp = create_version_response("SIP-1.1", PROTOCOL_VERSIONS, "agent-b")
        resp["type"] = "other"
        assert parse_version_response(resp) is None

    def test_parse_version_response_no_common_version(self):
        resp = create_version_response("SIP-1.0", ["SIP-2.0"], "agent-b")
        result = parse_version_response(resp)
        assert result is None


class TestVersionNotSupported:
    def test_create_version_not_supported(self):
        msg = create_version_not_supported(["SIP-1.0"], ["SIP-2.0"])
        assert msg["error_code"] == "VERSION_NOT_SUPPORTED"
        assert msg["type"] == "error"
        assert "timestamp" in msg


class TestFullNegotiationFlow:
    def test_full_4_step_negotiation(self):
        """模拟完整的 4 步版本协商"""
        # Step 1: Agent A 发起
        offer = create_version_offer(["SIP-1.0", "SIP-1.2"], "agent-a")

        # Step 2: Agent B 选择最高共同版本
        selected = negotiate_version(["SIP-1.1", "SIP-1.2"], offer["supported_versions"])
        assert selected == "SIP-1.2"

        # Step 3: Agent B 发送响应
        response = create_version_response(selected, ["SIP-1.1", "SIP-1.2"], "agent-b")

        # Step 4: Agent A 解析响应
        result = parse_version_response(response)
        assert result == "SIP-1.2"

    def test_negotiation_picks_highest_common(self):
        """协商选择最高共同版本"""
        offer = create_version_offer(["SIP-1.0", "SIP-1.1", "SIP-1.3"], "agent-a")
        selected = negotiate_version(["SIP-1.1", "SIP-1.2", "SIP-1.3"], offer["supported_versions"])
        assert selected == "SIP-1.3"

    def test_no_common_version_returns_none(self):
        offer = create_version_offer(["SIP-1.0"], "agent-a")
        response = create_version_response("SIP-1.0", ["SIP-2.0"], "agent-b")
        result = parse_version_response(response)
        assert result is None
