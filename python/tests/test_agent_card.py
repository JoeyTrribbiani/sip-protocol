"""AgentCard 数据结构测试"""

from __future__ import annotations

import dataclasses

import pytest

from sip_protocol.discovery.agent_card import (
    AgentCard,
    AuthScheme,
    Capabilities,
    Endpoints,
    Skill,
)


# ==================== Capabilities ====================


class TestCapabilities:
    def test_default_values(self):
        c = Capabilities()
        assert c.streaming is False
        assert c.push_notifications is False
        assert c.task_management is False
        assert c.file_transfer is False
        assert c.group_communication is False
        assert c.max_message_size == 1048576
        assert c.supported_schemas == ("sip-msg/v1",)

    def test_round_trip(self):
        original = Capabilities(
            streaming=True,
            push_notifications=True,
            task_management=False,
            file_transfer=True,
            group_communication=False,
            max_message_size=2097152,
            supported_schemas=("sip-msg/v1", "custom/v1"),
        )
        restored = Capabilities.from_dict(original.to_dict())
        assert restored == original

    def test_frozen(self):
        c = Capabilities()
        with pytest.raises(dataclasses.FrozenInstanceError):
            c.streaming = True  # type: ignore[misc]


# ==================== Skill ====================


class TestSkill:
    def test_round_trip_all_fields(self):
        original = Skill(
            id="search",
            name="Web Search",
            description="Search the web",
            input_schema={"query": "string"},
            output_schema={"results": "array"},
            tags=["web", "search"],
        )
        restored = Skill.from_dict(original.to_dict())
        assert restored == original

    def test_round_trip_minimal(self):
        original = Skill(id="ping", name="Ping")
        restored = Skill.from_dict(original.to_dict())
        assert restored.id == "ping"
        assert restored.name == "Ping"
        assert restored.description == ""
        assert restored.input_schema is None
        assert restored.output_schema is None
        assert restored.tags == []

    def test_none_schemas_excluded_from_dict(self):
        s = Skill(id="x", name="X", input_schema=None, output_schema=None)
        d = s.to_dict()
        assert "input_schema" not in d
        assert "output_schema" not in d


# ==================== AuthScheme ====================


class TestAuthScheme:
    def test_round_trip(self):
        original = AuthScheme(type="bearer", description="OAuth2 Bearer Token")
        restored = AuthScheme.from_dict(original.to_dict())
        assert restored == original

    def test_round_trip_type_only(self):
        original = AuthScheme(type="api_key")
        restored = AuthScheme.from_dict(original.to_dict())
        assert restored == original

    def test_frozen(self):
        a = AuthScheme(type="bearer")
        with pytest.raises(dataclasses.FrozenInstanceError):
            a.type = "basic"  # type: ignore[misc]


# ==================== Endpoints ====================


class TestEndpoints:
    def test_round_trip_all_fields(self):
        original = Endpoints(
            primary="wss://agent.example.com/ws",
            streaming="wss://agent.example.com/stream",
            file_transfer="https://agent.example.com/files",
            health="https://agent.example.com/health",
        )
        restored = Endpoints.from_dict(original.to_dict())
        assert restored == original

    def test_round_trip_primary_only(self):
        original = Endpoints(primary="wss://agent.example.com/ws")
        restored = Endpoints.from_dict(original.to_dict())
        assert restored == original

    def test_frozen(self):
        e = Endpoints(primary="wss://example.com")
        with pytest.raises(dataclasses.FrozenInstanceError):
            e.primary = "changed"  # type: ignore[misc]


# ==================== AgentCard ====================


class TestAgentCard:
    def _full_card(self) -> AgentCard:
        return AgentCard(
            name="TestAgent",
            description="A test agent",
            version="1.0.0",
            url="https://agent.example.com",
            capabilities=Capabilities(streaming=True, file_transfer=True),
            authentication=[AuthScheme(type="bearer"), AuthScheme(type="api_key")],
            skills=[
                Skill(
                    id="search",
                    name="Search",
                    description="Search things",
                    tags=["web"],
                ),
            ],
            endpoints=Endpoints(
                primary="wss://agent.example.com/ws",
                health="https://agent.example.com/health",
            ),
            metadata={"author": "test", "license": "MIT"},
        )

    def test_full_round_trip(self):
        original = self._full_card()
        restored = AgentCard.from_dict(original.to_dict())
        assert restored.name == original.name
        assert restored.description == original.description
        assert restored.version == original.version
        assert restored.url == original.url
        assert restored.capabilities == original.capabilities
        assert restored.authentication == original.authentication
        assert restored.skills == original.skills
        assert restored.endpoints == original.endpoints
        assert restored.metadata == original.metadata

    def test_minimal_round_trip(self):
        original = AgentCard(
            name="Min",
            description="Minimal",
            version="0.1.0",
            url="https://min.example.com",
        )
        restored = AgentCard.from_dict(original.to_dict())
        assert restored.name == "Min"
        assert restored.capabilities == Capabilities()
        assert restored.authentication == []
        assert restored.skills == []
        assert restored.endpoints is None
        assert restored.metadata == {}

    def test_missing_required_field_raises(self):
        with pytest.raises(KeyError):
            AgentCard.from_dict({"name": "X"})  # missing description, version, url

    def test_metadata_preserved(self):
        card = AgentCard(
            name="M",
            description="D",
            version="1.0",
            url="https://x.com",
            metadata={"key": "value", "nested": {"a": 1}},
        )
        restored = AgentCard.from_dict(card.to_dict())
        assert restored.metadata == {"key": "value", "nested": {"a": 1}}

    def test_nested_serialization(self):
        card = self._full_card()
        d = card.to_dict()
        # capabilities 是嵌套字典
        assert isinstance(d["capabilities"], dict)
        assert d["capabilities"]["streaming"] is True
        # authentication 是字典列表
        assert isinstance(d["authentication"], list)
        assert d["authentication"][0]["type"] == "bearer"
        # skills 是字典列表
        assert isinstance(d["skills"], list)
        assert d["skills"][0]["id"] == "search"
        # endpoints 是嵌套字典
        assert isinstance(d["endpoints"], dict)
        assert d["endpoints"]["primary"] == "wss://agent.example.com/ws"
