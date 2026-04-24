"""AgentRegistry 注册中心测试"""

from __future__ import annotations

import os
import tempfile
import time

import pytest

from sip_protocol.discovery.agent_card import (
    AgentCard,
    Capabilities,
    Endpoints,
    Skill,
)
from sip_protocol.discovery.registry import (
    AgentFilter,
    AgentRegistration,
    AgentRegistry,
    RegistryConfig,
)


# ==================== 测试辅助 ====================


@pytest.fixture()
def db_path():
    """创建临时数据库路径，测试结束后自动删除"""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    os.unlink(path)
    yield path
    if os.path.exists(path):
        os.unlink(path)


def _make_config(db_path: str, **kwargs) -> RegistryConfig:
    """构造使用临时路径的 RegistryConfig"""
    return RegistryConfig(db_path=db_path, **kwargs)


def _make_card(
    name: str = "AgentA",
    *,
    streaming: bool = False,
    skill_ids: list[str] | None = None,
    skill_tags: list[str] | None = None,
) -> AgentCard:
    """快速构造 AgentCard"""
    skills = []
    if skill_ids:
        for sid in skill_ids:
            tags = [t for t in (skill_tags or []) if t]
            skills.append(Skill(id=sid, name=sid.title(), tags=tags))
    return AgentCard(
        name=name,
        description=f"{name} desc",
        version="1.0.0",
        url=f"https://{name.lower()}.example.com",
        capabilities=Capabilities(streaming=streaming),
        skills=skills,
        endpoints=Endpoints(primary=f"wss://{name.lower()}.example.com/ws"),
    )


# ==================== 注册/注销 ====================


class TestRegister:
    def test_register_and_get(self, db_path):
        """注册Agent后可通过get取回"""
        reg = AgentRegistry(_make_config(db_path))
        card = _make_card("AgentA")
        reg_id = reg.register(card)

        assert reg_id == "AgentA"
        assert reg.get("AgentA") == card

    def test_register_overwrite(self, db_path):
        """同名Agent注册两次，后者覆盖前者"""
        reg = AgentRegistry(_make_config(db_path))
        card_v1 = _make_card("AgentA")
        card_v2 = AgentCard(
            name="AgentA",
            description="v2 desc",
            version="2.0.0",
            url="https://agenta-v2.example.com",
        )

        reg.register(card_v1)
        reg.register(card_v2)

        result = reg.get("AgentA")
        assert result is not None
        assert result.version == "2.0.0"

    def test_deregister_success(self, db_path):
        """注销已注册Agent，get返回None"""
        reg = AgentRegistry(_make_config(db_path))
        card = _make_card("AgentA")
        reg.register(card)

        assert reg.deregister("AgentA") is True
        assert reg.get("AgentA") is None

    def test_deregister_unknown(self, db_path):
        """注销不存在的Agent返回False"""
        reg = AgentRegistry(_make_config(db_path))
        assert reg.deregister("Ghost") is False


# ==================== 列表查询 ====================


class TestList:
    def test_list_all(self, db_path):
        """list_all返回所有注册的Agent"""
        reg = AgentRegistry(_make_config(db_path))
        for name in ("A", "B", "C"):
            reg.register(_make_card(name))

        cards = reg.list_all()
        assert len(cards) == 3

    def test_list_online(self, db_path):
        """list_online仅返回在线Agent"""
        reg = AgentRegistry(_make_config(db_path))
        for name in ("A", "B", "C"):
            reg.register(_make_card(name))

        # 手动将 AgentB 标记离线
        reg._store["B"].status = "offline"

        online = reg.list_online()
        assert len(online) == 2
        names = {c.name for c in online}
        assert names == {"A", "C"}


# ==================== 过滤查询 ====================


class TestQuery:
    def test_query_by_skill(self, db_path):
        """按技能ID过滤（OR关系）"""
        reg = AgentRegistry(_make_config(db_path))
        reg.register(_make_card("SearchBot", skill_ids=["search", "index"]))
        reg.register(_make_card("ChatBot", skill_ids=["chat"]))
        reg.register(_make_card("MixedBot", skill_ids=["search", "chat"]))

        results = reg.query(AgentFilter(skills=["search"]))
        names = {c.name for c in results}
        assert names == {"SearchBot", "MixedBot"}

    def test_query_by_tag(self, db_path):
        """按技能标签过滤（OR关系）"""
        reg = AgentRegistry(_make_config(db_path))
        reg.register(_make_card("WebBot", skill_ids=["search"], skill_tags=["web"]))
        reg.register(_make_card("LocalBot", skill_ids=["search"], skill_tags=["local"]))
        reg.register(_make_card("OmniBot", skill_ids=["search"], skill_tags=["web", "local"]))

        results = reg.query(AgentFilter(tags=["web"]))
        names = {c.name for c in results}
        assert names == {"WebBot", "OmniBot"}

    def test_query_by_capability(self, db_path):
        """按能力名称过滤"""
        reg = AgentRegistry(_make_config(db_path))
        reg.register(_make_card("StreamBot", streaming=True))
        reg.register(_make_card("PlainBot", streaming=False))

        results = reg.query(AgentFilter(capabilities=["streaming"]))
        names = {c.name for c in results}
        assert names == {"StreamBot"}

    def test_query_by_status_online(self, db_path):
        """按status=online过滤"""
        reg = AgentRegistry(_make_config(db_path))
        reg.register(_make_card("OnlineBot"))
        reg.register(_make_card("OfflineBot"))
        reg._store["OfflineBot"].status = "offline"

        results = reg.query(AgentFilter(status="online"))
        names = {c.name for c in results}
        assert names == {"OnlineBot"}

    def test_query_by_status_offline(self, db_path):
        """按status=offline过滤"""
        reg = AgentRegistry(_make_config(db_path))
        reg.register(_make_card("OnlineBot"))
        reg.register(_make_card("OfflineBot"))
        reg._store["OfflineBot"].status = "offline"

        results = reg.query(AgentFilter(status="offline"))
        names = {c.name for c in results}
        assert names == {"OfflineBot"}

    def test_query_no_match(self, db_path):
        """过滤条件无匹配时返回空列表"""
        reg = AgentRegistry(_make_config(db_path))
        reg.register(_make_card("Bot", skill_ids=["chat"]))

        results = reg.query(AgentFilter(skills=["nonexistent"]))
        assert results == []


# ==================== 心跳 ====================


class TestHeartbeat:
    def test_heartbeat_success(self, db_path):
        """心跳成功时更新expires_at"""
        reg = AgentRegistry(_make_config(db_path, default_ttl=300))
        card = _make_card("AgentA")
        reg.register(card)

        original_expires = reg._store["AgentA"].expires_at

        # 直接操控时间来避免sleep
        time.sleep(0.01)
        result = reg.heartbeat("AgentA")

        assert result is True
        assert reg._store["AgentA"].expires_at > original_expires

    def test_heartbeat_unknown_agent(self, db_path):
        """对未注册Agent心跳返回False"""
        reg = AgentRegistry(_make_config(db_path))
        assert reg.heartbeat("Ghost") is False

    def test_heartbeat_offline_agent(self, db_path):
        """对离线Agent心跳返回False"""
        reg = AgentRegistry(_make_config(db_path))
        reg.register(_make_card("AgentA"))
        reg._store["AgentA"].status = "offline"

        assert reg.heartbeat("AgentA") is False


# ==================== 健康检查 ====================


class TestHealthCheck:
    def test_check_health_marks_expired(self, db_path):
        """TTL过期后check_health将Agent标记为offline"""
        reg = AgentRegistry(_make_config(db_path, default_ttl=10))
        reg.register(_make_card("AgentA"))

        # 直接篡改 expires_at 模拟过期
        reg._store["AgentA"].expires_at = time.time() - 1

        unhealthy = reg.check_health()
        assert unhealthy == ["AgentA"]
        assert reg._store["AgentA"].status == "offline"
        assert reg._store["AgentA"].offline_since is not None

    def test_check_health_healthy(self, db_path):
        """TTL未过期时Agent保持online"""
        reg = AgentRegistry(_make_config(db_path, default_ttl=300))
        reg.register(_make_card("AgentA"))

        unhealthy = reg.check_health()
        assert unhealthy == []
        assert reg._store["AgentA"].status == "online"


# ==================== 清理 ====================


class TestCleanup:
    def test_cleanup_removes_expired_offline(self, db_path):
        """离线超过offline_ttl的Agent被清理"""
        reg = AgentRegistry(_make_config(db_path, offline_ttl=60))
        reg.register(_make_card("AgentA"))
        reg._store["AgentA"].status = "offline"
        reg._store["AgentA"].offline_since = time.time() - 120  # 超过 offline_ttl

        removed = reg.cleanup()
        assert removed == 1
        assert reg.get("AgentA") is None

    def test_cleanup_keeps_recent_offline(self, db_path):
        """离线未超过offline_ttl的Agent保留"""
        reg = AgentRegistry(_make_config(db_path, offline_ttl=86400))
        reg.register(_make_card("AgentA"))
        reg._store["AgentA"].status = "offline"
        reg._store["AgentA"].offline_since = time.time() - 60  # 远未到 offline_ttl

        removed = reg.cleanup()
        assert removed == 0
        assert reg.get("AgentA") is not None


# ==================== 自定义配置 ====================


class TestCustomConfig:
    def test_custom_config(self, db_path):
        """自定义TTL和offline_ttl正确生效"""
        config = _make_config(db_path, default_ttl=5, offline_ttl=30)
        reg = AgentRegistry(config)
        reg.register(_make_card("AgentA"))

        # 验证 expires_at 使用了自定义 default_ttl
        entry = reg._store["AgentA"]
        assert abs(entry.expires_at - entry.registered_at - 5) < 0.1

        # 模拟过期后标记offline
        entry.expires_at = time.time() - 1
        reg.check_health()
        assert entry.status == "offline"
        assert entry.offline_since is not None

        # 未到 offline_ttl，cleanup 不应清理
        assert reg.cleanup() == 0

        # 超过 offline_ttl，cleanup 应清理
        entry.offline_since = time.time() - 60
        assert reg.cleanup() == 1
        assert reg.get("AgentA") is None
