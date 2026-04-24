"""RegistryStore SQLite 存储层测试"""

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
from sip_protocol.discovery.registry import AgentRegistration
from sip_protocol.discovery.registry_store import RegistryStore


# ==================== 测试辅助 ====================


def _make_card(name: str = "TestAgent") -> AgentCard:
    """快速构造 AgentCard"""
    return AgentCard(
        name=name,
        description=f"{name} desc",
        version="1.0.0",
        url=f"https://{name.lower()}.example.com",
        capabilities=Capabilities(streaming=True),
        skills=[Skill(id="search", name="Search", tags=["web"])],
        endpoints=Endpoints(primary=f"wss://{name.lower()}.example.com/ws"),
    )


def _make_registration(
    name: str = "TestAgent",
    status: str = "online",
    *,
    expires_offset: float = 300,
    offline_since: float | None = None,
) -> AgentRegistration:
    """快速构造 AgentRegistration"""
    now = time.time()
    return AgentRegistration(
        agent_name=name,
        card=_make_card(name),
        status=status,
        registered_at=now,
        last_heartbeat=now,
        expires_at=now + expires_offset,
        offline_since=offline_since,
    )


def _tmp_db() -> str:
    """生成临时数据库路径"""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    return path


# ==================== 建表 ====================


class TestCreateTables:
    def test_create_tables(self):
        """验证表和索引已创建"""
        db_path = _tmp_db()
        store = RegistryStore(db_path)

        conn = store._get_conn()
        tables = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        assert "agents" in tables

        indexes = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='index'"
            ).fetchall()
        }
        assert "idx_agents_status" in indexes
        assert "idx_agents_expires" in indexes

        store.close()
        os.unlink(db_path)


# ==================== 存取 ====================


class TestSaveAndLoad:
    def test_save_and_load(self):
        """保存后加载，所有字段一致"""
        db_path = _tmp_db()
        store = RegistryStore(db_path)

        reg = _make_registration("AgentA")
        store.save(reg)

        loaded = store.load("AgentA")
        assert loaded is not None
        assert loaded.agent_name == "AgentA"
        assert loaded.status == "online"
        assert loaded.card.name == "AgentA"
        assert loaded.card.version == "1.0.0"
        assert loaded.offline_since is None

        store.close()
        os.unlink(db_path)

    def test_load_nonexistent(self):
        """查询不存在的名称返回 None"""
        db_path = _tmp_db()
        store = RegistryStore(db_path)

        assert store.load("Ghost") is None

        store.close()
        os.unlink(db_path)


# ==================== 删除 ====================


class TestDelete:
    def test_delete(self):
        """保存后删除，加载返回 None"""
        db_path = _tmp_db()
        store = RegistryStore(db_path)

        store.save(_make_registration("AgentA"))
        assert store.delete("AgentA") is True
        assert store.load("AgentA") is None

        store.close()
        os.unlink(db_path)

    def test_delete_nonexistent(self):
        """删除不存在的记录返回 False"""
        db_path = _tmp_db()
        store = RegistryStore(db_path)

        assert store.delete("Ghost") is False

        store.close()
        os.unlink(db_path)


# ==================== 列表 ====================


class TestListAll:
    def test_list_all(self):
        """保存3条记录，list_all 返回3条"""
        db_path = _tmp_db()
        store = RegistryStore(db_path)

        for name in ("A", "B", "C"):
            store.save(_make_registration(name))

        all_regs = store.list_all()
        assert len(all_regs) == 3
        names = {r.agent_name for r in all_regs}
        assert names == {"A", "B", "C"}

        store.close()
        os.unlink(db_path)


# ==================== 状态更新 ====================


class TestUpdateStatus:
    def test_update_status(self):
        """更新状态为 offline，加载后确认"""
        db_path = _tmp_db()
        store = RegistryStore(db_path)

        now = time.time()
        store.save(_make_registration("AgentA"))
        store.update_status("AgentA", "offline", now + 300, now, offline_since=now)

        loaded = store.load("AgentA")
        assert loaded is not None
        assert loaded.status == "offline"
        assert loaded.offline_since is not None

        store.close()
        os.unlink(db_path)


# ==================== 过期查找 ====================


class TestFindExpired:
    def test_find_expired(self):
        """expires_at 已过期且 online 的 Agent 被找到"""
        db_path = _tmp_db()
        store = RegistryStore(db_path)

        store.save(_make_registration("AgentA", expires_offset=-10))
        expired = store.find_expired()
        assert len(expired) == 1
        assert expired[0].agent_name == "AgentA"

        store.close()
        os.unlink(db_path)

    def test_find_expired_healthy(self):
        """expires_at 未过期的 Agent 不会被找到"""
        db_path = _tmp_db()
        store = RegistryStore(db_path)

        store.save(_make_registration("AgentA", expires_offset=300))
        expired = store.find_expired()
        assert expired == []

        store.close()
        os.unlink(db_path)


# ==================== 离线超时查找 ====================


class TestFindOfflineExpired:
    def test_find_offline_expired(self):
        """离线时间超过 offline_ttl 的 Agent 被找到"""
        db_path = _tmp_db()
        store = RegistryStore(db_path)

        now = time.time()
        reg = _make_registration(
            "AgentA",
            status="offline",
            offline_since=now - 200,
        )
        store.save(reg)

        expired = store.find_offline_expired(offline_ttl=60)
        assert len(expired) == 1
        assert expired[0].agent_name == "AgentA"

        store.close()
        os.unlink(db_path)

    def test_find_offline_expired_recent(self):
        """离线时间未超过 offline_ttl 的 Agent 不会被找到"""
        db_path = _tmp_db()
        store = RegistryStore(db_path)

        now = time.time()
        reg = _make_registration(
            "AgentA",
            status="offline",
            offline_since=now - 30,
        )
        store.save(reg)

        expired = store.find_offline_expired(offline_ttl=60)
        assert expired == []

        store.close()
        os.unlink(db_path)
