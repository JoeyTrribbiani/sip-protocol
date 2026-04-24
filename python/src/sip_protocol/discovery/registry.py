"""AgentRegistry — Agent注册中心"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from sip_protocol.discovery.agent_card import AgentCard


# ==================== 配置 ====================


@dataclass
class RegistryConfig:
    """注册中心配置"""

    default_ttl: int = 300           # 默认在线TTL（秒）
    heartbeat_interval: int = 120    # 心跳间隔（秒）
    offline_ttl: int = 86400         # 离线保留时间（秒）
    db_path: str = "~/.openclaw/sip_registry.db"
    cleanup_interval: int = 3600     # 清理间隔（秒）


# ==================== 查询过滤 ====================


@dataclass
class AgentFilter:
    """Agent查询过滤条件"""

    skills: list[str] | None = None
    tags: list[str] | None = None
    capabilities: list[str] | None = None
    status: str | None = None


# ==================== 注册记录 ====================


@dataclass
class AgentRegistration:
    """注册记录"""

    agent_name: str
    card: AgentCard
    status: str                    # "online" | "offline"
    registered_at: float
    last_heartbeat: float
    expires_at: float
    offline_since: float | None = None


# ==================== 注册中心 ====================


class AgentRegistry:
    """Agent注册中心 — 内存版本"""

    def __init__(self, config: RegistryConfig | None = None):
        self._config = config or RegistryConfig()
        self._store: dict[str, AgentRegistration] = {}

    # === 注册/注销 ===

    def register(self, card: AgentCard) -> str:
        """注册Agent，返回registration_id（使用 agent_name）

        如果同名Agent已存在且online，则覆盖。
        如果同名Agent已offline，则重新上线。
        """
        now = time.time()
        reg = AgentRegistration(
            agent_name=card.name,
            card=card,
            status="online",
            registered_at=now,
            last_heartbeat=now,
            expires_at=now + self._config.default_ttl,
        )
        self._store[card.name] = reg
        return card.name

    def deregister(self, agent_name: str) -> bool:
        """注销Agent，返回是否成功"""
        if agent_name not in self._store:
            return False
        del self._store[agent_name]
        return True

    # === 查询 ===

    def get(self, agent_name: str) -> AgentCard | None:
        """查询指定Agent的AgentCard（含离线）"""
        reg = self._store.get(agent_name)
        return reg.card if reg else None

    def list_all(self) -> list[AgentCard]:
        """列出所有AgentCard（含离线）"""
        return [reg.card for reg in self._store.values()]

    def query(self, agent_filter: AgentFilter) -> list[AgentCard]:
        """按过滤条件查询AgentCard（skills/tags/capabilities 均为 OR 关系）"""
        results: list[AgentCard] = []
        for reg in self._store.values():
            # 状态过滤
            if agent_filter.status and reg.status != agent_filter.status:
                continue
            card = reg.card

            # 技能过滤（OR关系）
            if agent_filter.skills:
                skill_ids = {s.id for s in card.skills}
                if not skill_ids.intersection(agent_filter.skills):
                    continue

            # 标签过滤（OR关系）
            if agent_filter.tags:
                all_tags: set[str] = set()
                for s in card.skills:
                    all_tags.update(s.tags)
                if not all_tags.intersection(agent_filter.tags):
                    continue

            # 能力过滤（OR关系）
            if agent_filter.capabilities:
                caps_dict = {
                    "streaming": card.capabilities.streaming,
                    "push_notifications": card.capabilities.push_notifications,
                    "task_management": card.capabilities.task_management,
                    "file_transfer": card.capabilities.file_transfer,
                    "group_communication": card.capabilities.group_communication,
                }
                matching = any(caps_dict.get(cap) for cap in agent_filter.capabilities)
                if not matching:
                    continue

            results.append(card)
        return results

    def list_online(self) -> list[AgentCard]:
        """仅列出在线Agent"""
        return [reg.card for reg in self._store.values() if reg.status == "online"]

    # === 心跳 ===

    def heartbeat(self, agent_name: str) -> bool:
        """心跳续约，Agent必须已注册且online"""
        reg = self._store.get(agent_name)
        if reg is None or reg.status != "online":
            return False
        now = time.time()
        reg.last_heartbeat = now
        reg.expires_at = now + self._config.default_ttl
        return True

    def check_health(self) -> list[str]:
        """检查所有Agent健康状态，返回刚标记为offline的Agent名列表"""
        now = time.time()
        unhealthy: list[str] = []
        for reg in self._store.values():
            if reg.status == "online" and reg.expires_at < now:
                reg.status = "offline"
                reg.offline_since = now
                unhealthy.append(reg.agent_name)
        return unhealthy

    # === 维护 ===

    def cleanup(self) -> int:
        """清理过期Agent，返回清理数量"""
        now = time.time()
        to_remove: list[str] = []
        for name, reg in self._store.items():
            if reg.status == "offline" and reg.offline_since is not None:
                if now - reg.offline_since > self._config.offline_ttl:
                    to_remove.append(name)
        for name in to_remove:
            del self._store[name]
        return len(to_remove)
