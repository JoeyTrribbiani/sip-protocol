"""AgentRegistry SQLite 存储层"""

from __future__ import annotations

import json
import os
import sqlite3
import time

from sip_protocol.discovery.agent_card import AgentCard, AgentRegistration


class RegistryStore:
    """SQLite 存储层 — Agent 注册记录持久化"""

    def __init__(self, db_path: str = "~/.openclaw/sip_registry.db") -> None:
        self._db_path = os.path.expanduser(db_path)
        self._conn: sqlite3.Connection | None = None
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        """获取数据库连接（延迟创建）"""
        if self._conn is None:
            parent = os.path.dirname(self._db_path)
            if parent:
                os.makedirs(parent, exist_ok=True)
            self._conn = sqlite3.connect(self._db_path)
            self._conn.row_factory = sqlite3.Row
            self._init_db()
        return self._conn

    def _init_db(self) -> None:
        """初始化数据库表和索引"""
        conn = self._get_conn()
        conn.execute("""
            CREATE TABLE IF NOT EXISTS agents (
                agent_name TEXT PRIMARY KEY,
                card_json TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'online',
                registered_at REAL NOT NULL,
                last_heartbeat REAL NOT NULL,
                expires_at REAL NOT NULL,
                offline_since REAL
            )
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_agents_status
            ON agents(status)
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_agents_expires
            ON agents(expires_at)
        """)
        conn.commit()

    def save(self, registration: AgentRegistration) -> None:
        """保存注册记录（INSERT OR REPLACE）"""
        conn = self._get_conn()
        conn.execute(
            """
            INSERT OR REPLACE INTO agents
                (agent_name, card_json, status, registered_at,
                 last_heartbeat, expires_at, offline_since)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
            (
                registration.agent_name,
                json.dumps(registration.card.to_dict(), ensure_ascii=False),
                registration.status,
                registration.registered_at,
                registration.last_heartbeat,
                registration.expires_at,
                registration.offline_since,
            ),
        )
        conn.commit()

    def load(self, agent_name: str) -> AgentRegistration | None:
        """按名称查询注册记录"""
        conn = self._get_conn()
        row = conn.execute(
            "SELECT * FROM agents WHERE agent_name = ?",
            (agent_name,),
        ).fetchone()
        if row is None:
            return None
        return self._row_to_registration(row)

    def delete(self, agent_name: str) -> bool:
        """删除注册记录"""
        conn = self._get_conn()
        cursor = conn.execute(
            "DELETE FROM agents WHERE agent_name = ?",
            (agent_name,),
        )
        conn.commit()
        return cursor.rowcount > 0

    def list_all(self) -> list[AgentRegistration]:
        """列出所有注册记录"""
        conn = self._get_conn()
        rows = conn.execute("SELECT * FROM agents").fetchall()
        return [self._row_to_registration(row) for row in rows]

    def update_status(
        self,
        agent_name: str,
        status: str,
        expires_at: float,
        last_heartbeat: float,
        offline_since: float | None = None,
    ) -> bool:
        """更新状态"""
        conn = self._get_conn()
        cursor = conn.execute(
            """
            UPDATE agents
            SET status = ?, expires_at = ?,
                last_heartbeat = ?, offline_since = ?
            WHERE agent_name = ?
        """,
            (status, expires_at, last_heartbeat, offline_since, agent_name),
        )
        conn.commit()
        return cursor.rowcount > 0

    def find_expired(self, now: float | None = None) -> list[AgentRegistration]:
        """查找过期但仍标记为online的Agent"""
        if now is None:
            now = time.time()
        conn = self._get_conn()
        rows = conn.execute(
            """
            SELECT * FROM agents
            WHERE status = 'online' AND expires_at < ?
        """,
            (now,),
        ).fetchall()
        return [self._row_to_registration(row) for row in rows]

    def find_offline_expired(
        self,
        offline_ttl: int,
        now: float | None = None,
    ) -> list[AgentRegistration]:
        """查找离线超过offline_ttl的Agent"""
        if now is None:
            now = time.time()
        cutoff = now - offline_ttl
        conn = self._get_conn()
        rows = conn.execute(
            """
            SELECT * FROM agents
            WHERE status = 'offline'
                AND offline_since IS NOT NULL
                AND offline_since < ?
        """,
            (cutoff,),
        ).fetchall()
        return [self._row_to_registration(row) for row in rows]

    def _row_to_registration(self, row: sqlite3.Row) -> AgentRegistration:
        """将数据库行转换为AgentRegistration"""
        card_dict = json.loads(row["card_json"])
        return AgentRegistration(
            agent_name=row["agent_name"],
            card=AgentCard.from_dict(card_dict),
            status=row["status"],
            registered_at=row["registered_at"],
            last_heartbeat=row["last_heartbeat"],
            expires_at=row["expires_at"],
            offline_since=row["offline_since"],
        )

    def close(self) -> None:
        """关闭数据库连接"""
        if self._conn is not None:
            self._conn.close()
            self._conn = None
