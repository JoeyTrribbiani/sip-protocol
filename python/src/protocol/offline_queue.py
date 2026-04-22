"""
离线消息队列模块

当Agent离线时，消息缓存在队列中；Agent上线后自动投递积压消息。

功能：
1. 离线消息缓存
2. 上线后按序投递
3. 消息过期清理
4. 按优先级排序投递
5. 投递确认机制

使用方式：
    from sip_protocol.protocol.offline_queue import OfflineQueue

    queue = OfflineQueue(agent_id="agent-a")

    # 其他Agent发送消息给离线的agent-a
    queue.enqueue("agent-b", "agent-a", {"id": "msg-1", "payload": "hello"})

    # agent-a上线后
    messages = queue.deliver_pending()
    for msg in messages:
        process(msg)

    # 确认已处理
    queue.ack(msg["id"])
"""

import json
import sqlite3
import time
from typing import Any, Dict, List, Optional


class OfflineQueue:
    """
    离线消息队列

    基于SQLite的持久化队列，支持优先级排序和过期清理。
    """

    SCHEMA = """
    CREATE TABLE IF NOT EXISTS offline_messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        message_id TEXT UNIQUE NOT NULL,
        sender_id TEXT NOT NULL,
        recipient_id TEXT NOT NULL,
        payload TEXT NOT NULL,
        priority INTEGER NOT NULL DEFAULT 1,
        enqueued_at REAL NOT NULL,
        expires_at REAL,
        delivered INTEGER NOT NULL DEFAULT 0,
        delivered_at REAL,
        acked INTEGER NOT NULL DEFAULT 0,
        acked_at REAL,
        attempts INTEGER NOT NULL DEFAULT 0,
        max_attempts INTEGER NOT NULL DEFAULT 3,
        metadata TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_offline_recipient ON offline_messages(recipient_id, delivered);
    CREATE INDEX IF NOT EXISTS idx_offline_expires ON offline_messages(expires_at);
    """

    def __init__(
        self,
        agent_id: str,
        db_path: str = ":memory:",
        default_ttl: float = 86400.0,
    ):
        """
        初始化离线队列

        Args:
            agent_id: 本地Agent ID
            db_path: 数据库路径
            default_ttl: 消息默认TTL（秒）
        """
        self.agent_id = agent_id
        self._default_ttl = default_ttl
        self._conn = sqlite3.connect(db_path)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(self.SCHEMA)

    def enqueue(
        self,
        sender_id: str,
        recipient_id: str,
        message: Dict[str, Any],
        priority: int = 1,
        ttl: Optional[float] = None,
    ) -> str:
        """
        消息入队

        Args:
            sender_id: 发送者ID
            recipient_id: 接收者ID
            message: 消息内容
            priority: 优先级（1=低, 2=普通, 3=高, 4=紧急）
            ttl: 生存时间（秒），None使用默认值

        Returns:
            消息ID
        """
        message_id = message.get("id", f"off-{int(time.time()*1000)}")
        expires_at = time.time() + (ttl if ttl is not None else self._default_ttl)

        self._conn.execute(
            """
            INSERT OR REPLACE INTO offline_messages
                (message_id, sender_id, recipient_id, payload, priority,
                 enqueued_at, expires_at, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                message_id,
                sender_id,
                recipient_id,
                json.dumps(message, ensure_ascii=False),
                priority,
                time.time(),
                expires_at,
                (
                    json.dumps(message.get("metadata"), ensure_ascii=False)
                    if message.get("metadata")
                    else None
                ),
            ),
        )
        self._conn.commit()
        return message_id

    def deliver_pending(self, limit: int = 50) -> List[Dict[str, Any]]:
        """
        投递积压消息

        按优先级降序、入队时间升序返回未投递且未过期的消息。

        Args:
            limit: 最大投递数量

        Returns:
            消息列表
        """
        now = time.time()
        rows = self._conn.execute(
            """
            SELECT * FROM offline_messages
            WHERE recipient_id = ? AND delivered = 0
              AND (expires_at IS NULL OR expires_at > ?)
              AND attempts < max_attempts
            ORDER BY priority DESC, enqueued_at ASC
            LIMIT ?
            """,
            (self.agent_id, now, limit),
        ).fetchall()

        messages = []
        for row in rows:
            # 标记为已投递
            self._conn.execute(
                """
                UPDATE offline_messages
                SET delivered = 1, delivered_at = ?, attempts = attempts + 1
                WHERE message_id = ?
                """,
                (now, row["message_id"]),
            )
            messages.append(self._row_to_dict(row))

        self._conn.commit()
        return messages

    def ack(self, message_id: str) -> bool:
        """
        确认消息已处理

        Args:
            message_id: 消息ID

        Returns:
            是否确认成功
        """
        cursor = self._conn.execute(
            """
            UPDATE offline_messages SET acked = 1, acked_at = ?
            WHERE message_id = ? AND delivered = 1
            """,
            (time.time(), message_id),
        )
        self._conn.commit()
        return cursor.rowcount > 0

    def nack(self, message_id: str) -> bool:
        """
        拒绝消息，重新入队

        Args:
            message_id: 消息ID

        Returns:
            是否成功重新入队
        """
        cursor = self._conn.execute(
            """
            UPDATE offline_messages SET delivered = 0, delivered_at = NULL
            WHERE message_id = ? AND delivered = 1 AND acked = 0
            """,
            (message_id,),
        )
        self._conn.commit()
        return cursor.rowcount > 0

    def pending_count(self) -> int:
        """待投递消息数量"""
        now = time.time()
        row = self._conn.execute(
            """
            SELECT COUNT(*) FROM offline_messages
            WHERE recipient_id = ? AND delivered = 0
              AND (expires_at IS NULL OR expires_at > ?)
            """,
            (self.agent_id, now),
        ).fetchone()
        return int(row[0])  # type: ignore[arg-type]

    def cleanup(self) -> int:
        """
        清理过期和已确认的消息

        Returns:
            清理数量
        """
        now = time.time()
        cursor = self._conn.execute(
            """
            DELETE FROM offline_messages
            WHERE (expires_at IS NOT NULL AND expires_at <= ?)
               OR (acked = 1 AND acked_at < ? - 3600)
            """,
            (now, now),
        )
        self._conn.commit()
        return cursor.rowcount

    def get_status(self) -> Dict[str, int]:
        """
        获取队列状态

        Returns:
            各状态消息数量
        """
        now = time.time()
        rows = self._conn.execute(
            """
            SELECT
                COUNT(*) as total,
                SUM(CASE WHEN delivered = 0 AND (expires_at IS NULL OR expires_at > ?) THEN 1 ELSE 0 END) as pending,
                SUM(CASE WHEN delivered = 1 AND acked = 0 THEN 1 ELSE 0 END) as delivered,
                SUM(CASE WHEN acked = 1 THEN 1 ELSE 0 END) as acked,
                SUM(CASE WHEN expires_at IS NOT NULL AND expires_at <= ? THEN 1 ELSE 0 END) as expired
            FROM offline_messages
            WHERE recipient_id = ?
            """,
            (now, now, self.agent_id),
        ).fetchone()

        return {
            "total": int(rows["total"]),
            "pending": int(rows["pending"]),
            "delivered": int(rows["delivered"]),
            "acked": int(rows["acked"]),
            "expired": int(rows["expired"]),
        }

    def close(self) -> None:
        """关闭队列"""
        self._conn.close()

    def _row_to_dict(self, row: sqlite3.Row) -> Dict[str, Any]:
        """将数据库行转为字典"""
        return {
            "id": row["message_id"],
            "sender_id": row["sender_id"],
            "recipient_id": row["recipient_id"],
            "payload": json.loads(row["payload"]),
            "priority": row["priority"],
            "enqueued_at": row["enqueued_at"],
            "delivered": bool(row["delivered"]),
            "acked": bool(row["acked"]),
            "attempts": row["attempts"],
        }
