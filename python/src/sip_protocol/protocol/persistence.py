"""
消息持久化模块

将Agent消息持久化到SQLite数据库，支持：
1. 消息存储和检索
2. 按时间/发送者/类型过滤
3. 会话历史记录
4. 加密消息原样存储（不解密）
5. 自动清理过期消息

使用方式：
    from sip_protocol.protocol.persistence import MessageStore

    store = MessageStore(db_path="messages.db")
    store.save(message_dict)
    messages = store.query(sender="agent-a", limit=20)
    store.close()
"""

import json
import sqlite3
import time
from typing import Any, Dict, List, Optional


class MessageStore:
    """
    消息持久化存储

    基于SQLite的轻量级消息存储，支持过滤和分页查询。
    """

    SCHEMA = """
    CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        message_id TEXT UNIQUE NOT NULL,
        sender_id TEXT NOT NULL,
        recipient_id TEXT,
        message_type TEXT NOT NULL DEFAULT 'text',
        priority INTEGER NOT NULL DEFAULT 1,
        payload TEXT NOT NULL,
        encrypted INTEGER NOT NULL DEFAULT 0,
        created_at REAL NOT NULL,
        session_id TEXT,
        metadata TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_messages_sender ON messages(sender_id);
    CREATE INDEX IF NOT EXISTS idx_messages_recipient ON messages(recipient_id);
    CREATE INDEX IF NOT EXISTS idx_messages_created ON messages(created_at);
    CREATE INDEX IF NOT EXISTS idx_messages_session ON messages(session_id);
    """

    def __init__(
        self,
        db_path: str = ":memory:",
        max_age_days: float = 30.0,
    ):
        """
        初始化消息存储

        Args:
            db_path: SQLite数据库路径（默认内存数据库）
            max_age_days: 消息最大保留天数
        """
        self._db_path = db_path
        self._max_age_days = max_age_days
        self._conn = sqlite3.connect(db_path)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(self.SCHEMA)

    def save(self, message: Dict[str, Any]) -> int:
        """
        保存消息

        Args:
            message: 消息字典，需包含 message_id, sender_id, payload

        Returns:
            数据库行ID
        """
        sql = """
        INSERT OR REPLACE INTO messages
            (message_id, sender_id, recipient_id, message_type,
             priority, payload, encrypted, created_at, session_id, metadata)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        cursor = self._conn.execute(
            sql,
            (
                message.get("id", ""),
                message.get("sender_id", ""),
                message.get("recipient_id"),
                message.get("type", "text"),
                message.get("priority", 1),
                json.dumps(message.get("payload", ""), ensure_ascii=False),
                1 if message.get("encrypted") else 0,
                message.get("timestamp", time.time()),
                message.get("session_id"),
                (
                    json.dumps(message.get("metadata"), ensure_ascii=False)
                    if message.get("metadata")
                    else None
                ),
            ),
        )
        self._conn.commit()
        return cursor.lastrowid or 0

    def get(self, message_id: str) -> Optional[Dict[str, Any]]:
        """
        按ID获取消息

        Args:
            message_id: 消息ID

        Returns:
            消息字典，不存在返回None
        """
        row = self._conn.execute(
            "SELECT * FROM messages WHERE message_id = ?", (message_id,)
        ).fetchone()

        if row is None:
            return None

        return self._row_to_dict(row)

    def query(
        self,
        filters: Optional[Dict[str, Any]] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        """
        查询消息

        Args:
            filters: 过滤条件，支持 sender, recipient, message_type, session_id, since, until
            limit: 返回数量限制
            offset: 偏移量

        Returns:
            消息列表
        """
        flt = filters or {}
        conditions: List[str] = []
        params: List[Any] = []

        if flt.get("sender") is not None:
            conditions.append("sender_id = ?")
            params.append(flt["sender"])
        if flt.get("recipient") is not None:
            conditions.append("recipient_id = ?")
            params.append(flt["recipient"])
        if flt.get("message_type") is not None:
            conditions.append("message_type = ?")
            params.append(flt["message_type"])
        if flt.get("session_id") is not None:
            conditions.append("session_id = ?")
            params.append(flt["session_id"])
        if flt.get("since") is not None:
            conditions.append("created_at >= ?")
            params.append(flt["since"])
        if flt.get("until") is not None:
            conditions.append("created_at <= ?")
            params.append(flt["until"])

        where = " AND ".join(conditions) if conditions else "1=1"
        sql = f"SELECT * FROM messages WHERE {where} ORDER BY created_at DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        rows = self._conn.execute(sql, params).fetchall()
        return [self._row_to_dict(row) for row in rows]

    def count(
        self,
        sender: Optional[str] = None,
        recipient: Optional[str] = None,
        session_id: Optional[str] = None,
    ) -> int:
        """
        统计消息数量

        Args:
            sender: 按发送者过滤
            recipient: 按接收者过滤
            session_id: 按会话ID过滤

        Returns:
            消息数量
        """
        conditions: List[str] = []
        params: List[Any] = []

        if sender is not None:
            conditions.append("sender_id = ?")
            params.append(sender)
        if recipient is not None:
            conditions.append("recipient_id = ?")
            params.append(recipient)
        if session_id is not None:
            conditions.append("session_id = ?")
            params.append(session_id)

        where = " AND ".join(conditions) if conditions else "1=1"
        row = self._conn.execute(f"SELECT COUNT(*) FROM messages WHERE {where}", params).fetchone()
        return int(row[0])  # type: ignore[arg-type]

    def delete(self, message_id: str) -> bool:
        """
        删除消息

        Args:
            message_id: 消息ID

        Returns:
            是否删除成功
        """
        cursor = self._conn.execute("DELETE FROM messages WHERE message_id = ?", (message_id,))
        self._conn.commit()
        return cursor.rowcount > 0

    def cleanup(self) -> int:
        """
        清理过期消息

        Returns:
            删除的消息数量
        """
        cutoff = time.time() - (self._max_age_days * 86400)
        cursor = self._conn.execute("DELETE FROM messages WHERE created_at < ?", (cutoff,))
        self._conn.commit()
        return cursor.rowcount

    def get_sessions(self) -> List[Dict[str, Any]]:
        """
        获取所有会话列表

        Returns:
            会话列表（session_id, 消息数, 最新消息时间）
        """
        rows = self._conn.execute("""
            SELECT session_id, COUNT(*) as msg_count, MAX(created_at) as last_msg
            FROM messages
            WHERE session_id IS NOT NULL
            GROUP BY session_id
            ORDER BY last_msg DESC
            """).fetchall()
        return [
            {
                "session_id": row["session_id"],
                "message_count": row["msg_count"],
                "last_message_at": row["last_msg"],
            }
            for row in rows
        ]

    def close(self) -> None:
        """关闭数据库连接"""
        self._conn.close()

    def _row_to_dict(self, row: sqlite3.Row) -> Dict[str, Any]:
        """将数据库行转为字典"""
        return {
            "id": row["message_id"],
            "sender_id": row["sender_id"],
            "recipient_id": row["recipient_id"],
            "type": row["message_type"],
            "priority": row["priority"],
            "payload": json.loads(row["payload"]),
            "encrypted": bool(row["encrypted"]),
            "timestamp": row["created_at"],
            "session_id": row["session_id"],
            "metadata": json.loads(row["metadata"]) if row["metadata"] else None,
        }
