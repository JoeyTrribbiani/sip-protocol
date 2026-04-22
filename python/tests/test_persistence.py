"""
消息持久化测试
"""

import sys
import os
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.protocol.persistence import MessageStore


class TestMessageStore:
    """消息持久化测试"""

    def test_save_and_get(self):
        """测试保存和获取"""
        store = MessageStore()
        msg = {
            "id": "msg-001",
            "sender_id": "agent-a",
            "recipient_id": "agent-b",
            "type": "text",
            "payload": "Hello",
            "timestamp": time.time(),
        }
        store.save(msg)
        result = store.get("msg-001")

        assert result is not None
        assert result["id"] == "msg-001"
        assert result["sender_id"] == "agent-a"
        assert result["payload"] == "Hello"
        store.close()

    def test_get_nonexistent(self):
        """测试获取不存在的消息"""
        store = MessageStore()
        result = store.get("nonexistent")
        assert result is None
        store.close()

    def test_query_by_sender(self):
        """测试按发送者查询"""
        store = MessageStore()
        for i in range(5):
            store.save(
                {
                    "id": f"msg-{i}",
                    "sender_id": "agent-a" if i < 3 else "agent-b",
                    "payload": f"Message {i}",
                    "timestamp": time.time() + i,
                }
            )

        results = store.query(filters={"sender": "agent-a"})
        assert len(results) == 3

        results_b = store.query(filters={"sender": "agent-b"})
        assert len(results_b) == 2
        store.close()

    def test_query_by_recipient(self):
        """测试按接收者查询"""
        store = MessageStore()
        store.save({"id": "msg-1", "sender_id": "a", "recipient_id": "b", "payload": "hi"})
        store.save({"id": "msg-2", "sender_id": "a", "recipient_id": "c", "payload": "hey"})
        store.save({"id": "msg-3", "sender_id": "b", "recipient_id": "b", "payload": "self"})

        results = store.query(filters={"recipient": "b"})
        assert len(results) == 2
        store.close()

    def test_query_by_time_range(self):
        """测试按时间范围查询"""
        store = MessageStore()
        base = time.time()
        for i in range(5):
            store.save(
                {
                    "id": f"msg-{i}",
                    "sender_id": "agent-a",
                    "payload": f"Msg {i}",
                    "timestamp": base + i * 100,
                }
            )

        results = store.query(filters={"since": base + 150, "until": base + 350})
        assert len(results) == 2
        store.close()

    def test_query_limit_and_offset(self):
        """测试分页查询"""
        store = MessageStore()
        for i in range(10):
            store.save(
                {
                    "id": f"msg-{i}",
                    "sender_id": "agent-a",
                    "payload": f"Msg {i}",
                    "timestamp": time.time() + i,
                }
            )

        page1 = store.query(limit=3, offset=0)
        assert len(page1) == 3

        page2 = store.query(limit=3, offset=3)
        assert len(page2) == 3

        # 不重叠
        ids1 = {m["id"] for m in page1}
        ids2 = {m["id"] for m in page2}
        assert ids1.isdisjoint(ids2)
        store.close()

    def test_query_by_session(self):
        """测试按会话查询"""
        store = MessageStore()
        store.save({"id": "msg-1", "sender_id": "a", "payload": "hi", "session_id": "sess-1"})
        store.save({"id": "msg-2", "sender_id": "a", "payload": "hey", "session_id": "sess-2"})
        store.save({"id": "msg-3", "sender_id": "a", "payload": "yo", "session_id": "sess-1"})

        results = store.query(filters={"session_id": "sess-1"})
        assert len(results) == 2
        store.close()

    def test_count(self):
        """测试计数"""
        store = MessageStore()
        store.save({"id": "msg-1", "sender_id": "a", "recipient_id": "b", "payload": "hi"})
        store.save({"id": "msg-2", "sender_id": "a", "recipient_id": "c", "payload": "hey"})
        store.save({"id": "msg-3", "sender_id": "b", "recipient_id": "b", "payload": "self"})

        assert store.count() == 3
        assert store.count(sender="a") == 2
        assert store.count(recipient="b") == 2
        store.close()

    def test_delete(self):
        """测试删除"""
        store = MessageStore()
        store.save({"id": "msg-1", "sender_id": "a", "payload": "hi"})

        assert store.delete("msg-1") is True
        assert store.get("msg-1") is None
        assert store.delete("msg-1") is False
        store.close()

    def test_cleanup(self):
        """测试清理过期消息"""
        store = MessageStore(max_age_days=0.00001)  # 约1秒过期
        old_time = time.time() - 100
        store.save({"id": "msg-old", "sender_id": "a", "payload": "old", "timestamp": old_time})
        store.save({"id": "msg-new", "sender_id": "a", "payload": "new", "timestamp": time.time()})

        time.sleep(0.1)
        deleted = store.cleanup()

        assert deleted == 1
        assert store.get("msg-old") is None
        assert store.get("msg-new") is not None
        store.close()

    def test_encrypted_message(self):
        """测试加密消息存储"""
        store = MessageStore()
        store.save(
            {
                "id": "msg-enc",
                "sender_id": "agent-a",
                "payload": {"ciphertext": "base64data", "nonce": "abc"},
                "encrypted": True,
                "timestamp": time.time(),
            }
        )

        result = store.get("msg-enc")
        assert result is not None
        assert result["encrypted"] is True
        assert isinstance(result["payload"], dict)
        store.close()

    def test_get_sessions(self):
        """测试获取会话列表"""
        store = MessageStore()
        store.save({"id": "m1", "sender_id": "a", "payload": "hi", "session_id": "s1"})
        store.save({"id": "m2", "sender_id": "a", "payload": "hey", "session_id": "s1"})
        store.save({"id": "m3", "sender_id": "b", "payload": "yo", "session_id": "s2"})

        sessions = store.get_sessions()
        assert len(sessions) == 2
        s1 = [s for s in sessions if s["session_id"] == "s1"][0]
        assert s1["message_count"] == 2
        store.close()

    def test_save_duplicate_id(self):
        """测试重复ID覆盖"""
        store = MessageStore()
        store.save({"id": "msg-1", "sender_id": "a", "payload": "first"})
        store.save({"id": "msg-1", "sender_id": "a", "payload": "second"})

        result = store.get("msg-1")
        assert result["payload"] == "second"
        assert store.count() == 1
        store.close()

    def test_file_based_db(self):
        """测试文件数据库"""
        import tempfile

        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name

        try:
            store1 = MessageStore(db_path=db_path)
            store1.save({"id": "msg-1", "sender_id": "a", "payload": "persisted"})
            store1.close()

            store2 = MessageStore(db_path=db_path)
            result = store2.get("msg-1")
            assert result is not None
            assert result["payload"] == "persisted"
            store2.close()
        finally:
            os.unlink(db_path)
