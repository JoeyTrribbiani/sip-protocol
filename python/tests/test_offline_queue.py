"""
离线消息队列测试
"""

import sys
import os
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sip_protocol.protocol.offline_queue import OfflineQueue


class TestOfflineQueue:
    """离线消息队列测试"""

    def test_enqueue(self):
        """测试入队"""
        q = OfflineQueue(agent_id="agent-a")
        msg_id = q.enqueue("agent-b", "agent-a", {"id": "m1", "payload": "hello"})

        assert msg_id == "m1"
        assert q.pending_count() == 1
        q.close()

    def test_deliver_pending(self):
        """测试投递积压消息"""
        q = OfflineQueue(agent_id="agent-a")
        q.enqueue("agent-b", "agent-a", {"id": "m1", "payload": "first"})
        q.enqueue("agent-c", "agent-a", {"id": "m2", "payload": "second"})

        messages = q.deliver_pending()

        assert len(messages) == 2
        assert q.pending_count() == 0
        q.close()

    def test_deliver_respects_limit(self):
        """测试投递数量限制"""
        q = OfflineQueue(agent_id="agent-a")
        for i in range(10):
            q.enqueue("agent-b", "agent-a", {"id": f"m{i}", "payload": f"msg{i}"})

        messages = q.deliver_pending(limit=3)
        assert len(messages) == 3
        assert q.pending_count() == 7
        q.close()

    def test_priority_ordering(self):
        """测试优先级排序"""
        q = OfflineQueue(agent_id="agent-a")
        q.enqueue("b", "agent-a", {"id": "low", "payload": "low"}, priority=1)
        q.enqueue("b", "agent-a", {"id": "urgent", "payload": "urgent"}, priority=4)
        q.enqueue("b", "agent-a", {"id": "normal", "payload": "normal"}, priority=2)

        messages = q.deliver_pending()

        assert messages[0]["id"] == "urgent"
        assert messages[1]["id"] == "normal"
        assert messages[2]["id"] == "low"
        q.close()

    def test_ack(self):
        """测试确认"""
        q = OfflineQueue(agent_id="agent-a")
        q.enqueue("b", "agent-a", {"id": "m1", "payload": "hi"})
        q.deliver_pending()

        assert q.ack("m1") is True
        status = q.get_status()
        assert status["acked"] == 1
        q.close()

    def test_nack(self):
        """测试拒绝重新入队"""
        q = OfflineQueue(agent_id="agent-a")
        q.enqueue("b", "agent-a", {"id": "m1", "payload": "hi"})
        q.deliver_pending()

        assert q.nack("m1") is True
        assert q.pending_count() == 1
        q.close()

    def test_expired_messages_not_delivered(self):
        """测试过期消息不被投递"""
        q = OfflineQueue(agent_id="agent-a", default_ttl=0.001)
        q.enqueue("b", "agent-a", {"id": "m1", "payload": "expired"})

        time.sleep(0.01)
        messages = q.deliver_pending()
        assert len(messages) == 0
        q.close()

    def test_max_attempts(self):
        """测试最大重试次数"""
        q = OfflineQueue(agent_id="agent-a")
        q.enqueue("b", "agent-a", {"id": "m1", "payload": "retry"})

        # 投递+拒绝3次
        for _ in range(3):
            q.deliver_pending()
            q.nack("m1")

        # 第4次不应再投递
        messages = q.deliver_pending()
        assert len(messages) == 0
        q.close()

    def test_get_status(self):
        """测试状态查询"""
        q = OfflineQueue(agent_id="agent-a")
        q.enqueue("b", "agent-a", {"id": "m1", "payload": "a"})
        q.enqueue("b", "agent-a", {"id": "m2", "payload": "b"})
        q.deliver_pending(limit=1)
        q.ack("m1")

        status = q.get_status()
        assert status["total"] == 2
        assert status["acked"] == 1
        assert status["delivered"] == 0
        assert status["pending"] == 1
        q.close()

    def test_cleanup(self):
        """测试清理"""
        q = OfflineQueue(agent_id="agent-a", default_ttl=0.001)
        q.enqueue("b", "agent-a", {"id": "m1", "payload": "expired"})

        time.sleep(0.01)
        cleaned = q.cleanup()
        assert cleaned >= 1
        q.close()

    def test_recipient_isolation(self):
        """测试不同接收者隔离"""
        q_a = OfflineQueue(agent_id="agent-a")
        q_b = OfflineQueue(agent_id="agent-b")

        q_a.enqueue("b", "agent-a", {"id": "m1", "payload": "for a"})
        q_a.enqueue("b", "agent-b", {"id": "m2", "payload": "for b"})

        # agent-a只收到自己的消息
        msgs_a = q_a.deliver_pending()
        assert len(msgs_a) == 1
        assert msgs_a[0]["id"] == "m1"

        q_a.close()
        q_b.close()
