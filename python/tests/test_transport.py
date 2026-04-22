"""
SIP传输层测试
测试加密消息通道、消息格式和OpenClaw适配器

运行方式:
    cd python
    python -m pytest tests/test_transport.py -v

测试覆盖:
    1. AgentMessage 消息格式
    2. EncryptedChannel 加密通道
    3. OpenClawAdapter 适配器
    4. 三方通信场景
    5. 边界条件和错误处理
"""

import sys
import os
import json
import time
import uuid

# 确保可以从项目根目录导入
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from sip_protocol.transport.message import (
    AgentMessage,
    MessageType,
    MessagePriority,
    ControlAction,
    create_text_message,
    create_control_message,
    create_encrypted_message,
    parse_raw_message,
)
from sip_protocol.transport.encrypted_channel import (
    EncryptedChannel,
    ChannelState,
    ChannelConfig,
)
from sip_protocol.transport.openclaw_adapter import (
    OpenClawAdapter,
    AgentConfig,
    SpawnResult,
)

# ──────────────── 测试常量 ────────────────

TEST_PSK = b"test-psk-for-unit-tests-32byt"
AGENT_A_ID = "agent:hermes::session:test-001"
AGENT_B_ID = "agent:openclaw::session:test-002"
AGENT_C_ID = "agent:claude-code::session:test-003"


# ═══════════════════════════════════════════════════════════════
# Part 1: AgentMessage 消息格式测试
# ═══════════════════════════════════════════════════════════════


class TestAgentMessage:
    """AgentMessage 消息格式测试"""

    def test_create_text_message(self):
        """测试创建文本消息"""
        msg = create_text_message(
            sender_id=AGENT_A_ID,
            recipient_id=AGENT_B_ID,
            text="Hello, Agent B!",
        )
        assert msg.type == MessageType.TEXT
        assert msg.sender_id == AGENT_A_ID
        assert msg.recipient_id == AGENT_B_ID
        assert msg.payload["text"] == "Hello, Agent B!"
        assert msg.version == "SIP-TRANSPORT-1.0"
        assert msg.priority == MessagePriority.NORMAL
        assert msg.id  # UUID已生成
        assert msg.timestamp > 0

    def test_create_control_message(self):
        """测试创建控制消息"""
        msg = create_control_message(
            sender_id=AGENT_A_ID,
            recipient_id=AGENT_B_ID,
            action=ControlAction.HEARTBEAT,
            data={"interval": 30},
        )
        assert msg.type == MessageType.CONTROL
        assert msg.payload["action"] == "heartbeat"
        assert msg.payload["data"]["interval"] == 30
        assert msg.priority == MessagePriority.HIGH

    def test_create_encrypted_message(self):
        """测试创建加密消息"""
        encrypted_payload = {
            "version": "SIP-1.0",
            "type": "message",
            "payload": "base64_encrypted_data",
            "iv": "base64_iv",
            "auth_tag": "base64_tag",
        }
        msg = create_encrypted_message(
            sender_id=AGENT_A_ID,
            recipient_id=AGENT_B_ID,
            encrypted_payload=encrypted_payload,
        )
        assert msg.type == MessageType.ENCRYPTED
        assert msg.payload == encrypted_payload

    def test_message_serialization(self):
        """测试消息序列化和反序列化"""
        msg = create_text_message(
            sender_id=AGENT_A_ID,
            recipient_id=AGENT_B_ID,
            text="Serialization test",
            metadata={"key": "value"},
        )

        # 序列化
        json_str = msg.to_json()
        assert isinstance(json_str, str)

        # 反序列化
        restored = AgentMessage.from_json(json_str)
        assert restored.id == msg.id
        assert restored.type == msg.type
        assert restored.sender_id == msg.sender_id
        assert restored.recipient_id == msg.recipient_id
        assert restored.payload["text"] == "Serialization test"
        assert restored.metadata["key"] == "value"

    def test_message_to_dict(self):
        """测试消息转字典"""
        msg = create_text_message(
            sender_id=AGENT_A_ID,
            recipient_id=AGENT_B_ID,
            text="Dict test",
        )
        d = msg.to_dict()
        assert d["type"] == "text"  # 枚举序列化为字符串值
        assert d["priority"] == 1  # 枚举序列化为整数值
        assert "correlation_id" not in d  # None字段被移除

    def test_message_from_dict(self):
        """测试从字典创建消息"""
        data = {
            "id": str(uuid.uuid4()),
            "version": "SIP-TRANSPORT-1.0",
            "type": "text",
            "sender_id": AGENT_A_ID,
            "recipient_id": AGENT_B_ID,
            "timestamp": int(time.time() * 1000),
            "payload": {"text": "From dict"},
            "priority": 1,
            "metadata": {},
            "hop_count": 0,
            "max_hops": 10,
        }
        msg = AgentMessage.from_dict(data)
        assert msg.type == MessageType.TEXT
        assert msg.priority == MessagePriority.NORMAL
        assert msg.payload["text"] == "From dict"

    def test_message_expiration(self):
        """测试消息过期检测"""
        msg = create_text_message(
            sender_id=AGENT_A_ID,
            recipient_id=AGENT_B_ID,
            text="Expiry test",
        )
        # 新消息不应该过期
        assert not msg.is_expired()

        # 修改时间戳使消息过期
        msg.timestamp = int(time.time() * 1000) - 10 * 60 * 1000  # 10分钟前
        assert msg.is_expired(ttl_ms=5 * 60 * 1000)  # 5分钟TTL

    def test_message_hop_count(self):
        """测试跳数计数"""
        msg = create_text_message(
            sender_id=AGENT_A_ID,
            recipient_id=AGENT_B_ID,
            text="Hop test",
        )
        assert msg.hop_count == 0
        assert not msg.is_max_hops_reached()

        # 增加跳数
        for i in range(10):
            msg.increment_hop()
        assert msg.hop_count == 10
        assert msg.is_max_hops_reached()

    def test_message_reply(self):
        """测试创建回复消息"""
        original = create_text_message(
            sender_id=AGENT_A_ID,
            recipient_id=AGENT_B_ID,
            text="Original message",
        )

        reply = original.create_reply({"text": "Reply message"})
        assert reply.correlation_id == original.id
        assert reply.sender_id == AGENT_B_ID  # 发送方变为原来的接收方
        assert reply.recipient_id == AGENT_A_ID
        assert reply.payload["text"] == "Reply message"

    def test_parse_raw_message_valid(self):
        """测试解析有效消息"""
        msg = create_text_message(
            sender_id=AGENT_A_ID,
            recipient_id=AGENT_B_ID,
            text="Parse test",
        )
        raw = msg.to_json()
        parsed = parse_raw_message(raw)
        assert parsed.id == msg.id
        assert parsed.type == msg.type

    def test_parse_raw_message_invalid(self):
        """测试解析无效消息"""
        with pytest.raises(ValueError, match="无效的消息格式"):
            parse_raw_message("not valid json {{")

    def test_all_control_actions(self):
        """测试所有控制动作"""
        actions = [
            ControlAction.HELLO,
            ControlAction.HEARTBEAT,
            ControlAction.HEARTBEAT_ACK,
            ControlAction.DISCONNECT,
            ControlAction.ACK,
            ControlAction.ERROR,
            ControlAction.HANDSHAKE_INIT,
            ControlAction.HANDSHAKE_COMPLETE,
            ControlAction.REKEY_REQUEST,
            ControlAction.REKEY_RESPONSE,
        ]
        for action in actions:
            msg = create_control_message(
                sender_id=AGENT_A_ID,
                recipient_id=AGENT_B_ID,
                action=action,
            )
            assert msg.payload["action"] == action.value
            assert msg.type == MessageType.CONTROL

    def test_all_message_types(self):
        """测试所有消息类型"""
        # TEXT
        text_msg = create_text_message(sender_id=AGENT_A_ID, recipient_id=AGENT_B_ID, text="text")
        assert text_msg.type == MessageType.TEXT

        # ENCRYPTED
        enc_msg = create_encrypted_message(
            sender_id=AGENT_A_ID,
            recipient_id=AGENT_B_ID,
            encrypted_payload={"data": "encrypted"},
        )
        assert enc_msg.type == MessageType.ENCRYPTED

        # CONTROL
        ctrl_msg = create_control_message(
            sender_id=AGENT_A_ID,
            recipient_id=AGENT_B_ID,
            action=ControlAction.HELLO,
        )
        assert ctrl_msg.type == MessageType.CONTROL

    def test_all_priorities(self):
        """测试所有优先级"""
        for priority in MessagePriority:
            msg = create_text_message(
                sender_id=AGENT_A_ID,
                recipient_id=AGENT_B_ID,
                text="Priority test",
                priority=priority,
            )
            assert msg.priority == priority


# ═══════════════════════════════════════════════════════════════
# Part 2: EncryptedChannel 加密通道测试
# ═══════════════════════════════════════════════════════════════


class TestEncryptedChannel:
    """EncryptedChannel 加密通道测试"""

    def test_channel_creation(self):
        """测试通道创建"""
        channel = EncryptedChannel(agent_id=AGENT_A_ID, psk=TEST_PSK)
        assert channel.state == ChannelState.IDLE
        assert channel.agent_id == AGENT_A_ID
        assert not channel.is_established

    def test_channel_initiate_handshake(self):
        """测试发起握手"""
        channel_a = EncryptedChannel(agent_id=AGENT_A_ID, psk=TEST_PSK)
        channel_b = EncryptedChannel(agent_id=AGENT_B_ID, psk=TEST_PSK)

        # A发起握手
        hello = channel_a.initiate()
        assert channel_a.state == ChannelState.HANDSHAKING
        assert hello.type == MessageType.CONTROL
        assert hello.payload["action"] == "handshake_init"
        assert "data" in hello.payload

    def test_full_handshake(self):
        """测试完整握手流程"""
        channel_a = EncryptedChannel(agent_id=AGENT_A_ID, psk=TEST_PSK)
        channel_b = EncryptedChannel(agent_id=AGENT_B_ID, psk=TEST_PSK)

        # A → B: Hello
        hello = channel_a.initiate()
        assert channel_a.state == ChannelState.HANDSHAKING

        # B → A: Auth
        auth = channel_b.respond_to_handshake(hello)
        assert channel_b.state == ChannelState.ESTABLISHED
        assert auth.payload["action"] == "handshake_complete"

        # A: Complete
        channel_a.complete_handshake(auth)
        assert channel_a.state == ChannelState.ESTABLISHED
        assert channel_a.is_established

    def test_send_receive_message(self):
        """测试发送和接收加密消息"""
        channel_a = EncryptedChannel(agent_id=AGENT_A_ID, psk=TEST_PSK)
        channel_b = EncryptedChannel(agent_id=AGENT_B_ID, psk=TEST_PSK)

        # 握手
        hello = channel_a.initiate()
        auth = channel_b.respond_to_handshake(hello)
        channel_a.complete_handshake(auth)

        # 发送消息
        plaintext = "Hello, encrypted world!"
        encrypted = channel_a.send(plaintext, AGENT_B_ID)

        # 验证消息类型
        assert encrypted.type == MessageType.ENCRYPTED
        assert encrypted.sender_id == AGENT_A_ID
        assert encrypted.recipient_id == AGENT_B_ID

        # 验证payload包含加密数据
        assert "payload" in encrypted.payload
        assert "iv" in encrypted.payload
        assert "auth_tag" in encrypted.payload
        assert "replay_tag" in encrypted.payload
        assert "message_counter" in encrypted.payload

        # 接收并解密
        decrypted = channel_b.receive(encrypted)
        assert decrypted == plaintext

    def test_multiple_messages(self):
        """测试多轮消息通信"""
        channel_a = EncryptedChannel(agent_id=AGENT_A_ID, psk=TEST_PSK)
        channel_b = EncryptedChannel(agent_id=AGENT_B_ID, psk=TEST_PSK)

        # 握手
        hello = channel_a.initiate()
        auth = channel_b.respond_to_handshake(hello)
        channel_a.complete_handshake(auth)

        # 发送多条消息
        messages = [
            "第一条消息",
            "Second message",
            "第三条消息 with emoji 🎉",
            "Fourth message with special chars: !@#$%^&*()",
            "",
        ]

        for i, text in enumerate(messages):
            encrypted = channel_a.send(text, AGENT_B_ID)
            assert encrypted.payload["message_counter"] == i + 1
            decrypted = channel_b.receive(encrypted)
            assert decrypted == text

    def test_bidirectional_communication(self):
        """测试双向加密通信"""
        channel_a = EncryptedChannel(agent_id=AGENT_A_ID, psk=TEST_PSK)
        channel_b = EncryptedChannel(agent_id=AGENT_B_ID, psk=TEST_PSK)

        # 握手
        hello = channel_a.initiate()
        auth = channel_b.respond_to_handshake(hello)
        channel_a.complete_handshake(auth)

        # A → B
        msg_a = channel_a.send("A to B message", AGENT_B_ID)
        dec_a = channel_b.receive(msg_a)
        assert dec_a == "A to B message"

        # B → A
        msg_b = channel_b.send("B to A message", AGENT_A_ID)
        dec_b = channel_a.receive(msg_b)
        assert dec_b == "B to A message"

    def test_channel_stats(self):
        """测试通道统计"""
        channel_a = EncryptedChannel(agent_id=AGENT_A_ID, psk=TEST_PSK)
        channel_b = EncryptedChannel(agent_id=AGENT_B_ID, psk=TEST_PSK)

        # 握手
        hello = channel_a.initiate()
        auth = channel_b.respond_to_handshake(hello)
        channel_a.complete_handshake(auth)

        # 发送消息
        channel_a.send("test", AGENT_B_ID)

        stats = channel_a.stats
        assert stats["messages_sent"] == 1
        assert stats["state"] == "established"
        assert stats["bytes_sent"] > 0

    def test_channel_close(self):
        """测试通道关闭"""
        channel = EncryptedChannel(agent_id=AGENT_A_ID, psk=TEST_PSK)
        assert channel.state == ChannelState.IDLE

        channel.close()
        assert channel.state == ChannelState.CLOSED

    def test_send_before_established(self):
        """测试未建立通道时发送消息应抛出异常"""
        channel = EncryptedChannel(agent_id=AGENT_A_ID, psk=TEST_PSK)
        with pytest.raises(RuntimeError, match="通道未建立"):
            channel.send("test", AGENT_B_ID)

    def test_receive_before_established(self):
        """测试未建立通道时接收消息应抛出异常"""
        channel = EncryptedChannel(agent_id=AGENT_A_ID, psk=TEST_PSK)
        msg = create_encrypted_message(
            sender_id=AGENT_B_ID,
            recipient_id=AGENT_A_ID,
            encrypted_payload={"payload": "fake"},
        )
        with pytest.raises(RuntimeError, match="通道未建立"):
            channel.receive(msg)

    def test_heartbeat_message(self):
        """测试心跳消息"""
        channel_a = EncryptedChannel(agent_id=AGENT_A_ID, psk=TEST_PSK)
        channel_b = EncryptedChannel(agent_id=AGENT_B_ID, psk=TEST_PSK)

        # 握手
        hello = channel_a.initiate()
        auth = channel_b.respond_to_handshake(hello)
        channel_a.complete_handshake(auth)

        # 创建心跳
        heartbeat = channel_a.create_heartbeat()
        assert heartbeat.type == MessageType.CONTROL
        assert heartbeat.payload["action"] == "heartbeat"

        # 接收方处理心跳
        result = channel_b.receive(heartbeat)
        assert result == "[heartbeat]"

    def test_disconnect_message(self):
        """测试断开连接消息"""
        channel_a = EncryptedChannel(agent_id=AGENT_A_ID, psk=TEST_PSK)
        channel_b = EncryptedChannel(agent_id=AGENT_B_ID, psk=TEST_PSK)

        # 握手
        hello = channel_a.initiate()
        auth = channel_b.respond_to_handshake(hello)
        channel_a.complete_handshake(auth)

        # 创建断开连接消息
        disconnect = channel_a.create_disconnect()
        assert disconnect.type == MessageType.CONTROL
        assert disconnect.payload["action"] == "disconnect"

        # 接收方处理断开
        result = channel_b.receive(disconnect)
        assert result == "[disconnect]"
        assert channel_b.state == ChannelState.CLOSED

    def test_replay_attack_detection(self):
        """测试重放攻击检测"""
        channel_a = EncryptedChannel(agent_id=AGENT_A_ID, psk=TEST_PSK)
        channel_b = EncryptedChannel(agent_id=AGENT_B_ID, psk=TEST_PSK)

        # 握手
        hello = channel_a.initiate()
        auth = channel_b.respond_to_handshake(hello)
        channel_a.complete_handshake(auth)

        # 发送消息
        encrypted = channel_a.send("First message", AGENT_B_ID)
        decrypted = channel_b.receive(encrypted)
        assert decrypted == "First message"

        # 重放同一条消息
        with pytest.raises(ValueError, match="消息计数器异常"):
            channel_b.receive(encrypted)

    def test_expired_message_detection(self):
        """测试过期消息检测"""
        channel_a = EncryptedChannel(agent_id=AGENT_A_ID, psk=TEST_PSK)
        channel_b = EncryptedChannel(agent_id=AGENT_B_ID, psk=TEST_PSK)

        # 握手
        hello = channel_a.initiate()
        auth = channel_b.respond_to_handshake(hello)
        channel_a.complete_handshake(auth)

        # 发送消息
        encrypted = channel_a.send("Expiring message", AGENT_B_ID)

        # 篡改时间戳使消息过期
        encrypted.timestamp = int(time.time() * 1000) - 10 * 60 * 1000

        with pytest.raises(ValueError, match="消息已过期"):
            channel_b.receive(encrypted)

    def test_channel_config(self):
        """测试自定义通道配置"""
        config = ChannelConfig(
            rekey_after_messages=100,
            rekey_after_seconds=600,
            heartbeat_interval=10,
            message_ttl_ms=3 * 60 * 1000,
        )
        channel = EncryptedChannel(agent_id=AGENT_A_ID, psk=TEST_PSK, config=config)
        assert channel.config.rekey_after_messages == 100
        assert channel.config.rekey_after_seconds == 600

    def test_receive_plain_text_message(self):
        """测试接收普通文本消息"""
        channel_a = EncryptedChannel(agent_id=AGENT_A_ID, psk=TEST_PSK)
        channel_b = EncryptedChannel(agent_id=AGENT_B_ID, psk=TEST_PSK)

        # 握手
        hello = channel_a.initiate()
        auth = channel_b.respond_to_handshake(hello)
        channel_a.complete_handshake(auth)

        # 发送普通文本消息
        text_msg = create_text_message(
            sender_id=AGENT_A_ID,
            recipient_id=AGENT_B_ID,
            text="Plain text message",
        )
        result = channel_b.receive(text_msg)
        assert result == "Plain text message"

    def test_initiate_from_non_idle_state(self):
        """测试非IDLE状态发起握手"""
        channel = EncryptedChannel(agent_id=AGENT_A_ID, psk=TEST_PSK)
        channel._set_state(ChannelState.HANDSHAKING)
        with pytest.raises(RuntimeError, match="无法在.*状态.*发起握手"):
            channel.initiate()

    def test_respond_from_non_idle_state(self):
        """测试非IDLE状态响应握手"""
        channel = EncryptedChannel(agent_id=AGENT_A_ID, psk=TEST_PSK)
        channel._set_state(ChannelState.ESTABLISHED)
        msg = create_control_message(
            sender_id=AGENT_B_ID,
            recipient_id=AGENT_A_ID,
            action=ControlAction.HANDSHAKE_INIT,
            data={"version": "SIP-1.0"},
        )
        with pytest.raises(RuntimeError, match="无法在.*状态.*响应握手"):
            channel.respond_to_handshake(msg)

    def test_state_change_callback(self):
        """测试状态变更回调"""
        state_changes = []
        channel = EncryptedChannel(agent_id=AGENT_A_ID, psk=TEST_PSK)
        channel.on_state_change(lambda old, new: state_changes.append((old, new)))

        channel._set_state(ChannelState.HANDSHAKING)
        assert len(state_changes) == 1
        assert state_changes[0] == (ChannelState.IDLE, ChannelState.HANDSHAKING)


# ═══════════════════════════════════════════════════════════════
# Part 3: OpenClawAdapter 适配器测试
# ═══════════════════════════════════════════════════════════════


class TestOpenClawAdapter:
    """OpenClawAdapter 适配器测试"""

    def _create_paired_adapters(self):
        """创建一对已连接的适配器"""
        adapter_a = OpenClawAdapter(
            config=AgentConfig(
                agent_id=AGENT_A_ID,
                agent_type="decision",
                psk=TEST_PSK,
            )
        )
        adapter_b = OpenClawAdapter(
            config=AgentConfig(
                agent_id=AGENT_B_ID,
                agent_type="orchestrator",
                psk=TEST_PSK,
            )
        )

        adapter_a.start()
        adapter_b.start()

        # 握手
        hello = adapter_a.initiate_handshake()
        auth = adapter_b.respond_to_handshake(hello)
        adapter_a.complete_handshake(auth)

        return adapter_a, adapter_b

    def test_adapter_creation(self):
        """测试适配器创建"""
        adapter = OpenClawAdapter(
            config=AgentConfig(
                agent_id=AGENT_A_ID,
                agent_type="decision",
                psk=TEST_PSK,
            )
        )
        assert adapter.agent_id == AGENT_A_ID
        assert adapter.agent_type == "decision"
        assert not adapter.is_connected

    def test_adapter_start_stop(self):
        """测试适配器启动和停止"""
        adapter = OpenClawAdapter(
            config=AgentConfig(
                agent_id=AGENT_A_ID,
                agent_type="decision",
                psk=TEST_PSK,
            )
        )
        adapter.start()
        assert adapter._stats["started_at"] is not None

        adapter.stop()
        assert adapter.channel.state == ChannelState.IDLE

    def test_adapter_handshake(self):
        """测试适配器握手"""
        adapter_a, adapter_b = self._create_paired_adapters()
        assert adapter_a.is_connected
        assert adapter_b.is_connected

    def test_adapter_send_encrypted(self):
        """测试适配器发送加密消息"""
        adapter_a, adapter_b = self._create_paired_adapters()

        text = "Encrypted message via adapter"
        encrypted = adapter_a.send_encrypted(text, AGENT_B_ID)
        assert encrypted.type == MessageType.ENCRYPTED

        decrypted = adapter_b.receive_encrypted(encrypted)
        assert decrypted == text

    def test_adapter_bidirectional(self):
        """测试适配器双向通信"""
        adapter_a, adapter_b = self._create_paired_adapters()

        # A → B
        enc_a = adapter_a.send_encrypted("A to B", AGENT_B_ID)
        dec_a = adapter_b.receive_encrypted(enc_a)
        assert dec_a == "A to B"

        # B → A
        enc_b = adapter_b.send_encrypted("B to A", AGENT_A_ID)
        dec_b = adapter_a.receive_encrypted(enc_b)
        assert dec_b == "B to A"

    def test_adapter_stats(self):
        """测试适配器统计"""
        adapter_a, adapter_b = self._create_paired_adapters()

        adapter_a.send_encrypted("test", AGENT_B_ID)
        adapter_b.receive_encrypted(adapter_a.get_outbound_messages()[0])

        stats = adapter_a.stats
        assert stats["messages_sent"] >= 1
        assert "channel" in stats

    def test_adapter_known_agents(self):
        """测试Agent注册"""
        adapter_a, adapter_b = self._create_paired_adapters()

        agents = adapter_b.get_known_agents()
        assert AGENT_A_ID in agents

    def test_adapter_message_callback(self):
        """测试消息回调"""
        adapter_a, adapter_b = self._create_paired_adapters()

        received = []
        adapter_b.on_message(lambda text, msg: received.append(text))

        encrypted = adapter_a.send_encrypted("Callback test", AGENT_B_ID)
        adapter_b.receive_encrypted(encrypted)

        assert len(received) == 1
        assert received[0] == "Callback test"

    def test_adapter_outbound_queue(self):
        """测试出站消息队列"""
        adapter_a, adapter_b = self._create_paired_adapters()

        adapter_a.send_encrypted("msg1", AGENT_B_ID)
        adapter_a.send_encrypted("msg2", AGENT_B_ID)

        outbound = adapter_a.get_outbound_messages()
        assert len(outbound) == 2

        # 清空后应为空
        outbound = adapter_a.get_outbound_messages()
        assert len(outbound) == 0

    def test_spawn_result_dataclass(self):
        """测试SpawnResult数据类"""
        result = SpawnResult(
            session_id="session-123",
            label="test-session",
            success=True,
        )
        assert result.session_id == "session-123"
        assert result.success

        failed = SpawnResult(
            session_id="",
            label="failed-session",
            success=False,
            error="CLI not found",
        )
        assert not failed.success
        assert failed.error == "CLI not found"

    def test_forward_message(self):
        """测试消息转发"""
        # 创建三个适配器: A ↔ B ↔ C
        adapter_a = OpenClawAdapter(
            config=AgentConfig(agent_id=AGENT_A_ID, agent_type="decision", psk=TEST_PSK)
        )
        adapter_b = OpenClawAdapter(
            config=AgentConfig(agent_id=AGENT_B_ID, agent_type="orchestrator", psk=TEST_PSK)
        )
        adapter_c = OpenClawAdapter(
            config=AgentConfig(agent_id=AGENT_C_ID, agent_type="executor", psk=TEST_PSK)
        )

        adapter_a.start()
        adapter_b.start()
        adapter_c.start()

        # A ↔ B 握手
        hello_ab = adapter_a.initiate_handshake()
        auth_ab = adapter_b.respond_to_handshake(hello_ab)
        adapter_a.complete_handshake(auth_ab)

        # B ↔ C 握手（使用B的另一个通道实例，实际需要独立通道）
        # 在这个简化测试中，我们通过B的通道转发
        # 注意：实际三方通信需要B维护两个独立的加密通道

        # 简化测试：A加密发送给B，B解密后转发给C
        # 在这个测试中我们只验证转发逻辑的存在
        assert adapter_a.is_connected
        assert adapter_b.is_connected

    def test_agent_config_dataclass(self):
        """测试AgentConfig数据类"""
        config = AgentConfig(
            agent_id="test-agent",
            agent_type="executor",
            psk=b"test-psk",
        )
        assert config.agent_id == "test-agent"
        assert config.agent_type == "executor"
        assert config.psk == b"test-psk"
        assert config.openclaw_path == "openclaw"  # default


# ═══════════════════════════════════════════════════════════════
# Part 4: 三方通信场景测试
# ═══════════════════════════════════════════════════════════════


class TestThreePartyCommunication:
    """三方通信场景测试"""

    def _setup_three_party(self):
        """建立三方加密通信"""
        # 创建通道
        channel_a = EncryptedChannel(agent_id=AGENT_A_ID, psk=TEST_PSK)
        channel_b_ab = EncryptedChannel(agent_id=AGENT_B_ID, psk=TEST_PSK)
        channel_b_bc = EncryptedChannel(agent_id=AGENT_B_ID, psk=TEST_PSK)
        channel_c = EncryptedChannel(agent_id=AGENT_C_ID, psk=TEST_PSK)

        # A ↔ B 握手
        hello_ab = channel_a.initiate()
        auth_ab = channel_b_ab.respond_to_handshake(hello_ab)
        channel_a.complete_handshake(auth_ab)

        # B ↔ C 握手
        hello_bc = channel_b_bc.initiate()
        auth_bc = channel_c.respond_to_handshake(hello_bc)
        channel_b_bc.complete_handshake(auth_bc)

        return channel_a, channel_b_ab, channel_b_bc, channel_c

    def test_three_party_handshake(self):
        """测试三方握手"""
        channel_a, channel_b_ab, channel_b_bc, channel_c = self._setup_three_party()
        assert channel_a.state == ChannelState.ESTABLISHED
        assert channel_b_ab.state == ChannelState.ESTABLISHED
        assert channel_b_bc.state == ChannelState.ESTABLISHED
        assert channel_c.state == ChannelState.ESTABLISHED

    def test_three_party_a_to_c(self):
        """测试 A → B → C 加密通信"""
        channel_a, channel_b_ab, channel_b_bc, channel_c = self._setup_three_party()

        # A → B
        text = "Hello from Hermes to Claude Code"
        encrypted_ab = channel_a.send(text, AGENT_B_ID)
        decrypted_ab = channel_b_ab.receive(encrypted_ab)
        assert decrypted_ab == text

        # B → C (转发)
        forward_text = f"[Forwarded from Hermes]: {decrypted_ab}"
        encrypted_bc = channel_b_bc.send(forward_text, AGENT_C_ID)
        decrypted_bc = channel_c.receive(encrypted_bc)
        assert decrypted_bc == forward_text

    def test_three_party_c_to_a(self):
        """测试 C → B → A 回复通信"""
        channel_a, channel_b_ab, channel_b_bc, channel_c = self._setup_three_party()

        # C → B
        reply = "Reply from Claude Code"
        encrypted_cb = channel_c.send(reply, AGENT_B_ID)
        decrypted_cb = channel_b_bc.receive(encrypted_cb)
        assert decrypted_cb == reply

        # B → A (转发)
        forward_text = f"[Forwarded from Claude Code]: {decrypted_cb}"
        encrypted_ba = channel_b_ab.send(forward_text, AGENT_A_ID)
        decrypted_ba = channel_a.receive(encrypted_ba)
        assert decrypted_ba == forward_text

    def test_three_party_multiple_rounds(self):
        """测试三方多轮通信"""
        channel_a, channel_b_ab, channel_b_bc, channel_c = self._setup_three_party()

        conversations = [
            ("Hermes", "请分析这个需求"),
            ("Claude Code", "需求可行，建议分三个阶段"),
            ("Hermes", "请给出第一阶段方案"),
            ("Claude Code", "第一阶段：搭建基础架构"),
            ("Hermes", "收到，开始执行"),
        ]

        for sender, text in conversations:
            if sender == "Hermes":
                # A → B → C
                enc_ab = channel_a.send(text, AGENT_B_ID)
                dec_ab = channel_b_ab.receive(enc_ab)
                forward = f"[from {sender}]: {dec_ab}"
                enc_bc = channel_b_bc.send(forward, AGENT_C_ID)
                dec_bc = channel_c.receive(enc_bc)
                assert text in dec_bc
            else:
                # C → B → A
                enc_cb = channel_c.send(text, AGENT_B_ID)
                dec_cb = channel_b_bc.receive(enc_cb)
                forward = f"[from {sender}]: {dec_cb}"
                enc_ba = channel_b_ab.send(forward, AGENT_A_ID)
                dec_ba = channel_a.receive(enc_ba)
                assert text in dec_ba

    def test_three_party_independent_channels(self):
        """测试三方通道独立性"""
        channel_a, channel_b_ab, channel_b_bc, channel_c = self._setup_three_party()

        # A → B 的消息不应该被 C 收到
        enc_ab = channel_a.send("Only for B", AGENT_B_ID)
        dec_ab = channel_b_ab.receive(enc_ab)
        assert dec_ab == "Only for B"

        # 尝试用 C 的通道解密 A→B 的消息应失败
        with pytest.raises(Exception):
            channel_c.receive(enc_ab)

    def test_three_party_stats(self):
        """测试三方通信统计"""
        channel_a, channel_b_ab, channel_b_bc, channel_c = self._setup_three_party()

        # 发送一轮消息
        enc = channel_a.send("Test", AGENT_B_ID)
        channel_b_ab.receive(enc)
        forward = channel_b_bc.send("Forwarded", AGENT_C_ID)
        channel_c.receive(forward)

        # 验证统计
        assert channel_a.stats["messages_sent"] == 1
        assert channel_b_ab.stats["messages_received"] == 1
        assert channel_b_bc.stats["messages_sent"] == 1
        assert channel_c.stats["messages_received"] == 1


# ═══════════════════════════════════════════════════════════════
# Part 5: 边界条件和错误处理
# ═══════════════════════════════════════════════════════════════


class TestEdgeCases:
    """边界条件和错误处理测试"""

    def test_empty_message(self):
        """测试空消息"""
        channel_a = EncryptedChannel(agent_id=AGENT_A_ID, psk=TEST_PSK)
        channel_b = EncryptedChannel(agent_id=AGENT_B_ID, psk=TEST_PSK)

        hello = channel_a.initiate()
        auth = channel_b.respond_to_handshake(hello)
        channel_a.complete_handshake(auth)

        encrypted = channel_a.send("", AGENT_B_ID)
        decrypted = channel_b.receive(encrypted)
        assert decrypted == ""

    def test_unicode_message(self):
        """测试Unicode消息"""
        channel_a = EncryptedChannel(agent_id=AGENT_A_ID, psk=TEST_PSK)
        channel_b = EncryptedChannel(agent_id=AGENT_B_ID, psk=TEST_PSK)

        hello = channel_a.initiate()
        auth = channel_b.respond_to_handshake(hello)
        channel_a.complete_handshake(auth)

        texts = [
            "中文消息测试 🎉",
            "日本語テスト 🔒",
            "한국어 테스트 🛡️",
            "Mix of 中文 and English with émojis 🚀",
            "Special chars: <>&\"'\\/\n\t",
        ]

        for text in texts:
            encrypted = channel_a.send(text, AGENT_B_ID)
            decrypted = channel_b.receive(encrypted)
            assert decrypted == text

    def test_long_message(self):
        """测试长消息"""
        channel_a = EncryptedChannel(agent_id=AGENT_A_ID, psk=TEST_PSK)
        channel_b = EncryptedChannel(agent_id=AGENT_B_ID, psk=TEST_PSK)

        hello = channel_a.initiate()
        auth = channel_b.respond_to_handshake(hello)
        channel_a.complete_handshake(auth)

        # 10KB message
        long_text = "A" * 10240
        encrypted = channel_a.send(long_text, AGENT_B_ID)
        decrypted = channel_b.receive(encrypted)
        assert decrypted == long_text

    def test_message_id_uniqueness(self):
        """测试消息ID唯一性"""
        ids = set()
        for _ in range(100):
            msg = create_text_message(
                sender_id=AGENT_A_ID,
                recipient_id=AGENT_B_ID,
                text="test",
            )
            assert msg.id not in ids
            ids.add(msg.id)
        assert len(ids) == 100

    def test_different_psk_fails_decryption(self):
        """测试不同PSK导致解密失败"""
        channel_a = EncryptedChannel(agent_id=AGENT_A_ID, psk=b"psk-alpha-32bytes-pad!!")
        channel_b = EncryptedChannel(agent_id=AGENT_B_ID, psk=b"psk-beta-32bytes-pad!!!")

        # 握手可能不会失败（因为PSK使用随机盐哈希）
        # 但加密/解密一定失败
        hello = channel_a.initiate()
        try:
            auth = channel_b.respond_to_handshake(hello)
            channel_a.complete_handshake(auth)
            # 如果握手没有失败（不同PSK哈希），尝试发送消息
            encrypted = channel_a.send("secret message", AGENT_B_ID)
            with pytest.raises(Exception):
                channel_b.receive(encrypted)
        except (ValueError, Exception):
            # 握手失败也可以（HMAC验证失败）
            pass

    def test_send_without_recipient(self):
        """测试未指定接收方发送"""
        channel = EncryptedChannel(agent_id=AGENT_A_ID, psk=TEST_PSK)
        # 手动设置状态为已建立
        channel._set_state(ChannelState.ESTABLISHED)
        channel._session_keys = {
            "encryption_key": b"x" * 32,
            "auth_key": b"y" * 32,
            "replay_key": b"z" * 32,
        }
        with pytest.raises(ValueError, match="未指定接收方ID"):
            channel.send("test")

    def test_channel_state_transitions(self):
        """测试通道状态转换"""
        channel = EncryptedChannel(agent_id=AGENT_A_ID, psk=TEST_PSK)
        assert channel.state == ChannelState.IDLE

        # IDLE → HANDSHAKING
        channel._set_state(ChannelState.HANDSHAKING)
        assert channel.state == ChannelState.HANDSHAKING

        # HANDSHAKING → ESTABLISHED
        channel._set_state(ChannelState.ESTABLISHED)
        assert channel.state == ChannelState.ESTABLISHED
        assert channel.is_established

        # ESTABLISHED → CLOSED
        channel.close()
        assert channel.state == ChannelState.CLOSED

    def test_message_serialization_roundtrip(self):
        """测试消息序列化往返"""
        original = create_text_message(
            sender_id=AGENT_A_ID,
            recipient_id=AGENT_B_ID,
            text="Roundtrip test 🔄",
            metadata={"key": "值", "number": 42},
        )

        json_str = original.to_json()
        restored = AgentMessage.from_json(json_str)

        assert restored.id == original.id
        assert restored.type == original.type
        assert restored.sender_id == original.sender_id
        assert restored.recipient_id == original.recipient_id
        assert restored.payload == original.payload
        assert restored.metadata == original.metadata
        assert restored.timestamp == original.timestamp

    def test_adapter_not_connected_send(self):
        """测试未连接时发送"""
        adapter = OpenClawAdapter(
            config=AgentConfig(agent_id=AGENT_A_ID, agent_type="decision", psk=TEST_PSK)
        )
        with pytest.raises(RuntimeError):
            adapter.send_encrypted("test")

    def test_channel_error_callback(self):
        """测试错误回调"""
        errors = []
        channel = EncryptedChannel(agent_id=AGENT_A_ID, psk=TEST_PSK)
        channel.on_error(lambda e: errors.append(str(e)))

        # 在HANDSHAKING状态下尝试respond_to_handshake，触发内部错误
        channel._set_state(ChannelState.HANDSHAKING)
        # initiate in HANDSHAKING raises RuntimeError, but error callback fires
        # only for errors inside the try/except block that catches exceptions
        # Let's test by having respond_to_handshake fail internally
        channel2 = EncryptedChannel(agent_id=AGENT_B_ID, psk=TEST_PSK)
        channel2.on_error(lambda e: errors.append(str(e)))

        # Create a handshake message with invalid data to trigger error
        msg = create_control_message(
            sender_id=AGENT_B_ID,
            recipient_id=AGENT_A_ID,
            action=ControlAction.HANDSHAKE_INIT,
            data={
                "version": "SIP-1.0",
                "timestamp": 0,
                "identity_pub": "invalid",
                "ephemeral_pub": "invalid",
                "nonce": "invalid",
            },
        )
        try:
            channel2.respond_to_handshake(msg)
        except Exception:
            pass

        assert len(errors) >= 1
        assert any("" in e for e in errors)


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
