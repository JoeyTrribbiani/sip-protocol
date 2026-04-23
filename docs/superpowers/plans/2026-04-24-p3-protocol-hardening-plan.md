# P3 协议修复 实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 修复 protocol 层实现与 e2ee-protocol.md 设计文档的 10 项差距，优先修 bug 再补功能。

**Architecture:** 先修 3 个低风险 bug（G8/G9/G10），再做安全加固（G5/G6），最后补全功能（G1/G2/G3/G4/G7）。每个任务保持对外接口不变，只改内部实现。

**Tech Stack:** Python 3.11+, stdlib, ctypes（仅 zeroize）, collections.OrderedDict

**设计文档:** `docs/superpowers/specs/2026-04-24-protocol-hardening-design.md`

**关键约束:**
- 纯同步 API，无 async/await
- 纯 stdlib dataclasses + enum，无 pydantic
- Pylint max-args=7
- 注释/文档中文，标识符英文
- 对外接口不变，只改内部实现
- 现有 553 测试必须零回归

---

## 文件结构

```
python/src/sip_protocol/
├── protocol/
│   ├── group.py          # 修改: 重写 Double Ratchet（G1/G2/G3）
│   ├── handshake.py      # 修改: 删除重复三重 DH（G9）
│   ├── rekey.py          # 修改: 添加 _secure_wipe（G6）
│   ├── resume.py         # 修改: 签名字段 session_id→sender_id（G8）
│   └── version.py       # 修改: 添加协商消息构造/解析（G7）
├── transport/
│   └── encrypted_channel.py  # 修改: Rekey 闭环 + 接收端触发（G4/G5）
├── managers/
│   └── nonce.py          # 修改: set→OrderedDict（G10）
└── tests/
    ├── test_group_ratchet.py      # 新增: Double Ratchet 正确性测试
    └── test_rekey_e2e.py         # 新增: Rekey 闭环测试
```

---

### Task 1: Bug 修复三连（G9/G8/G10）

**Files:**
- Modify: `src/sip_protocol/protocol/handshake.py:238-244`
- Modify: `src/sip_protocol/protocol/resume.py:98`
- Modify: `src/sip_protocol/managers/nonce.py:17,45-46`

- [ ] **Step 1: 修复 handshake.py 重复三重 DH**

删除 `complete_handshake` 中第 238-244 行的重复三重 DH 计算（与第 231-236 行完全相同）。

删除以下代码：

```python
        # 三重DH密钥交换（发起方视角）
        # shared_1: identity_local × remote_ephemeral
        shared_1 = dh_exchange(agent_state["identity_private_key"], remote_ephemeral_pub)
        # shared_2: ephemeral_local × remote_identity
        shared_2 = dh_exchange(agent_state["ephemeral_private_key"], remote_identity_pub)
        # shared_3: ephemeral_local × remote_ephemeral
        shared_3 = dh_exchange(agent_state["ephemeral_private_key"], remote_ephemeral_pub)
```

- [ ] **Step 2: 修复 resume.py 签名字段**

将第 98 行：

```python
        data = f"{session_state.session_id}:{next_message_counter}".encode()
```

改为：

```python
        data = f"{session_state.sender_id}:{next_message_counter}".encode()
```

同时检查 `verify_session_resume` 方法中的签名验证是否也使用 `sender_id`。如果使用 `session_id`，也一并修正为 `sender_id`。

- [ ] **Step 3: 修复 nonce.py FIFO 淘汰**

在第 7 行添加 import：

```python
from collections import OrderedDict
```

将第 17 行：

```python
        self.used_nonces = set()
```

改为：

```python
        self.used_nonces: OrderedDict[bytes, None] = OrderedDict()
```

修改 `check_and_add` 方法（第 32-47 行）：

```python
    def check_and_add(self, nonce: bytes) -> bool:
        """检查并添加Nonce"""
        if nonce in self.used_nonces:
            return False
        self.used_nonces[nonce] = None
        if len(self.used_nonces) > 1000:
            self.used_nonces.popitem(last=False)
        return True
```

修改 `generate_nonce` 方法（第 19-30 行）中的 `in` 检查也使用 `used_nonces`。

修改 `validate_nonce` 方法（第 49-59 行）保持不变。

- [ ] **Step 4: 运行现有测试确认零回归**

```bash
cd python && source .venv/bin/activate
pytest tests/ -q
```

预期：553 passed, 36 skipped

- [ ] **Step 5: 提交**

```bash
git add src/sip_protocol/protocol/handshake.py src/sip_protocol/protocol/resume.py src/sip_protocol/managers/nonce.py
git commit -m "fix: 修复handshake重复计算、resume签名不一致、nonce FIFO淘汰"
```

---

### Task 2: Rekey 安全加固（G5/G6）

**Files:**
- Modify: `src/sip_protocol/transport/encrypted_channel.py:457-484`
- Modify: `src/sip_protocol/protocol/rekey.py`（新增 `_secure_wipe`）

- [ ] **Step 1: 添加 `_secure_wipe` 函数到 rekey.py**

在 `rekey.py` 顶部 import 区域后添加：

```python
def _secure_wipe(data: bytearray) -> None:
    """安全擦除内存中的密钥数据（尽力而为）

    Python 的 del 和变量覆盖不保证内存清零。
    使用 ctypes.memset 提供尽力擦除。

    Args:
        data: 需要擦除的 bytearray（就地修改）
    """
    import ctypes
    ctypes.memset(ctypes.addressof(data), 0, len(data))
```

- [ ] **Step 2: 在 apply_new_keys 中调用 _secure_wipe**

找到 `apply_new_keys` 方法（在 `process_rekey_response` 之后），在切换到新密钥之前，擦除旧密钥。

在 `apply_new_keys` 方法中，在更新 `self.session_state` 之前添加旧密钥擦除：

```python
    def apply_new_keys(self, new_keys: dict) -> None:
        """应用新密钥"""
        # 安全擦除旧密钥
        for key_name in ("encryption_key", "auth_key", "replay_key"):
            old_val = self.session_state.get(key_name)
            if old_val and isinstance(old_val, (bytes, bytearray)):
                buf = bytearray(old_val) if isinstance(old_val, bytes) else bytearray(old_val)
                _secure_wipe(buf)

        self.session_state.update(new_keys)
```

- [ ] **Step 3: 修改 encrypted_channel.py 接收端 rekey 触发**

在 `_check_rekey_needed` 方法中（行 457-470），添加接收计数器检查：

```python
    def _check_rekey_needed(self) -> None:
        """检查是否需要密钥轮换"""
        if not self._stats["established_at"]:
            return

        # 按消息数量检查（发送端）
        if self._send_counter >= self.config.rekey_after_messages:
            self._initiate_rekey()
            return

        # 按接收消息数量检查（接收端）
        if self._receive_counter >= self.config.rekey_after_messages:
            self._initiate_rekey()
            return

        # 按时间检查
        elapsed = time.time() - self._stats["established_at"]
        if elapsed >= self.config.rekey_after_seconds:
            self._initiate_rekey()
```

确保 `EncryptedChannel` 类中有 `_receive_counter` 属性（如果没有，在 `send` 或 `receive` 时递增）。检查现有代码中 `_receive_counter` 是否存在，不存在则添加到接收逻辑中。

- [ ] **Step 4: 运行现有测试**

```bash
pytest tests/ -q
```

预期：553 passed

- [ ] **Step 5: 提交**

```bash
git add src/sip_protocol/protocol/rekey.py src/sip_protocol/transport/encrypted_channel.py
git commit -m "fix: Rekey旧密钥安全擦除+接收端触发检查"
```

---

### Task 3: 群组 Double Ratchet 重写（G1/G2/G3）

**Files:**
- Modify: `src/sip_protocol/protocol/group.py`（重写 `send_group_message`, `receive_group_message`, `add_member`, `remove_member`）
- Create: `tests/test_group_ratchet.py`

- [ ] **Step 1: 添加 ChainState 数据类**

在 `group.py` 的 import 区域后，`GroupManager` 类之前添加：

```python
@dataclass
class ChainState:
    """单条 Ratchet 链状态"""

    chain_key: bytes
    message_number: int = 0
    skip_keys: dict[int, bytes] = field(default_factory=dict)
```

- [ ] **Step 2: 重写 send_group_message**

将 `send_group_message` 方法替换为：

```python
    def send_group_message(
        self, plaintext: str, sending_chain: dict, sender_id: str
    ) -> tuple[str, dict]:
        """发送群组消息（Double Ratchet）

        每条消息推进 chain_key，确保前向保密。
        """
        chain_key = sending_chain["chain_key"]
        msg_num = sending_chain["message_number"]

        # 1. 从 chain_key 派生 message_key
        message_key = hkdf(chain_key, b"", b"message-key", MESSAGE_KEY_LENGTH)

        # 2. 推进 chain_key
        next_chain_key = hkdf(chain_key, b"", b"chain-key", CHAIN_KEY_LENGTH)

        # 3. 加密消息
        iv = os.urandom(AES_GCM_NONCE_LENGTH)
        ciphertext, auth_tag = encrypt_aes_gcm(message_key, plaintext.encode(), iv)

        # 4. 发送方签名
        sender_signature = hmac.new(message_key, ciphertext, hashlib.sha256).digest()

        # 5. 更新发送链状态
        updated_chain = {
            "chain_key": next_chain_key,
            "message_number": msg_num + 1,
        }

        # 6. 构建群组消息
        message = {
            "version": GROUP_PROTOCOL_VERSION,
            "type": "group_message",
            "timestamp": int(time.time() * 1000),
            "sender_id": sender_id,
            "group_id": self.group_id,
            "message_number": msg_num,
            "iv": base64.b64encode(iv).decode(),
            "ciphertext": base64.b64encode(ciphertext).decode(),
            "auth_tag": base64.b64encode(auth_tag).decode(),
            "sender_signature": base64.b64encode(sender_signature).decode(),
        }

        return json.dumps(message), updated_chain
```

- [ ] **Step 3: 重写 receive_group_message（含 Skip Ratchet）**

将 `receive_group_message` 方法替换为：

```python
    def receive_group_message(
        self, message: str, receiving_chain: dict, sender_id: str
    ) -> tuple[str, dict]:
        """接收群组消息（Double Ratchet + Skip Ratchet）"""
        msg = json.loads(message)
        message_number = msg["message_number"]
        chain_key = receiving_chain["chain_key"]
        expected_num = receiving_chain["message_number"]

        # Skip Ratchet：处理乱序消息
        skip_keys = receiving_chain.get("skip_keys", {})
        for missing_num in range(expected_num, message_number):
            if missing_num in skip_keys:
                # 使用预生成的 skip_key
                chain_key = hkdf(chain_key, b"", b"skip-key", CHAIN_KEY_LENGTH)
                del skip_keys[missing_num]
            else:
                # 没有预生成，用 message-key 推进后计算 skip_key
                message_key = hkdf(chain_key, b"", b"message-key", MESSAGE_KEY_LENGTH)
                skip_keys[missing_num] = hkdf(chain_key, b"", b"skip-key", CHAIN_KEY_LENGTH)
                chain_key = hkdf(chain_key, b"", b"chain-key", CHAIN_KEY_LENGTH)

        # 派生当前消息的 message_key
        message_key = hkdf(chain_key, b"", b"message-key", MESSAGE_KEY_LENGTH)

        # 推进 chain_key
        next_chain_key = hkdf(chain_key, b"", b"chain-key", CHAIN_KEY_LENGTH)

        # 解密消息
        iv = base64.b64decode(msg["iv"])
        ciphertext = base64.b64decode(msg["ciphertext"])
        auth_tag = base64.b64decode(msg["auth_tag"])
        plaintext = decrypt_aes_gcm(message_key, ciphertext, iv, auth_tag)

        # 验证发送方签名
        sender_signature = base64.b64decode(msg["sender_signature"])
        expected_signature = hmac.new(message_key, ciphertext, hashlib.sha256).digest()

        if not hmac.compare_digest(sender_signature, expected_signature):
            raise ValueError("Invalid sender signature")

        # 更新接收链状态
        updated_chain = {
            "chain_key": next_chain_key,
            "message_number": message_number + 1,
            "skip_keys": skip_keys,
        }

        return plaintext.decode(), updated_chain
```

- [ ] **Step 4: 修改 add_member 使用 chain_key 派生**

修改 `add_member` 方法，使用 HKDF 派生初始 chain_key（而非 root_key 直接派生）：

```python
    def add_member(
        self,
        member_id: str,
        public_key: Optional[bytes] = None,
        role: str = "member",
    ) -> None:
        if member_id in self.members:
            raise ValueError(f"Member {member_id} already exists")

        # 从 root_key 为新成员派生初始 chain_key
        initial_chain_key = hkdf(
            self.root_key, f"{member_id}:init".encode(), b"init-chain", CHAIN_KEY_LENGTH
        )

        self.members[member_id] = {
            "member_id": member_id,
            "role": role,
            "joined_at": int(time.time() * 1000),
            "public_key": base64.b64encode(public_key).decode() if public_key else "",
            "sending_chain": {
                "chain_key": initial_chain_key,
                "message_number": 0,
            },
            "receiving_chain": {
                "chain_key": initial_chain_key,
                "message_number": 0,
                "skip_keys": {},
            },
        }
```

- [ ] **Step 5: 修改 remove_member 中重新派生链密钥**

在 `remove_member` 方法中，移除成员后重新派生链密钥时使用 HKDF 派生 chain_key（而非 root_key 直接派生）：

```python
        # 为剩余成员重新派生链密钥
        for mid, member_data in self.members.items():
            if mid == member_id:
                continue
            chain_key = hkdf(
                self.root_key, f"{mid}:reinit".encode(), b"reinit-chain", CHAIN_KEY_LENGTH
            )
            member_data["sending_chain"]["chain_key"] = chain_key
            member_data["receiving_chain"]["chain_key"] = chain_key
```

- [ ] **Step 6: 修改 initialize_group_chains 保持接口一致**

修改 `initialize_group_chains` 以返回新格式的 chain dict：

```python
    def initialize_group_chains(self, members: list, root_key: bytes) -> dict:
        chains = {}
        group_base = hkdf(root_key, b"group-base", b"sip-group", 32)

        for member in members:
            chain_key = hkdf(group_base, f"{member}:init".encode(), b"init-chain", CHAIN_KEY_LENGTH)
            chains[member] = {
                "sending_chain": {"chain_key": chain_key, "message_number": 0},
                "receiving_chain": {
                    "chain_key": chain_key,
                    "message_number": 0,
                    "skip_keys": {},
                },
            }
        return chains
```

- [ ] **Step 7: 写 Double Ratchet 测试**

创建 `tests/test_group_ratchet.py`：

```python
"""群组 Double Ratchet 正确性测试"""

import base64
import json

import pytest

from sip_protocol.crypto.hkdf import hkdf
from sip_protocol.protocol.group import GROUP_PROTOCOL_VERSION, MESSAGE_KEY_LENGTH, CHAIN_KEY_LENGTH


def _make_group_manager(group_id: str = "test-group", root_key: bytes = b"x" * 32) -> "GroupManager":
    from sip_protocol.protocol.group import GroupManager
    return GroupManager(group_id=group_id, root_key=root_key)


class TestChainKeyAdvancement:
    def test_chain_key_advances_on_send(self):
        """发送消息后 chain_key 必须改变"""
        mgr = _make_group_manager()
        chain = {"chain_key": b"a" * CHAIN_KEY_LENGTH, "message_number": 0}

        _, updated = mgr.send_group_message("hello", chain, "alice")

        assert updated["chain_key"] != chain["chain_key"]
        assert updated["message_number"] == 1

    def test_chain_key_advances_on_receive(self):
        """接收消息后 chain_key 必须改变"""
        mgr = _make_group_manager()
        chain = {"chain_key": b"a" * CHAIN_KEY_LENGTH, "message_number": 0}

        msg, _ = mgr.send_group_message("hello", chain, "alice")
        _, updated = mgr.receive_group_message(msg, {"chain_key": chain["chain_key"], "message_number": 0, "skip_keys": {}}, "alice")

        assert updated["chain_key"] != chain["chain_key"]
        assert updated["message_number"] == 1

    def test_different_senders_different_keys(self):
        """不同发送者派生不同的 message_key"""
        mgr = _make_group_manager()
        chain_a = {"chain_key": b"a" * CHAIN_KEY_LENGTH, "message_number": 0}
        chain_b = {"chain_key": b"b" * CHAIN_KEY_LENGTH, "message_number": 0}

        key_a = hkdf(chain_a["chain_key"], b"", b"message-key", MESSAGE_KEY_LENGTH)
        key_b = hkdf(chain_b["chain_key"], b"", b"message-key", MESSAGE_KEY_LENGTH)
        assert key_a != key_b  # 不同 chain_key → 不同 message_key


class TestSkipRatchet:
    def test_skip_ratchet_handles_gap(self):
        """Skip Ratchet 正确处理消息间隔"""
        mgr = _make_group_manager()
        chain = {"chain_key": b"a" * CHAIN_KEY_LENGTH, "message_number": 0, "skip_keys": {}}

        # 发送 msg 0, 1, 2
        msg0, _ = mgr.send_group_message("msg0", chain, "alice")
        chain = {"chain_key": msg0 and _extract_chain_key(msg0, mgr) or chain["chain_key"], "message_number": 1, "skip_keys": {}}
        _, _ = mgr.send_group_message("msg1", chain, "alice")
        chain["message_number"] = 2

        # 发送 msg 2（模拟丢失，只拿到 msg3）
        msg3, _ = mgr.send_group_message("msg3", {"chain_key": chain["chain_key"], "message_number": 2}, "alice")

        # 接收端从 msg 1 开始，需要 skip msg2
        # 构造 msg1 用于 skip
        msg1_key = hkdf(
            chain["chain_key"], b"", b"message-key", MESSAGE_KEY_LENGTH
        )
        iv1 = b"\x00" * 12  # 需要 12 字节 AES-GCM nonce
        fake_ct = b"encrypted"  # 不重要，测试 skip 逻辑
        msg1_json = json.dumps({
            "version": GROUP_PROTOCOL_VERSION, "type": "group_message",
            "timestamp": 0, "sender_id": "alice", "group_id": "test-group",
            "message_number": 1, "iv": base64.b64encode(iv1).decode(),
            "ciphertext": base64.b64encode(fake_ct).decode(),
            "auth_tag": base64.b64encode(b"tag").decode(),
            "sender_signature": base64.b64encode(b"sig").decode(),
        })

        # 接收 msg1
        _, chain_after_1 = mgr.receive_group_message(msg1_json, chain, "alice")
        assert chain_after_1["message_number"] == 1

        # 接收 msg3（应触发 Skip Ratchet）
        _, chain_after_3 = mgr.receive_group_message(msg3, chain_after_1, "alice")
        assert chain_after_3["message_number"] == 3

    def test_skip_ratchet_preserves_decryption(self):
        """Skip Ratchet 后仍能正确解密"""
        mgr = _make_group_manager()

        # 手动构造测试：发送 msg0，跳过 msg1，接收 msg2
        chain = {"chain_key": b"a" * CHAIN_KEY_LENGTH, "message_number": 0, "skip_keys": {}}

        # 发送 msg0
        msg0, _ = mgr.send_group_message("secret", chain, "alice")
        chain = {"chain_key": _extract_chain_key(msg0, mgr), "message_number": 1, "skip_keys": {}}

        # 发送 msg2
        msg2, _ = mgr.send_group_message("data", {"chain_key": chain["chain_key"], "message_number": 1}, "alice")

        # 接收端：直接接收 msg2（跳过 msg1）
        _, chain_after = mgr.receive_group_message(msg2, chain, "alice")
        assert chain_after["message_number"] == 2
```

注意：`_extract_chain_key` 是测试辅助函数，从发送后的 chain 状态反推 chain_key。实现时可直接在测试中手动管理 chain_key 来避免解析加密消息的复杂性。建议简化测试——直接用 `hkdf` 手动跟踪 chain_key 推进过程，而非解析完整加密消息。

- [ ] **Step 8: 运行全量测试**

```bash
pytest tests/ -q
```

预期：全部通过

- [ ] **Step 9: 提交**

```bash
git add src/sip_protocol/protocol/group.py tests/test_group_ratchet.py
git commit -m "feat: 重写群组Double Ratchet，chain_key推进+Skip Ratchet"
```

---

### Task 4: 版本协商协议补全（G7）

**Files:**
- Modify: `src/sip_protocol/protocol/version.py`
- Create: `tests/test_version_negotiation.py`

- [ ] **Step 1: 添加消息构造/解析函数**

在 `version.py` 中添加：

```python
def create_version_offer(supported_versions: List[str], sender_id: str) -> dict:
    """创建版本协商提议消息"""
    return {
        "version": DEFAULT_VERSION,
        "type": "version_offer",
        "timestamp": int(time.time() * 1000),
        "sender_id": sender_id,
        "supported_versions": supported_versions,
    }


def parse_version_response(data: dict) -> Optional[str]:
    """解析版本协商响应，返回协商结果版本

    Returns:
        协商后的版本，无共同版本返回 None
    """
    if data.get("type") != "version_response":
        return None
    selected = data.get("selected_version", "")
    supported = data.get("supported_versions", [])
    return negotiate_version(supported, [selected])


def create_version_not_supported(supported: List[str], remote_supported: List[str]) -> dict:
    """创建版本不支持的错误消息"""
    return {
        "version": DEFAULT_VERSION,
        "type": "error",
        "error_code": "VERSION_NOT_SUPPORTED",
        "error_message": f"No common version. Supported: {supported}",
        "timestamp": int(time.time() * 1000),
        "remote_versions": remote_supported,
    }


def create_version_response(selected_version: str, supported_versions: List[str], sender_id: str) -> dict:
    """创建版本协商响应消息"""
    return {
        "version": selected_version,
        "type": "version_response",
        "timestamp": int(time.time() * 1000),
        "sender_id": sender_id,
        "selected_version": selected_version,
        "supported_versions": supported_versions,
    }
```

需要在文件顶部添加 `import time`。

- [ ] **Step 2: 写版本协商测试**

创建 `tests/test_version_negotiation.py`：

```python
"""版本协商协议测试"""

import pytest

from sip_protocol.protocol.version import (
    PROTOCOL_VERSIONS,
    create_version_not_supported,
    create_version_offer,
    create_version_response,
    parse_version_response,
    validate_version,
)


class TestVersionNegotiation:
    def test_create_version_offer(self):
        offer = create_version_offer(PROTOCOL_VERSIONS, "agent-a")
        assert offer["type"] == "version_offer"
        assert offer["supported_versions"] == PROTOCOL_VERSIONS
        assert offer["sender_id"] == "agent-a"

    def test_create_version_response(self):
        resp = create_version_response("SIP-1.2", PROTOCOL_VERSIONS, "agent-b")
        assert resp["type"] == "version_response"
        assert resp["selected_version"] == "SIP-1.2"

    def test_parse_version_response_success(self):
        resp = create_version_response("SIP-1.1", PROTOCOL_VERSIONS, "agent-b")
        result = parse_version_response(resp)
        assert result == "SIP-1.1"

    def test_parse_version_response_wrong_type(self):
        resp = create_version_response("SIP-1.1", PROTOCOL_VERSIONS, "agent-b")
        resp["type"] = "other"
        assert parse_version_response(resp) is None

    def test_version_not_supported_message(self):
        msg = create_version_not_supported(["SIP-1.0"], ["SIP-2.0"])
        assert msg["error_code"] == "VERSION_NOT_SUPPORTED"

    def test_full_negotiation_flow(self):
        """模拟完整的 4 步版本协商"""
        # Agent A 发起
        offer = create_version_offer(["SIP-1.0", "SIP-1.2"], "agent-a")

        # Agent B 选择最高共同版本
        selected = negotiate_version(["SIP-1.1", "SIP-1.3"], offer["supported_versions"])
        assert selected == "SIP-1.2"

        # Agent B 发送响应
        response = create_version_response(selected, ["SIP-1.1", "SIP-1.3"], "agent-b")

        # Agent A 解析响应
        result = parse_version_response(response)
        assert result == selected

    def test_no_common_version(self):
        offer = create_version_offer(["SIP-1.0"], "agent-a")
        response = create_version_response("SIP-1.0", ["SIP-2.0"], "agent-b")
        result = parse_version_response(response)
        assert result is None
```

- [ ] **Step 3: 运行测试**

```bash
pytest tests/test_version_negotiation.py -v
```

预期：全部 PASS

- [ ] **Step 4: 运行全量测试**

```bash
pytest tests/ -q
```

预期：553+ passed

- [ ] **Step 5: 提交**

```bash
git add src/sip_protocol/protocol/version.py tests/test_version_negotiation.py
git commit -m "feat: 添加版本协商4步协议（消息构造/解析）"
```

---

### Task 5: Rekey 闭环（G4）

**Files:**
- Modify: `src/sip_protocol/transport/encrypted_channel.py`
- Create: `tests/test_rekey_e2e.py`

- [ ] **Step 1: 在 send 方法中处理 rekey_response**

在 `EncryptedChannel.send` 方法中（或消息发送路径上），检查是否有待处理的 rekey response。具体实现取决于 `_handshake_state` 的当前结构。

找到发送消息的位置，在构建 AgentMessage 之前，检查 `self._handshake_state` 中是否有 `rekey_manager`。如果有待处理的 rekey_response 消息，先处理它。

- [ ] **Step 2: 在 receive 方法中处理 rekey_request**

在 `EncryptedChannel.receive` 方法中（或消息接收路径上），检查是否收到 `rekey_request` 类型的消息。如果是，用 `RekeyManager.process_rekey_request()` 处理，然后发送 `rekey_response`。

需要找到加密消息的接收逻辑，添加对 rekey 类型消息的处理分支。

- [ ] **Step 3: 写 Rekey 端到端测试**

创建 `tests/test_rekey_e2e.py`：

```python
"""Rekey 端到端测试"""

import pytest

from sip_protocol.protocol.rekey import RekeyManager


class TestRekeyE2E:
    def test_full_rekey_flow(self):
        """完整的 rekey 握议 → 响应 → 密钥切换流程"""
        session_keys = {
            "encryption_key": b"old_enc" * 16,
            "auth_key": b"old_auth" * 16,
            "replay_key": b"old_replay" * 16,
        }

        # 发起方创建 rekey request
        manager = RekeyManager(session_keys, is_initiator=True)
        request = manager.create_rekey_request()

        assert request["type"] == "rekey"
        assert request["step"] == "request"
        assert "request" in request
        assert "signature" in request

        # 验证签名
        is_valid = manager.validate_rekey_request(request)
        assert is_valid is True

        # 接收方创建 rekey response
        responder = RekeyManager(session_keys, is_initiator=False)
        response = responder.process_rekey_request(request)

        assert response["type"] == "rekey"
        assert response["step"] == "response"

        # 发起方处理响应
        new_keys = manager.process_rekey_response(response)
        assert new_keys["encryption_key"] != b"old_enc" * 16
        assert new_keys["auth_key"] != b"old_auth" * 16

        # 应用新密钥
        manager.apply_new_keys(new_keys)
        assert manager.session_state["encryption_key"] == new_keys["encryption_key"]

    def test_rekey_sequence_check(self):
        """rekey 序列号单调递增"""
        manager = RekeyManager(
            {"encryption_key": b"x" * 32, "auth_key": b"y" * 32, "replay_key": b"z" * 32},
            is_initiator=True,
            rekey_sequence=0,
        )
        request = manager.create_rekey_request()
        assert request["sequence"] == 0

    def test_tampered_rekey_request(self):
        """篡改的 rekey request 应被拒绝"""
        manager = RekeyManager(
            {"encryption_key": b"x" * 32, "auth_key": b"y" * 32, "replay_key": b"z" * 32},
            is_initiator=False,
        )
        request = manager.create_rekey_request()
        request["request"]["nonce"] = "TAMPERED"

        is_valid = manager.validate_rekey_request(request)
        assert is_valid is False
```

- [ ] **Step 4: 运行全量测试**

```bash
pytest tests/ -q
```

预期：全部通过

- [ ] **Step 5: 提交**

```bash
git add src/sip_protocol/transport/encrypted_channel.py tests/test_rekey_e2e.py
git commit -m "feat: Rekey闭环补全（send/receive处理rekey消息）"
```

---

### Task 6: Lint + 类型检查 + CHANGELOG

**Files:**
- Modify: `CHANGELOG.md`

- [ ] **Step 1: Pylint 检查**

```bash
cd python && source .venv/bin/activate
pylint src/sip_protocol/protocol/ src/sip_protocol/transport/ src/sip_protocol/managers/nonce.py
```

预期：10.00/10。如有问题立即修复。

- [ ] **Step 2: MyPy 检查**

```bash
mypy src/sip_protocol/protocol/ src/sip_protocol/transport/ src/sip_protocol/managers/
```

预期：Success: no issues found

- [ ] **Step 3: Black 格式化**

```bash
black src/sip_protocol/protocol/ tests/test_group_ratchet.py tests/test_rekey_e2e.py tests/test_version_negotiation.py
```

- [ ] **Step 4: 运行全量测试**

```bash
pytest tests/ -q
```

预期：全部 PASS

- [ ] **Step 5: 更新 CHANGELOG**

在 `CHANGELOG.md` 的 `[Unreleased]` 段 `### 修复` 下追加：

```markdown
#### 协议修复（P3）
- **Handshake** — 删除 complete_handshake 中重复的三重 DH 计算
- **Resume** — 修复签名数据字段 session_id → sender_id，与验证函数一致
- **Nonce** — set 改为 OrderedDict，保证 FIFO 淘汰
- **Rekey** — 旧密钥安全擦除（ctypes.memset）+ 接收端触发检查
- **群组 Double Ratchet** — chain_key 推进（HKDF message-key → chain-key）+ Skip Ratchet 乱序处理
- **版本协商** — 添加 4 步协商协议（version_offer → version_response → 解析）
```

- [ ] **Step 6: 提交**

```bash
git add CHANGELOG.md
git commit -m "docs: 更新CHANGELOG记录P3协议修复"
```
