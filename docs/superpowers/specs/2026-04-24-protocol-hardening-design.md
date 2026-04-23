# P3 协议修复 — 设计规格

> 修复现有 protocol 层实现与 e2ee-protocol.md 设计文档的差距

**设计文档:** `docs/e2ee-protocol.md`（权威规范）
**实施范围:** protocol/group.py, protocol/rekey.py, protocol/resume.py, protocol/handshake.py, protocol/version.py, transport/encrypted_channel.py, managers/nonce.py
**约束:** 纯同步 API，纯 stdlib，不引入新依赖

---

## 1. 差距清单

| # | 文件 | 差距 | 严重度 | e2ee 文档位置 |
|---|------|------|--------|--------------|
| G1 | group.py | Double Ratchet 未实现：chain_key 不推进，仅确定性派生 | 高 | 群组加密流程 |
| G2 | group.py | Skip Ratchet 逻辑缺失：skip_keys 字段存在但无处理代码 | 高 | 群组加密流程 |
| G3 | group.py | root_key 更新用 HKDF 而非 DH 交换 | 高 | 群组加密流程 |
| G4 | encrypted_channel.py | Rekey 闭环不完整：发起后无完整消息交换和密钥切换 | 中 | Rekey 流程 |
| G5 | encrypted_channel.py | Rekey 触发仅检查发送计数器，不检查接收计数器 | 中 | Rekey 触发条件 |
| G6 | rekey.py | 旧密钥未安全擦除：del 不保证内存清零 | 低 | Rekey 流程 |
| G7 | version.py | 缺 4 步版本协商协议（仅有工具函数） | 低 | 版本协商 |
| G8 | resume.py | 签名数据用 session_id 而非 sender_id 构造 | 低 | 连接恢复 |
| G9 | handshake.py | complete_handshake 中三重 DH 重复计算 | 低 | 握手流程 |
| G10 | nonce.py | set.pop() 不保证 FIFO 淘汰 | 低 | Nonce 管理 |

---

## 2. 设计方案

### 2.1 群组 Double Ratchet 重写（G1/G2/G3）

**当前问题：** `send_group_message` 使用 `hkdf(root_key, sender_id:msg_num)` 确定性派生密钥，chain_key 从不推进。

**目标实现（遵循 e2ee-protocol.md）：**

```
发送链:
  message_key = HKDF(chain_key, "", "message-key", 32)
  next_chain_key = HKDF(chain_key, "", "chain-key", 32)

接收链:
  若 message_number > expected:
    跳跃：对每个缺失的 number 执行
      skip_key = HKDF(chain_key, "", "skip-key", 32)
      next_chain_key = HKDF(chain_key, "", "chain-key", 32)
  然后：正常处理当前消息
```

**数据结构：**

```python
@dataclass
class ChainState:
    chain_key: bytes
    message_number: int
    skip_keys: dict[int, bytes]  # message_number -> skip_key

@dataclass
class GroupMemberState:
    sending_chain: ChainState
    receiving_chain: ChainState
```

**root_key 更新（成员变更）：**
- 加入：`new_root_key = HKDF(root_key, new_member_pub, "group-root-key", 32)`
- 离开：`new_root_key = HKDF(root_key, leaving_member_pub, "group-root-key-after-leave", 32)`
- 注：代码中无法做真正的 DH（没有成员持久密钥），保持 HKDF 方案但在 info 参数中包含成员公钥以确保确定性派生

**与现有代码的关系：**
- `GroupManager` 类保留，内部切换到 ChainState 数据结构
- 对外接口（`send_group_message`, `receive_group_message`, `add_member`, `remove_member`）不变
- `group_simple.py` 保持不变，作为轻量替代

### 2.2 Rekey 闭环补全（G4/G5/G6）

**当前问题：** encrypted_channel 中 `_initiate_rekey` 创建请求但没有发送和完成闭环。

**目标：**

```
发送端:
  1. _check_rekey_needed() — 同时检查 send_counter 和 receive_counter
  2. _initiate_rekey() — 创建 RekeyManager + 发送 rekey_request
  3. handle_rekey_response() — 验证签名，调用 apply_new_keys()
  4. 旧密钥 zeroize

接收端:
  1. handle_rekey_request() — 验证签名，创建 response
  2. apply_new_keys() — 切换密钥
  3. 旧密钥 zeroize
```

**旧密钥安全擦除：**
```python
def _secure_wipe(data: bytearray) -> None:
    """安全擦除内存中的密钥数据"""
    import ctypes
    ctypes.memset(ctypes.addressof(data), 0, len(data))
```
注意：Python 的 `del` 和覆盖不保证内存清零。用 ctypes.memset 提供尽力擦除。

### 2.3 版本协商协议补全（G7）

**当前：** `version.py` 只有 `negotiate_version()`, `validate_version()`, `version_compare()` 工具函数。

**目标：** 添加消息构造/解析函数：

```python
def create_version_negotiation(supported_versions: list[str]) -> dict
def parse_version_response(data: dict) -> dict
def create_version_not_supported(supported: list[str]) -> dict
```

消息格式遵循 e2ee-protocol.md 第 738-783 行。

### 2.4 Bug 修复（G8/G9/G10）

**G9 — handshake.py：**
删除 `complete_handshake` 中重复的三重 DH 计算（行 239-244 为冗余代码）。

**G8 — resume.py：**
`create_session_resume_message` 中签名数据从 `session_id:message_counter` 改为 `sender_id:message_counter`，与 `verify_session_resume` 保持一致。

**G10 — nonce.py：**
将 `self.used_nonces: set` 改为 `collections.OrderedDict`，确保 `pop(last=False)` 移除最早添加的条目。

---

## 3. 不改的部分

- `group_simple.py` — 轻量群组替代，保持不变
- `protocol/decision.py` — 设计文档无规范，保持自主设计
- `protocol/persistence.py` / `offline_queue.py` — 与此次修复无关
- `crypto/` — 加密原语层无差距
- `schema/` / `file_transfer/` — 与此次修复无关
- `transport/` 适配器层 — 与此次修复无关

---

## 4. 测试策略

### 新增测试
- `test_group_ratchet.py` — chain_key 推进验证、Skip Ratchet 验证、root_key 更新验证
- `test_rekey_e2e.py` — 发送端发起 → 接收端响应 → 双方密钥切换 → 旧密钥无法解密
- `test_version_negotiation.py` — 4 步协商成功/失败场景

### 现有测试
- 所有现有测试必须通过，零回归
- 修复后覆盖率不低于 82%
