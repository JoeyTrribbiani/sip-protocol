# SSE 流式传输设计文档

> 版本: v1.0
> 日期: 2026-04-22
> 状态: 已批准
> 关联: M2 (sip-protocol-report.md Section 8.3.2 差距4)

## 1. 问题陈述

SIP只能处理完整消息，无法支持LLM流式输出、实时进度反馈等场景。

## 2. 设计原则

1. **分层实现** — 先在现有传输层（WebSocket/stdio）上实现流式语义，后续再加HTTP/SSE适配器
2. **单向流式** — SSE只用于单向流式输出（Server→Client），不替代双向通信
3. **有序传输** — chunk必须按index顺序到达，乱序视为错误
4. **Schema预留** — StreamPart类型已在S1 Message Schema中预留定义

## 3. StreamPart 复用

已在S1定义的StreamPart：

```json
{
  "type": "stream",
  "chunk_index": 3,
  "total_chunks": null,
  "is_final": false,
  "data": "分块数据"
}
```

## 4. 分阶段实现

### Phase 1：基于现有传输层的流式（当前实现）

在WebSocket和stdio上通过StreamPart消息序列实现流式：

```
Agent A ──StreamPart chunk=0──→ Agent B
Agent A ──StreamPart chunk=1──→ Agent B
Agent A ──StreamPart chunk=2──→ Agent B
Agent A ──StreamPart chunk=3, is_final=true──→ Agent B
```

### Phase 2：HTTP + SSE 适配器（后续扩展）

当HTTP传输层（S3）实现后，增加SSE适配器：

```
Agent A ←──SIP加密消息──→ Agent B（双向请求/响应）
Agent A ←──SSE stream──── Agent B（B向A单向流式推送）
```

## 5. 重组策略

### 5.1 StreamReceiver

```python
class StreamReceiver:
    """流式消息接收器 — 重组StreamPart为完整消息"""

    def __init__(self, stream_id: str, chunk_timeout: float = 30.0):
        self._stream_id = stream_id
        self._chunks: dict[int, Any] = {}
        self._expected_index: int = 0
        self._total_chunks: int | None = None
        self._is_complete: bool = False
        self._chunk_timeout = chunk_timeout
        self._last_chunk_time: float = 0

    def receive_chunk(self, part: dict) -> "StreamResult":
        """接收一个StreamPart，返回处理结果"""
        chunk_index = part["chunk_index"]

        # 有序检查
        if chunk_index != self._expected_index:
            return StreamResult(
                status="error",
                error=f"Expected chunk {self._expected_index}, got {chunk_index}",
            )

        self._chunks[chunk_index] = part["data"]
        self._expected_index = chunk_index + 1
        self._last_chunk_time = time.time()

        if part.get("total_chunks") is not None:
            self._total_chunks = part["total_chunks"]

        if part.get("is_final", False):
            self._is_complete = True
            return StreamResult(
                status="complete",
                data=self._assemble(),
            )

        return StreamResult(status="partial", received=chunk_index + 1)

    def check_timeout(self) -> bool:
        """检查是否等待超时"""
        if self._is_complete or not self._chunks:
            return False
        return time.time() - self._last_chunk_time > self._chunk_timeout

    def _assemble(self) -> Any:
        """按序组装所有chunk为完整数据"""
        if not self._chunks:
            return None
        # 如果是文本流，拼接字符串
        # 如果是二进制流，拼接bytes
        # 由调用方根据content_type决定
        parts = [self._chunks[i] for i in range(len(self._chunks))]
        return parts

    def abort(self) -> None:
        """中止流式接收，丢弃已收到的数据"""


@dataclass
class StreamResult:
    status: str        # "partial" | "complete" | "error"
    data: Any = None   # 完整数据（status=complete时）
    received: int = 0  # 已接收chunk数（status=partial时）
    error: str | None = None  # 错误信息（status=error时）
```

### 5.2 StreamSender

```python
class StreamSender:
    """流式消息发送器 — 将数据切片为StreamPart"""

    def __init__(self, stream_id: str, chunk_size: int = 4096):
        self._stream_id = stream_id
        self._chunk_size = chunk_size
        self._chunk_index = 0

    def create_chunks(self, data: str | bytes) -> list[dict]:
        """将数据切片为StreamPart列表"""
        if isinstance(data, str):
            data_bytes = data.encode("utf-8")
        else:
            data_bytes = data

        chunks = []
        total = math.ceil(len(data_bytes) / self._chunk_size)

        for i in range(total):
            start = i * self._chunk_size
            end = min(start + self._chunk_size, len(data_bytes))
            chunk_data = data_bytes[start:end]

            is_final = (i == total - 1)
            part = {
                "type": "stream",
                "stream_id": self._stream_id,
                "chunk_index": i,
                "total_chunks": total,
                "is_final": is_final,
                "data": chunk_data.decode("utf-8") if isinstance(data, str) else chunk_data,
            }
            chunks.append(part)

        return chunks
```

## 6. 错误处理

```python
class StreamAbortError(SIPError):
    """流式传输中止"""
    def __init__(self, stream_id: str, chunk_index: int, reason: str = ""):
        super().__init__(
            code="SIP-MSG-010",
            message=f"Stream aborted at chunk {chunk_index}: {reason}",
            recoverable=True,
            details={"stream_id": stream_id, "chunk_index": chunk_index},
        )
```

**丢包处理**：
1. chunk等待超时（默认30秒）→ 发送StreamAbort消息
2. 接收方收到StreamAbort → 丢弃已收到的数据，可选重试
3. 重试由调用方决定（重新发起流式传输）

## 7. 与Task Manager集成

流式输出与任务进度联动：

```python
# Agent B 向 Agent A 流式输出任务结果
sender = StreamSender(stream_id=task.id)
chunks = sender.create_chunks(result_text)

for chunk in chunks:
    send_sip_message(recipient="agent-a", parts=[chunk])

    # 每10个chunk更新一次任务进度
    if chunk["chunk_index"] % 10 == 0:
        task_manager.update_state(
            task.id, TaskState.WORKING, agent_id="agent-b",
            message=f"Progress: {chunk['chunk_index']}/{chunk['total_chunks']}",
        )

# 最终chunk发送后标记完成
task_manager.complete_task(task.id, agent_id="agent-b")
```

## 8. 模块位置

```
python/src/sip_protocol/
├── streaming/
│   ├── __init__.py
│   ├── sender.py         # StreamSender
│   ├── receiver.py       # StreamReceiver, StreamResult
│   └── exceptions.py     # StreamAbortError（或放入exceptions.py）
```
