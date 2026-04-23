# Task Manager 设计文档

> 版本: v1.0
> 日期: 2026-04-22
> 状态: 已批准
> 关联: M1 (sip-protocol-report.md Section 8.5.2 M1)

## 1. 问题陈述

SIP只有会话概念，没有任务概念。无法支持长时间运行任务、任务状态追踪、人工介入场景。

## 2. 设计原则

1. **完整状态机** — Task实体支持7种状态的明确转换
2. **自动历史记录** — 每次状态变更自动追加TaskEvent，不需要调用方手动记录
3. **超时保护** — 任务可设超时，超时自动标记FAILED
4. **同步API** — 与现有SIP项目一致
5. **产出物管理** — Artifact复用S1 Message Schema的Part类型

## 3. 状态机

```python
class TaskState(str, Enum):
    PENDING = "pending"                 # 已创建，等待认领
    CLAIMED = "claimed"                 # 已被Agent认领
    WORKING = "working"                 # 执行中
    INPUT_REQUIRED = "input_required"   # 等待人工输入
    COMPLETED = "completed"             # 已完成
    FAILED = "failed"                   # 失败
    CANCELLED = "cancelled"             # 已取消
```

**合法状态转换**：

```
PENDING ──→ CLAIMED ──→ WORKING ──→ COMPLETED
                        │              └→ FAILED
                        │
                        └→ INPUT_REQUIRED ──→ WORKING ──→ COMPLETED
                                              └→ FAILED
PENDING ──→ CANCELLED
WORKING ──→ CANCELLED
```

```python
VALID_TRANSITIONS: dict[TaskState, set[TaskState]] = {
    TaskState.PENDING: {TaskState.CLAIMED, TaskState.CANCELLED},
    TaskState.CLAIMED: {TaskState.WORKING, TaskState.CANCELLED},
    TaskState.WORKING: {TaskState.COMPLETED, TaskState.FAILED,
                        TaskState.INPUT_REQUIRED, TaskState.CANCELLED},
    TaskState.INPUT_REQUIRED: {TaskState.WORKING, TaskState.CANCELLED},
    # COMPLETED, FAILED, CANCELLED 是终态，不可转换
}
```

## 4. 数据结构

### 4.1 TaskEvent（状态变更事件，自动记录）

```python
@dataclass
class TaskEvent:
    """任务状态变更事件 — 由TaskManager自动生成"""
    from_state: TaskState
    to_state: TaskState
    agent_id: str              # 触发者Agent ID
    timestamp: float           # Unix时间戳
    message: str | None = None # 可选说明
```

### 4.2 Artifact（任务产出物）

```python
class ArtifactType(str, Enum):
    FILE = "file"       # 文件产出
    DATA = "data"       # 结构化数据
    TEXT = "text"       # 文本产出


@dataclass
class Artifact:
    """任务产出物 — 复用S1 Message Schema的Part类型"""
    id: str
    name: str
    type: ArtifactType
    parts: list[dict]          # Part类型数组（TextPart/DataPart/FileRefPart等）
    created_at: float

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "type": self.type.value,
            "parts": self.parts,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Artifact":
        return cls(
            id=data["id"],
            name=data["name"],
            type=ArtifactType(data["type"]),
            parts=data.get("parts", []),
            created_at=data.get("created_at", 0),
        )
```

### 4.3 Task

```python
@dataclass
class Task:
    id: str                              # UUIDv7
    conversation_id: str                 # 关联对话
    state: TaskState
    assignee: str | None                 # 执行者Agent ID
    created_by: str                      # 创建者Agent ID
    description: str                     # 任务描述
    artifacts: list[Artifact]
    history: list[TaskEvent]             # 状态变更历史（自动记录）
    timeout_seconds: int | None          # 超时时间（秒），None=不限
    metadata: dict[str, Any]
    created_at: float
    updated_at: float
    completed_at: float | None
    error: str | None                    # 失败时的错误信息
```

## 5. TaskManager API

```python
class TaskManager:
    """任务管理器 — 同步API"""

    def __init__(self, db_path: str = "~/.openclaw/sip_tasks.db"):
        ...

    # === 创建 ===

    def create_task(
        self,
        conversation_id: str,
        description: str,
        created_by: str,
        timeout_seconds: int | None = None,
    ) -> Task:
        """创建任务，初始状态PENDING"""

    # === 状态管理 ===

    def claim_task(self, task_id: str, agent_id: str) -> Task:
        """认领任务：PENDING → CLAIMED"""

    def start_task(self, task_id: str) -> Task:
        """开始执行：CLAIMED → WORKING"""

    def update_state(
        self,
        task_id: str,
        state: TaskState,
        agent_id: str,
        message: str | None = None,
        error: str | None = None,
    ) -> Task:
        """更新状态，自动追加TaskEvent到history"""

    def resume_with_input(self, task_id: str, input_data: dict, agent_id: str) -> Task:
        """人工输入恢复：INPUT_REQUIRED → WORKING"""

    def complete_task(self, task_id: str, agent_id: str) -> Task:
        """完成任务：WORKING → COMPLETED"""

    def fail_task(self, task_id: str, error: str, agent_id: str) -> Task:
        """标记失败：WORKING → FAILED"""

    def cancel_task(self, task_id: str, agent_id: str) -> Task:
        """取消任务：PENDING/CLAIMED/WORKING → CANCELLED"""

    # === 产出物 ===

    def add_artifact(self, task_id: str, artifact: Artifact) -> Task:
        """添加产出物"""

    # === 查询 ===

    def get_task(self, task_id: str) -> Task | None:
        """查询单个任务"""

    def list_tasks(
        self,
        conversation_id: str | None = None,
        state: TaskState | None = None,
        assignee: str | None = None,
    ) -> list[Task]:
        """按条件查询任务"""

    # === 维护 ===

    def check_timeouts(self) -> list[Task]:
        """检查超时任务，返回超时被标记FAILED的任务列表"""

    def cleanup_completed(self, older_than_seconds: int = 604800) -> int:
        """清理已完成/取消/失败的任务（默认7天），返回清理数量"""
```

## 6. update_state 自动记录

```python
def update_state(self, task_id: str, state: TaskState,
                 agent_id: str, message: str | None = None,
                 error: str | None = None) -> Task:
    task = self.get_task(task_id)
    if task is None:
        raise TaskError(f"Task not found: {task_id}")

    # 验证状态转换合法性
    if state not in VALID_TRANSITIONS.get(task.state, set()):
        raise TaskError(
            f"Invalid transition: {task.state.value} → {state.value}"
        )

    from_state = task.state

    # 自动追加历史事件
    event = TaskEvent(
        from_state=from_state,
        to_state=state,
        agent_id=agent_id,
        timestamp=time.time(),
        message=message,
    )
    task.history.append(event)
    task.state = state
    task.updated_at = time.time()

    if error:
        task.error = error
    if state in (TaskState.COMPLETED, TaskState.FAILED, TaskState.CANCELLED):
        task.completed_at = time.time()

    self._store.save(task)
    return task
```

## 7. 超时机制

```python
def check_timeouts(self) -> list[Task]:
    """检查并处理超时任务"""
    now = time.time()
    timed_out = []
    for task in self.list_tasks(state=TaskState.WORKING):
        if task.timeout_seconds is None:
            continue
        elapsed = now - task.updated_at
        if elapsed >= task.timeout_seconds:
            self.fail_task(
                task.id,
                error=f"Task timed out after {task.timeout_seconds}s",
                agent_id="system",
            )
            timed_out.append(task)
    return timed_out
```

调用时机：由Registry的心跳检查机制触发（每次check_health时顺便check_timeouts）。

## 8. 模块位置

```
python/src/sip_protocol/
├── task/
│   ├── __init__.py
│   ├── types.py          # TaskState, ArtifactType, TaskEvent, Artifact
│   ├── task.py           # Task 数据结构
│   └── manager.py        # TaskManager
```
