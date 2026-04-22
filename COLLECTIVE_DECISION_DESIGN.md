# 集体决策机制设计

## 目标

让多个Agent能够通过投票/共识机制做决策，而不是单一Agent决定。

## 场景

- 多个Agent对同一个问题给出不同建议，需要投票选出最佳方案
- 安全关键决策需要多个Agent确认
- 分布式任务分配需要共识

## 设计方案

### 1. 决策提案（Proposal）

任何Agent可以发起一个提案：
```python
{
    "proposal_id": "prop-001",
    "initiator": "agent-a",
    "title": "是否采用方案X",
    "description": "...",
    "options": ["同意", "反对", "弃权"],
    "voters": ["agent-a", "agent-b", "agent-c"],
    "deadline": "2026-04-22T13:00:00Z",
    "quorum": 2,  # 需要至少2票
    "status": "pending"  # pending, approved, rejected, expired
}
```

### 2. 投票（Vote）

每个Agent对提案投票：
```python
{
    "vote_id": "vote-001",
    "proposal_id": "prop-001",
    "voter": "agent-b",
    "option": "同意",
    "reason": "方案X符合需求",
    "timestamp": "2026-04-22T12:45:00Z"
}
```

### 3. 决策算法

#### 简单多数
- 超过半数同意 → 通过

#### 绝对多数
- 超过2/3同意 → 通过

#### 一致同意
- 所有投票者都同意 → 通过

#### 加权投票
- 每个Agent有不同的权重

### 4. 集成到SIP

- 提案通过SIP加密传输
- 投票结果通过SIP加密存储
- 防止投票篡改

## 实现步骤

1. **ProposalManager** - 管理提案和投票
2. **DecisionEngine** - 决策算法
3. **加密存储** - 使用SIP保护投票数据
4. **MCP工具** - 让Agent通过MCP参与投票
5. **测试** - 验证各种决策场景
