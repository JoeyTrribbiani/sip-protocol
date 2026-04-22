"""
集体决策机制模块

让多个Agent通过投票/共识机制做决策。

功能：
1. 创建提案（Proposal）
2. 投票（Vote）
3. 决策算法（简单多数、绝对多数、一致同意、加权投票）
4. 超时过期
5. 结果通知

使用方式：
    from sip_protocol.protocol.decision import DecisionEngine

    engine = DecisionEngine(agent_id="agent-a")

    # 发起提案
    proposal = engine.create_proposal(
        title="是否采用方案X",
        options=["同意", "反对", "弃权"],
        voters=["agent-a", "agent-b", "agent-c"],
        deadline_seconds=3600,
        strategy="majority",
    )

    # 投票
    engine.vote(proposal.proposal_id, "同意", reason="方案X符合需求")

    # 检查结果
    result = engine.evaluate(proposal.proposal_id)
"""

import json
import time
import uuid
from enum import Enum
from typing import Any, Dict, List, Optional

# ──────────────── 枚举 ────────────────


class ProposalStatus(str, Enum):
    """提案状态"""

    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"
    CANCELLED = "cancelled"


class DecisionStrategy(str, Enum):
    """决策策略"""

    MAJORITY = "majority"  # 简单多数（>50%）
    SUPER_MAJORITY = "super_majority"  # 绝对多数（>2/3）
    UNANIMOUS = "unanimous"  # 一致同意
    WEIGHTED = "weighted"  # 加权投票
    VETO = "veto"  # 一票否决（任一反对即否决）


# ──────────────── 数据类 ────────────────


class Proposal:
    """提案"""

    def __init__(
        self,
        proposal_id: str,
        initiator: str,
        title: str,
        options: List[str],
        voters: List[str],
        deadline: float,
        strategy: str,
        quorum: int,
        description: str = "",
        weights: Optional[Dict[str, float]] = None,
    ):
        self.proposal_id = proposal_id
        self.initiator = initiator
        self.title = title
        self.description = description
        self.options = options
        self.voters = voters
        self.deadline = deadline
        self.strategy = strategy
        self.quorum = quorum
        self.weights = weights or {}
        self.status = ProposalStatus.PENDING
        self.created_at = time.time()
        self.votes: List["Vote"] = []

    def to_dict(self) -> Dict[str, Any]:
        """序列化为字典"""
        return {
            "proposal_id": self.proposal_id,
            "initiator": self.initiator,
            "title": self.title,
            "description": self.description,
            "options": self.options,
            "voters": self.voters,
            "deadline": self.deadline,
            "strategy": self.strategy,
            "quorum": self.quorum,
            "weights": self.weights,
            "status": self.status.value,
            "created_at": self.created_at,
            "votes": [v.to_dict() for v in self.votes],
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Proposal":
        """从字典反序列化"""
        proposal = cls(
            proposal_id=data["proposal_id"],
            initiator=data["initiator"],
            title=data["title"],
            options=data["options"],
            voters=data["voters"],
            deadline=data["deadline"],
            strategy=data["strategy"],
            quorum=data["quorum"],
            description=data.get("description", ""),
            weights=data.get("weights"),
        )
        proposal.status = ProposalStatus(data["status"])
        proposal.created_at = data["created_at"]
        for vote_data in data.get("votes", []):
            proposal.votes.append(Vote.from_dict(vote_data))
        return proposal


class Vote:
    """投票"""

    def __init__(
        self,
        vote_id: str,
        proposal_id: str,
        voter: str,
        option: str,
        reason: str = "",
        timestamp: Optional[float] = None,
    ):
        self.vote_id = vote_id
        self.proposal_id = proposal_id
        self.voter = voter
        self.option = option
        self.reason = reason
        self.timestamp = timestamp or time.time()

    def to_dict(self) -> Dict[str, Any]:
        """序列化为字典"""
        return {
            "vote_id": self.vote_id,
            "proposal_id": self.proposal_id,
            "voter": self.voter,
            "option": self.option,
            "reason": self.reason,
            "timestamp": self.timestamp,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Vote":
        """从字典反序列化"""
        return cls(
            vote_id=data["vote_id"],
            proposal_id=data["proposal_id"],
            voter=data["voter"],
            option=data["option"],
            reason=data.get("reason", ""),
            timestamp=data.get("timestamp"),
        )


class DecisionResult:
    """决策结果"""

    def __init__(
        self,
        proposal_id: str,
        status: ProposalStatus,
        winner: Optional[str],
        vote_counts: Dict[str, int],
        total_votes: int,
        quorum_met: bool,
        details: str,
    ):
        self.proposal_id = proposal_id
        self.status = status
        self.winner = winner
        self.vote_counts = vote_counts
        self.total_votes = total_votes
        self.quorum_met = quorum_met
        self.details = details

    def to_dict(self) -> Dict[str, Any]:
        """序列化为字典"""
        return {
            "proposal_id": self.proposal_id,
            "status": self.status.value,
            "winner": self.winner,
            "vote_counts": self.vote_counts,
            "total_votes": self.total_votes,
            "quorum_met": self.quorum_met,
            "details": self.details,
        }


# ──────────────── 决策引擎 ────────────────


class DecisionEngine:
    """
    集体决策引擎

    管理提案、投票和决策流程。

    使用方式：
        engine = DecisionEngine(agent_id="agent-a")
        proposal = engine.create_proposal(...)
        engine.vote(proposal.proposal_id, "同意")
        result = engine.evaluate(proposal.proposal_id)
    """

    def __init__(
        self,
        agent_id: str,
        default_strategy: str = "majority",
        default_quorum: int = 2,
    ):
        """
        初始化决策引擎

        Args:
            agent_id: 本地Agent ID
            default_strategy: 默认决策策略
            default_quorum: 默认法定人数
        """
        self.agent_id = agent_id
        self.default_strategy = default_strategy
        self.default_quorum = default_quorum
        self._proposals: Dict[str, Proposal] = {}

    def create_proposal(
        self,
        title: str,
        options: Optional[List[str]] = None,
        voters: Optional[List[str]] = None,
        deadline_seconds: float = 3600.0,
        strategy: Optional[str] = None,
        quorum: Optional[int] = None,
        description: str = "",
        weights: Optional[Dict[str, float]] = None,
    ) -> Proposal:
        """
        创建提案

        Args:
            title: 提案标题
            options: 投票选项（默认：["同意", "反对", "弃权"]）
            voters: 投票者列表
            deadline_seconds: 截止时间（秒）
            strategy: 决策策略
            quorum: 法定人数
            description: 描述
            weights: 加权权重（strategy="weighted"时使用）

        Returns:
            Proposal: 新创建的提案
        """
        if options is None:
            options = ["同意", "反对", "弃权"]
        if voters is None:
            voters = [self.agent_id]
        if strategy is None:
            strategy = self.default_strategy
        if quorum is None:
            quorum = min(self.default_quorum, len(voters))

        proposal_id = f"prop-{uuid.uuid4().hex[:8]}"
        deadline = time.time() + deadline_seconds

        proposal = Proposal(
            proposal_id=proposal_id,
            initiator=self.agent_id,
            title=title,
            options=options,
            voters=voters,
            deadline=deadline,
            strategy=strategy,
            quorum=quorum,
            description=description,
            weights=weights,
        )

        self._proposals[proposal_id] = proposal
        return proposal

    def vote(
        self,
        proposal_id: str,
        option: str,
        reason: str = "",
    ) -> Vote:
        """
        对提案投票

        Args:
            proposal_id: 提案ID
            option: 投票选项
            reason: 投票理由

        Returns:
            Vote: 投票记录

        Raises:
            ValueError: 提案不存在/已结束/无权投票/已投过票/选项无效
        """
        proposal = self._get_proposal(proposal_id)

        # 检查提案状态
        if proposal.status != ProposalStatus.PENDING:
            raise ValueError(f"提案已结束: {proposal.status.value}")

        # 检查是否过期
        if time.time() > proposal.deadline:
            proposal.status = ProposalStatus.EXPIRED
            raise ValueError("提案已过期")

        # 检查是否有权投票
        if self.agent_id not in proposal.voters:
            raise ValueError(f"无权投票: {self.agent_id} 不在投票者列表中")

        # 检查是否已投过票
        for existing_vote in proposal.votes:
            if existing_vote.voter == self.agent_id:
                raise ValueError(f"已投过票: {self.agent_id}")

        # 检查选项是否有效
        if option not in proposal.options:
            raise ValueError(f"无效选项: {option}，有效选项: {proposal.options}")

        vote = Vote(
            vote_id=f"vote-{uuid.uuid4().hex[:8]}",
            proposal_id=proposal_id,
            voter=self.agent_id,
            option=option,
            reason=reason,
        )

        proposal.votes.append(vote)
        return vote

    def evaluate(self, proposal_id: str) -> DecisionResult:
        """
        评估提案结果

        Args:
            proposal_id: 提案ID

        Returns:
            DecisionResult: 决策结果
        """
        proposal = self._get_proposal(proposal_id)

        # 检查是否过期
        if time.time() > proposal.deadline and proposal.status == ProposalStatus.PENDING:
            proposal.status = ProposalStatus.EXPIRED

        # 统计票数
        vote_counts: Dict[str, int] = {opt: 0 for opt in proposal.options}
        for v in proposal.votes:
            vote_counts[v.option] = vote_counts.get(v.option, 0) + 1

        total_votes = len(proposal.votes)
        quorum_met = total_votes >= proposal.quorum

        # 如果提案已结束，直接返回当前状态
        if proposal.status != ProposalStatus.PENDING:
            return DecisionResult(
                proposal_id=proposal_id,
                status=proposal.status,
                winner=None,
                vote_counts=vote_counts,
                total_votes=total_votes,
                quorum_met=quorum_met,
                details=f"提案已结束: {proposal.status.value}",
            )

        # 未达法定人数
        if not quorum_met:
            return DecisionResult(
                proposal_id=proposal_id,
                status=ProposalStatus.PENDING,
                winner=None,
                vote_counts=vote_counts,
                total_votes=total_votes,
                quorum_met=False,
                details=f"未达法定人数: {total_votes}/{proposal.quorum}",
            )

        # 根据策略计算结果
        strategy = proposal.strategy
        if strategy == DecisionStrategy.WEIGHTED.value:
            winner, details = self._evaluate_weighted(proposal)
        elif strategy == DecisionStrategy.UNANIMOUS.value:
            winner, details = self._evaluate_unanimous(proposal, vote_counts)
        elif strategy == DecisionStrategy.SUPER_MAJORITY.value:
            winner, details = self._evaluate_super_majority(proposal, vote_counts, total_votes)
        elif strategy == DecisionStrategy.VETO.value:
            winner, details = self._evaluate_veto(proposal, vote_counts)
        else:
            winner, details = self._evaluate_majority(proposal, vote_counts, total_votes)

        # 更新提案状态
        if winner is not None:
            proposal.status = ProposalStatus.APPROVED
        elif (
            details.startswith("否决")
            or details.startswith("未通过")
            or details.startswith("未一致")
        ):
            proposal.status = ProposalStatus.REJECTED

        return DecisionResult(
            proposal_id=proposal_id,
            status=proposal.status,
            winner=winner,
            vote_counts=vote_counts,
            total_votes=total_votes,
            quorum_met=quorum_met,
            details=details,
        )

    def cancel_proposal(self, proposal_id: str) -> None:
        """
        取消提案

        Args:
            proposal_id: 提案ID

        Raises:
            ValueError: 无权取消
        """
        proposal = self._get_proposal(proposal_id)

        if proposal.initiator != self.agent_id:
            raise ValueError("只有发起者可以取消提案")

        if proposal.status != ProposalStatus.PENDING:
            raise ValueError(f"提案已结束: {proposal.status.value}")

        proposal.status = ProposalStatus.CANCELLED

    def get_proposal(self, proposal_id: str) -> Optional[Proposal]:
        """获取提案"""
        return self._proposals.get(proposal_id)

    def list_proposals(
        self,
        status: Optional[ProposalStatus] = None,
    ) -> List[Proposal]:
        """
        列出提案

        Args:
            status: 按状态过滤

        Returns:
            提案列表
        """
        proposals = list(self._proposals.values())
        if status is not None:
            proposals = [p for p in proposals if p.status == status]
        return proposals

    def import_vote(self, proposal_id: str, vote_data: Dict[str, Any]) -> Vote:
        """
        导入外部投票（来自其他Agent）

        Args:
            proposal_id: 提案ID
            vote_data: 投票数据

        Returns:
            Vote: 投票记录
        """
        proposal = self._get_proposal(proposal_id)

        vote = Vote.from_dict(vote_data)

        # 验证投票者
        if vote.voter not in proposal.voters:
            raise ValueError(f"无效投票者: {vote.voter}")

        # 检查是否已投过
        for existing in proposal.votes:
            if existing.voter == vote.voter:
                raise ValueError(f"投票者已投票: {vote.voter}")

        proposal.votes.append(vote)
        return vote

    def export_proposal(self, proposal_id: str) -> str:
        """
        导出提案为JSON字符串（用于传输给其他Agent）

        Args:
            proposal_id: 提案ID

        Returns:
            JSON字符串
        """
        import json

        proposal = self._get_proposal(proposal_id)
        return json.dumps(proposal.to_dict(), ensure_ascii=False)

    def import_proposal(self, proposal_json: str) -> Proposal:
        """
        从JSON字符串导入提案

        Args:
            proposal_json: JSON字符串

        Returns:
            Proposal: 提案对象
        """
        import json

        data = json.loads(proposal_json)
        proposal = Proposal.from_dict(data)
        self._proposals[proposal.proposal_id] = proposal
        return proposal

    # ──────────────── 私有方法 ────────────────

    def _get_proposal(self, proposal_id: str) -> Proposal:
        """获取提案，不存在则抛异常"""
        if proposal_id not in self._proposals:
            raise ValueError(f"提案不存在: {proposal_id}")
        return self._proposals[proposal_id]

    def _evaluate_majority(
        self,
        proposal: Proposal,
        vote_counts: Dict[str, int],
        total_votes: int,
    ) -> tuple:
        """简单多数决策"""
        # 找出第一个选项（通常是"同意"）的票数
        approve_option = proposal.options[0]
        approve_count = vote_counts.get(approve_option, 0)

        if approve_count > total_votes / 2:
            return approve_option, f"简单多数通过: {approve_count}/{total_votes}"

        return None, f"未通过简单多数: {approve_count}/{total_votes}"

    def _evaluate_super_majority(
        self,
        proposal: Proposal,
        vote_counts: Dict[str, int],
        total_votes: int,
    ) -> tuple:
        """绝对多数决策（>2/3）"""
        approve_option = proposal.options[0]
        approve_count = vote_counts.get(approve_option, 0)

        if total_votes > 0 and approve_count / total_votes > 2 / 3:
            return approve_option, f"绝对多数通过: {approve_count}/{total_votes}"

        return None, f"未通过绝对多数: {approve_count}/{total_votes}"

    def _evaluate_unanimous(
        self,
        proposal: Proposal,
        vote_counts: Dict[str, int],
    ) -> tuple:
        """一致同意决策"""
        approve_option = proposal.options[0]
        total_voters = len(proposal.voters)
        approve_count = vote_counts.get(approve_option, 0)

        # 需要所有投票者都投票且都同意
        if approve_count == total_voters:
            return approve_option, f"一致通过: {approve_count}/{total_voters}"

        return None, f"未一致通过: {approve_count}/{total_voters}"

    def _evaluate_weighted(self, proposal: Proposal) -> tuple:
        """加权投票决策"""
        weighted_counts: Dict[str, float] = {opt: 0.0 for opt in proposal.options}
        total_weight = 0.0

        for v in proposal.votes:
            weight = proposal.weights.get(v.voter, 1.0)
            weighted_counts[v.option] = weighted_counts.get(v.option, 0.0) + weight
            total_weight += weight

        if total_weight == 0:
            return None, "无有效投票"

        approve_option = proposal.options[0]
        approve_weight = weighted_counts.get(approve_option, 0.0)

        if approve_weight > total_weight / 2:
            return (
                approve_option,
                f"加权多数通过: {approve_weight:.1f}/{total_weight:.1f}",
            )

        return None, f"未通过加权多数: {approve_weight:.1f}/{total_weight:.1f}"

    def _evaluate_veto(
        self,
        proposal: Proposal,
        vote_counts: Dict[str, int],
    ) -> tuple:
        """一票否决决策"""
        # 选项中第二个通常是"反对"
        reject_option = proposal.options[1] if len(proposal.options) > 1 else "反对"
        reject_count = vote_counts.get(reject_option, 0)

        if reject_count > 0:
            return None, f"否决: {reject_count}票反对"

        approve_option = proposal.options[0]
        return approve_option, f"无否决，通过"
