"""
集体决策机制测试
"""

import sys
import os
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.protocol.decision import (
    DecisionEngine,
    DecisionResult,
    DecisionStrategy,
    Proposal,
    ProposalStatus,
    Vote,
)


class TestProposal:
    """提案数据类测试"""

    def test_to_dict(self):
        """测试序列化"""
        proposal = Proposal(
            proposal_id="prop-001",
            initiator="agent-a",
            title="测试提案",
            options=["同意", "反对", "弃权"],
            voters=["agent-a", "agent-b", "agent-c"],
            deadline=time.time() + 3600,
            strategy="majority",
            quorum=2,
        )
        data = proposal.to_dict()

        assert data["proposal_id"] == "prop-001"
        assert data["initiator"] == "agent-a"
        assert data["title"] == "测试提案"
        assert data["status"] == "pending"
        assert len(data["voters"]) == 3

    def test_from_dict(self):
        """测试反序列化"""
        data = {
            "proposal_id": "prop-002",
            "initiator": "agent-b",
            "title": "测试提案2",
            "options": ["同意", "反对"],
            "voters": ["agent-a", "agent-b"],
            "deadline": time.time() + 3600,
            "strategy": "unanimous",
            "quorum": 2,
            "status": "pending",
            "created_at": time.time(),
            "votes": [],
        }
        proposal = Proposal.from_dict(data)

        assert proposal.proposal_id == "prop-002"
        assert proposal.initiator == "agent-b"
        assert proposal.strategy == "unanimous"


class TestVote:
    """投票数据类测试"""

    def test_to_dict(self):
        """测试序列化"""
        vote = Vote(
            vote_id="vote-001",
            proposal_id="prop-001",
            voter="agent-a",
            option="同意",
            reason="测试理由",
        )
        data = vote.to_dict()

        assert data["vote_id"] == "vote-001"
        assert data["voter"] == "agent-a"
        assert data["option"] == "同意"

    def test_from_dict(self):
        """测试反序列化"""
        data = {
            "vote_id": "vote-002",
            "proposal_id": "prop-001",
            "voter": "agent-b",
            "option": "反对",
            "reason": "",
            "timestamp": time.time(),
        }
        vote = Vote.from_dict(data)

        assert vote.vote_id == "vote-002"
        assert vote.voter == "agent-b"
        assert vote.option == "反对"


class TestDecisionEngine:
    """决策引擎测试"""

    def test_create_proposal(self):
        """测试创建提案"""
        engine = DecisionEngine(agent_id="agent-a")
        proposal = engine.create_proposal(
            title="测试提案",
            config={"voters": ["agent-a", "agent-b", "agent-c"]},
        )

        assert proposal.initiator == "agent-a"
        assert proposal.title == "测试提案"
        assert proposal.status == ProposalStatus.PENDING
        assert len(proposal.voters) == 3
        assert proposal.strategy == "majority"

    def test_vote(self):
        """测试投票"""
        engine = DecisionEngine(agent_id="agent-a")
        proposal = engine.create_proposal(
            title="测试提案",
            config={"voters": ["agent-a", "agent-b"]},
        )

        vote = engine.vote(proposal.proposal_id, "同意", reason="测试")

        assert vote.voter == "agent-a"
        assert vote.option == "同意"
        assert len(proposal.votes) == 1

    def test_vote_twice_fails(self):
        """测试重复投票"""
        engine = DecisionEngine(agent_id="agent-a")
        proposal = engine.create_proposal(
            title="测试提案",
            config={"voters": ["agent-a", "agent-b"]},
        )

        engine.vote(proposal.proposal_id, "同意")

        import pytest

        with pytest.raises(ValueError, match="已投过票"):
            engine.vote(proposal.proposal_id, "反对")

    def test_vote_invalid_option(self):
        """测试无效选项"""
        engine = DecisionEngine(agent_id="agent-a")
        proposal = engine.create_proposal(
            title="测试提案",
            config={"voters": ["agent-a"]},
        )

        import pytest

        with pytest.raises(ValueError, match="无效选项"):
            engine.vote(proposal.proposal_id, "不存在的选项")

    def test_vote_not_in_voters(self):
        """测试无权投票"""
        engine = DecisionEngine(agent_id="agent-x")
        proposal = engine.create_proposal(
            title="测试提案",
            config={"voters": ["agent-a", "agent-b"]},
        )

        import pytest

        with pytest.raises(ValueError, match="无权投票"):
            engine.vote(proposal.proposal_id, "同意")

    def test_evaluate_majority_approved(self):
        """测试简单多数通过"""
        engine = DecisionEngine(agent_id="agent-a")
        proposal = engine.create_proposal(
            title="测试提案",
            config={
                "voters": ["agent-a", "agent-b", "agent-c"],
                "strategy": "majority",
                "quorum": 2,
            },
        )

        engine.vote(proposal.proposal_id, "同意")
        # 模拟agent-b投票
        engine.import_vote(
            proposal.proposal_id,
            {
                "vote_id": "vote-ext-1",
                "proposal_id": proposal.proposal_id,
                "voter": "agent-b",
                "option": "同意",
                "reason": "",
                "timestamp": time.time(),
            },
        )

        result = engine.evaluate(proposal.proposal_id)

        assert result.status == ProposalStatus.APPROVED
        assert result.winner == "同意"
        assert result.quorum_met is True
        assert result.total_votes == 2

    def test_evaluate_majority_rejected(self):
        """测试简单多数未通过"""
        engine = DecisionEngine(agent_id="agent-a")
        proposal = engine.create_proposal(
            title="测试提案",
            config={
                "voters": ["agent-a", "agent-b", "agent-c"],
                "strategy": "majority",
                "quorum": 2,
            },
        )

        engine.vote(proposal.proposal_id, "反对")
        engine.import_vote(
            proposal.proposal_id,
            {
                "vote_id": "vote-ext-1",
                "proposal_id": proposal.proposal_id,
                "voter": "agent-b",
                "option": "同意",
                "reason": "",
                "timestamp": time.time(),
            },
        )

        result = engine.evaluate(proposal.proposal_id)

        # 1票同意 vs 1票反对，同意不超半数
        assert result.status == ProposalStatus.REJECTED
        assert result.winner is None

    def test_evaluate_quorum_not_met(self):
        """测试未达法定人数"""
        engine = DecisionEngine(agent_id="agent-a")
        proposal = engine.create_proposal(
            title="测试提案",
            config={"voters": ["agent-a", "agent-b", "agent-c"], "quorum": 3},
        )

        engine.vote(proposal.proposal_id, "同意")
        result = engine.evaluate(proposal.proposal_id)

        assert result.quorum_met is False
        assert result.status == ProposalStatus.PENDING

    def test_evaluate_unanimous(self):
        """测试一致同意"""
        engine = DecisionEngine(agent_id="agent-a")
        proposal = engine.create_proposal(
            title="测试提案",
            config={"voters": ["agent-a", "agent-b"], "strategy": "unanimous", "quorum": 2},
        )

        engine.vote(proposal.proposal_id, "同意")
        engine.import_vote(
            proposal.proposal_id,
            {
                "vote_id": "vote-ext-1",
                "proposal_id": proposal.proposal_id,
                "voter": "agent-b",
                "option": "同意",
                "reason": "",
                "timestamp": time.time(),
            },
        )

        result = engine.evaluate(proposal.proposal_id)

        assert result.status == ProposalStatus.APPROVED
        assert result.winner == "同意"

    def test_evaluate_unanimous_fail(self):
        """测试一致同意失败"""
        engine = DecisionEngine(agent_id="agent-a")
        proposal = engine.create_proposal(
            title="测试提案",
            config={"voters": ["agent-a", "agent-b"], "strategy": "unanimous", "quorum": 2},
        )

        engine.vote(proposal.proposal_id, "同意")
        engine.import_vote(
            proposal.proposal_id,
            {
                "vote_id": "vote-ext-1",
                "proposal_id": proposal.proposal_id,
                "voter": "agent-b",
                "option": "反对",
                "reason": "",
                "timestamp": time.time(),
            },
        )

        result = engine.evaluate(proposal.proposal_id)

        assert result.status == ProposalStatus.REJECTED
        assert result.winner is None

    def test_evaluate_super_majority(self):
        """测试绝对多数（>2/3）"""
        engine = DecisionEngine(agent_id="agent-a")
        proposal = engine.create_proposal(
            title="测试提案",
            config={
                "voters": ["agent-a", "agent-b", "agent-c"],
                "strategy": "super_majority",
                "quorum": 3,
            },
        )

        engine.vote(proposal.proposal_id, "同意")
        engine.import_vote(
            proposal.proposal_id,
            {
                "vote_id": "vote-ext-1",
                "proposal_id": proposal.proposal_id,
                "voter": "agent-b",
                "option": "同意",
                "reason": "",
                "timestamp": time.time(),
            },
        )
        engine.import_vote(
            proposal.proposal_id,
            {
                "vote_id": "vote-ext-2",
                "proposal_id": proposal.proposal_id,
                "voter": "agent-c",
                "option": "反对",
                "reason": "",
                "timestamp": time.time(),
            },
        )

        result = engine.evaluate(proposal.proposal_id)

        # 2/3 = 66.7%，不超2/3
        assert result.status == ProposalStatus.REJECTED

    def test_evaluate_weighted(self):
        """测试加权投票"""
        engine = DecisionEngine(agent_id="agent-a")
        proposal = engine.create_proposal(
            title="测试提案",
            config={
                "voters": ["agent-a", "agent-b"],
                "strategy": "weighted",
                "quorum": 2,
                "weights": {"agent-a": 3.0, "agent-b": 1.0},
            },
        )

        engine.vote(proposal.proposal_id, "同意")
        engine.import_vote(
            proposal.proposal_id,
            {
                "vote_id": "vote-ext-1",
                "proposal_id": proposal.proposal_id,
                "voter": "agent-b",
                "option": "反对",
                "reason": "",
                "timestamp": time.time(),
            },
        )

        result = engine.evaluate(proposal.proposal_id)

        # agent-a权重3.0，agent-b权重1.0
        # 同意=3.0，反对=1.0，3.0 > 2.0
        assert result.status == ProposalStatus.APPROVED
        assert result.winner == "同意"

    def test_evaluate_veto(self):
        """测试一票否决"""
        engine = DecisionEngine(agent_id="agent-a")
        proposal = engine.create_proposal(
            title="测试提案",
            config={"voters": ["agent-a", "agent-b"], "strategy": "veto", "quorum": 2},
        )

        engine.vote(proposal.proposal_id, "同意")
        engine.import_vote(
            proposal.proposal_id,
            {
                "vote_id": "vote-ext-1",
                "proposal_id": proposal.proposal_id,
                "voter": "agent-b",
                "option": "反对",
                "reason": "",
                "timestamp": time.time(),
            },
        )

        result = engine.evaluate(proposal.proposal_id)

        # agent-b反对，一票否决
        assert result.status == ProposalStatus.REJECTED

    def test_evaluate_veto_pass(self):
        """测试一票否决通过"""
        engine = DecisionEngine(agent_id="agent-a")
        proposal = engine.create_proposal(
            title="测试提案",
            config={"voters": ["agent-a", "agent-b"], "strategy": "veto", "quorum": 2},
        )

        engine.vote(proposal.proposal_id, "同意")
        engine.import_vote(
            proposal.proposal_id,
            {
                "vote_id": "vote-ext-1",
                "proposal_id": proposal.proposal_id,
                "voter": "agent-b",
                "option": "同意",
                "reason": "",
                "timestamp": time.time(),
            },
        )

        result = engine.evaluate(proposal.proposal_id)

        assert result.status == ProposalStatus.APPROVED
        assert result.winner == "同意"

    def test_expired_proposal(self):
        """测试过期提案"""
        engine = DecisionEngine(agent_id="agent-a")
        proposal = engine.create_proposal(
            title="测试提案",
            config={"voters": ["agent-a"], "deadline_seconds": -1},
        )

        import pytest

        with pytest.raises(ValueError, match="已过期"):
            engine.vote(proposal.proposal_id, "同意")

    def test_cancel_proposal(self):
        """测试取消提案"""
        engine = DecisionEngine(agent_id="agent-a")
        proposal = engine.create_proposal(
            title="测试提案",
            config={"voters": ["agent-a"]},
        )

        engine.cancel_proposal(proposal.proposal_id)

        assert proposal.status == ProposalStatus.CANCELLED

    def test_cancel_by_non_initiator_fails(self):
        """测试非发起者取消"""
        engine_a = DecisionEngine(agent_id="agent-a")
        engine_b = DecisionEngine(agent_id="agent-b")

        proposal = engine_a.create_proposal(
            title="测试提案",
            config={"voters": ["agent-a", "agent-b"]},
        )

        # 导入到engine_b
        engine_b.import_proposal(engine_a.export_proposal(proposal.proposal_id))

        import pytest

        with pytest.raises(ValueError, match="只有发起者可以取消"):
            engine_b.cancel_proposal(proposal.proposal_id)

    def test_list_proposals(self):
        """测试列出提案"""
        engine = DecisionEngine(agent_id="agent-a")

        p1 = engine.create_proposal(
            title="提案1",
            config={"voters": ["agent-a"]},
        )
        p2 = engine.create_proposal(
            title="提案2",
            config={"voters": ["agent-a"]},
        )
        p3 = engine.create_proposal(
            title="提案3",
            config={"voters": ["agent-a"]},
        )

        # 取消一个
        engine.cancel_proposal(p3.proposal_id)

        all_proposals = engine.list_proposals()
        assert len(all_proposals) == 3

        pending = engine.list_proposals(status=ProposalStatus.PENDING)
        assert len(pending) == 2

        cancelled = engine.list_proposals(status=ProposalStatus.CANCELLED)
        assert len(cancelled) == 1

    def test_export_import_proposal(self):
        """测试导出导入提案"""
        engine_a = DecisionEngine(agent_id="agent-a")
        engine_b = DecisionEngine(agent_id="agent-b")

        proposal = engine_a.create_proposal(
            title="跨Agent提案",
            config={"voters": ["agent-a", "agent-b"]},
        )
        engine_a.vote(proposal.proposal_id, "同意")

        # 导出
        exported = engine_a.export_proposal(proposal.proposal_id)

        # 导入到engine_b
        imported = engine_b.import_proposal(exported)

        assert imported.proposal_id == proposal.proposal_id
        assert imported.title == "跨Agent提案"
        assert len(imported.votes) == 1

    def test_import_duplicate_vote(self):
        """测试导入重复投票"""
        engine = DecisionEngine(agent_id="agent-a")
        proposal = engine.create_proposal(
            title="测试提案",
            config={"voters": ["agent-a", "agent-b"]},
        )

        engine.vote(proposal.proposal_id, "同意")

        import pytest

        with pytest.raises(ValueError, match="投票者已投票"):
            engine.import_vote(
                proposal.proposal_id,
                {
                    "vote_id": "vote-ext-1",
                    "proposal_id": proposal.proposal_id,
                    "voter": "agent-a",
                    "option": "反对",
                    "reason": "",
                    "timestamp": time.time(),
                },
            )
