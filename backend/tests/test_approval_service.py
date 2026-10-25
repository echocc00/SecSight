"""审批服务测试 — L2 真正双签多记录"""
from __future__ import annotations

import pytest

from app.approvals.service import ApprovalError, approval_service
from app.db.repositories import ApprovalRecordRepository, CaseRepository
from app.mock.alerts import xmrig_process_alert
from app.models.schemas import Action, ActionType, AutonomyLevel, CaseStatus, Severity


async def _create_case_with_l2_action(db_session) -> tuple[str, str]:
    """建一个含单个 L2 动作 (query_asset,非高危) 的 Case"""
    repo = CaseRepository(db_session)
    case = await repo.create_from_alert(xmrig_process_alert())
    action = Action(
        action_type=ActionType.query_asset,  # 非高危,双签即可
        target={"ip": "10.0.1.15"},
        autonomy_level=AutonomyLevel.L2,
        risk=Severity.medium,
        approval_required=True,
        requires_double_sign=True,
    )
    await repo.update_actions(case.case_id, [action])
    await repo.update_status(case.case_id, CaseStatus.pending_approval)
    return case.case_id, action.action_id


class TestDoubleSign:
    @pytest.mark.asyncio
    async def test_single_role_not_fully_approved(self, db_session):
        """单角色审批 → action_status=pending, all_approved=False"""
        case_id, action_id = await _create_case_with_l2_action(db_session)
        result = await approval_service.submit_approval(
            case_id, action_id, "incident_commander", "alice", "approved"
        )
        assert result["action_status"] == "pending"
        assert result["all_approved"] is False

    @pytest.mark.asyncio
    async def test_two_roles_fully_approved(self, db_session):
        """两角色都 approved → fully approved"""
        case_id, action_id = await _create_case_with_l2_action(db_session)
        await approval_service.submit_approval(
            case_id, action_id, "incident_commander", "alice", "approved"
        )
        result = await approval_service.submit_approval(
            case_id, action_id, "approver", "bob", "approved"
        )
        assert result["action_status"] == "approved"
        assert result["all_approved"] is True

    @pytest.mark.asyncio
    async def test_all_approved_sets_status_investigating(self, db_session):
        case_id, action_id = await _create_case_with_l2_action(db_session)
        await approval_service.submit_approval(
            case_id, action_id, "incident_commander", "alice", "approved"
        )
        await approval_service.submit_approval(
            case_id, action_id, "approver", "bob", "approved"
        )
        repo = CaseRepository(db_session)
        case = await repo.get(case_id)
        assert case.status == CaseStatus.investigating


class TestDuplicateRoleRejection:
    @pytest.mark.asyncio
    async def test_same_role_cannot_approve_twice(self, db_session):
        """同角色重复审批被拒"""
        case_id, action_id = await _create_case_with_l2_action(db_session)
        await approval_service.submit_approval(
            case_id, action_id, "incident_commander", "alice", "approved"
        )
        with pytest.raises(ApprovalError, match="已审批过"):
            await approval_service.submit_approval(
                case_id, action_id, "incident_commander", "alice2", "approved"
            )


class TestRejection:
    @pytest.mark.asyncio
    async def test_rejection_closes_case(self, db_session):
        """任一 rejected → 拒绝终态: Case 关闭,永不满足 all_approved

        v0.6.2 起 rejected 是 Case 级终态 (防止已闭环案件被补签复活),
        拒绝后不再吸收任何新签名。
        """
        case_id, action_id = await _create_case_with_l2_action(db_session)
        await approval_service.submit_approval(
            case_id, action_id, "incident_commander", "alice", "approved"
        )
        result = await approval_service.submit_approval(
            case_id, action_id, "approver", "bob", "rejected"
        )
        assert result["action_status"] == "rejected"
        assert result["all_approved"] is False
        assert result["rejected"] is True
        case = await CaseRepository(db_session).get(case_id)
        assert case.status == CaseStatus.resolved

    @pytest.mark.asyncio
    async def test_no_signature_after_rejection(self, db_session):
        """拒绝后 (Case 已闭环) 再提交任何审批 → ApprovalError"""
        case_id, action_id = await _create_case_with_l2_action(db_session)
        await approval_service.submit_approval(
            case_id, action_id, "incident_commander", "alice", "rejected"
        )
        with pytest.raises(ApprovalError, match="已闭环"):
            await approval_service.submit_approval(
                case_id, action_id, "approver", "bob", "approved"
            )


class TestSubmitApprovalErrors:
    @pytest.mark.asyncio
    async def test_raises_for_nonexistent_case(self):
        with pytest.raises(ApprovalError, match="Case not found"):
            await approval_service.submit_approval(
                "no-such-case", "x", "approver", "u", "approved"
            )

    @pytest.mark.asyncio
    async def test_raises_for_unknown_action(self, db_session):
        case_id, _ = await _create_case_with_l2_action(db_session)
        with pytest.raises(ApprovalError, match="not found in case"):
            await approval_service.submit_approval(
                case_id, "nonexistent-action", "approver", "u", "approved"
            )

    @pytest.mark.asyncio
    async def test_raises_when_action_not_requiring_approval(self, db_session):
        repo = CaseRepository(db_session)
        case = await repo.create_from_alert(xmrig_process_alert())
        l4_action = Action(
            action_type=ActionType.query_asset,
            target={},
            autonomy_level=AutonomyLevel.L4,
            approval_required=False,
        )
        await repo.update_actions(case.case_id, [l4_action])
        with pytest.raises(ApprovalError, match="无需审批"):
            await approval_service.submit_approval(
                case.case_id, l4_action.action_id, "approver", "u", "approved"
            )


class TestApprovalRecords:
    @pytest.mark.asyncio
    async def test_records_persisted(self, db_session):
        case_id, action_id = await _create_case_with_l2_action(db_session)
        await approval_service.submit_approval(
            case_id, action_id, "incident_commander", "alice", "approved", "ok"
        )
        record_repo = ApprovalRecordRepository(db_session)
        records = await record_repo.list_by_action(case_id, action_id)
        assert len(records) == 1
        assert records[0]["approver_role"] == "incident_commander"
        assert records[0]["decision"] == "approved"

    @pytest.mark.asyncio
    async def test_count_approvals(self, db_session):
        case_id, action_id = await _create_case_with_l2_action(db_session)
        record_repo = ApprovalRecordRepository(db_session)
        await approval_service.submit_approval(
            case_id, action_id, "incident_commander", "a", "approved"
        )
        assert await record_repo.count_approvals(case_id, action_id) == 1
        await approval_service.submit_approval(
            case_id, action_id, "approver", "b", "approved"
        )
        assert await record_repo.count_approvals(case_id, action_id) == 2
