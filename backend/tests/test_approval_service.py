"""审批服务测试 — L2 双签逻辑 + 错误路径 (安全关键)"""
from __future__ import annotations

import pytest

from app.approvals.service import ApprovalError, approval_service
from app.db.repositories import CaseRepository
from app.mock.alerts import xmrig_process_alert
from app.models.schemas import Action, ActionType, AutonomyLevel, CaseStatus, Severity


async def _create_case_with_l2_action(db_session) -> tuple[str, str]:
    """建一个含 L2 动作的 Case,返回 (case_id, action_id)"""
    repo = CaseRepository(db_session)
    case = await repo.create_from_alert(xmrig_process_alert())
    action = Action(
        action_type=ActionType.isolate_host,
        target={"ip": "10.0.1.15"},
        autonomy_level=AutonomyLevel.L2,
        risk=Severity.high,
        approval_required=True,
        requires_double_sign=True,
    )
    await repo.update_actions(case.case_id, [action])
    await repo.update_status(case.case_id, CaseStatus.pending_approval)
    return case.case_id, action.action_id


class TestSubmitApprovalSuccess:
    @pytest.mark.asyncio
    async def test_approve_l2_action_records_decision(self, db_session):
        case_id, action_id = await _create_case_with_l2_action(db_session)
        result = await approval_service.submit_approval(
            case_id, action_id, "incident_commander", "alice", "approved"
        )
        assert result["action_status"] == "approved"
        assert result["all_approved"] is True  # 唯一 L2 动作批准 → 全批准

    @pytest.mark.asyncio
    async def test_all_approved_sets_status_investigating(self, db_session):
        case_id, action_id = await _create_case_with_l2_action(db_session)
        await approval_service.submit_approval(
            case_id, action_id, "approver", "bob", "approved"
        )
        repo = CaseRepository(db_session)
        case = await repo.get(case_id)
        assert case.status == CaseStatus.investigating


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


class TestCheckAllApproved:
    @pytest.mark.asyncio
    async def test_returns_true_when_no_l2_actions(self, db_session):
        repo = CaseRepository(db_session)
        case = await repo.create_from_alert(xmrig_process_alert())
        assert await approval_service._check_all_approved(case.case_id) is True

    @pytest.mark.asyncio
    async def test_returns_false_when_l2_pending(self, db_session):
        case_id, _ = await _create_case_with_l2_action(db_session)
        assert await approval_service._check_all_approved(case_id) is False

    @pytest.mark.asyncio
    async def test_returns_false_for_nonexistent_case(self):
        assert await approval_service._check_all_approved("ghost") is False
