"""审批服务 — L2 真正双签多记录

双签规则:
  - L2 动作需 incident_commander + approver 两个不同角色都 approved
  - 高危动作 (isolate_host/block_ip 等) 需 + ciso_or_delegate (三签)
  - 同角色重复审批被拒 (防同人刷)
  - 任一 rejected → 该动作拒绝
"""
from __future__ import annotations

from datetime import datetime

from app.db.database import async_session
from app.db.repositories import ApprovalRecordRepository, AuditLogRepository, CaseRepository
from app.models.schemas import AutonomyLevel, CaseStatus

import structlog

log = structlog.get_logger()

# 双签角色要求
DOUBLE_SIGN_ROLES = {"incident_commander", "approver"}
# 高危三签 (整机隔离/全网封禁等)
CRITICAL_ACTIONS = {"isolate_host", "block_ip", "block_domain", "freeze_account"}
CRITICAL_TRIPLE_ROLES = {"incident_commander", "approver", "ciso_or_delegate"}


class ApprovalError(Exception):
    pass


class ApprovalService:
    async def submit_approval(
        self,
        case_id: str,
        action_id: str,
        approver_role: str,
        approver_user: str,
        decision: str,
        comment: str = "",
    ) -> dict:
        """提交单个审批 (多记录,双签判定)"""
        async with async_session() as session:
            repo = CaseRepository(session)
            case = await repo.get(case_id)
            if not case:
                raise ApprovalError("Case not found")

            action = next(
                (a for a in case.proposed_actions if a.action_id == action_id), None
            )
            if not action:
                raise ApprovalError(f"Action {action_id} not found in case")

            if not action.approval_required:
                raise ApprovalError(
                    f"Action {action_id} 无需审批 (autonomy={action.autonomy_level.value})"
                )

            record_repo = ApprovalRecordRepository(session)

            # 防同人重复: 同角色同 action 已审批过则拒
            if await record_repo.has_role_approved(case_id, action_id, approver_role):
                raise ApprovalError(
                    f"角色 {approver_role} 已审批过 action {action_id[:8]}"
                )

            # 记录审批
            await record_repo.add(
                case_id=case_id,
                action_id=action_id,
                approver_role=approver_role,
                approver_user=approver_user,
                decision=decision,
                comment=comment,
            )

            audit = AuditLogRepository(session)
            await audit.record(
                action=f"approval:{decision}",
                actor=approver_user,
                case_id=case_id,
                detail={"action_id": action_id, "role": approver_role, "comment": comment},
            )

            # 判定该 action 是否完成双签
            action_fully_approved = await self._check_action_fully_approved(
                record_repo, case_id, action_id, action
            )
            all_approved = await self._check_all_approved(record_repo, case)

            if all_approved:
                await repo.update_status(case_id, CaseStatus.investigating)
                log.info("approval.all_approved", case_id=case_id, action_id=action_id)
                return {
                    "action_status": "approved" if action_fully_approved else "pending",
                    "case_status": "ready_to_execute",
                    "all_approved": True,
                }

            return {
                "action_status": "approved" if action_fully_approved else "pending",
                "case_status": "pending_approval",
                "all_approved": False,
            }

    async def _check_action_fully_approved(
        self,
        record_repo: ApprovalRecordRepository,
        case_id: str,
        action_id: str,
        action,
    ) -> bool:
        """检查单个 action 是否完成双签/三签"""
        records = await record_repo.list_by_action(case_id, action_id)
        if not records:
            return False
        # 任一 rejected → 拒绝
        if any(r["decision"] == "rejected" for r in records):
            return False
        # 需要的角色集
        action_type = action.action_type.value
        required_roles = (
            CRITICAL_TRIPLE_ROLES
            if action_type in CRITICAL_ACTIONS
            else DOUBLE_SIGN_ROLES
        )
        approved_roles = {
            r["approver_role"] for r in records if r["decision"] == "approved"
        }
        return required_roles.issubset(approved_roles)

    async def _check_all_approved(
        self, record_repo: ApprovalRecordRepository, case
    ) -> bool:
        """所有 L2 动作都完成双签 → True"""
        l2_actions = [a for a in case.proposed_actions if a.approval_required]
        if not l2_actions:
            return True
        for a in l2_actions:
            if not await self._check_action_fully_approved(
                record_repo, case.case_id, a.action_id, a
            ):
                return False
        return True


approval_service = ApprovalService()
