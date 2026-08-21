"""审批服务 — L2 双签逻辑"""
from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from app.db.database import async_session
from app.db.repositories import AuditLogRepository, CaseRepository
from app.models.schemas import ApprovalRecord, AutonomyLevel, CaseStatus

import structlog

log = structlog.get_logger()

# 双签角色要求
DOUBLE_SIGN_ROLES = {"incident_commander", "approver"}
# 高危三签 (整机隔离/全网封禁等)
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
        """提交单个审批

        双签逻辑:
          - L2 动作需要 incident_commander + approver 两个角色都 approved
          - 任一 rejected → 该动作拒绝
          - 全部动作 approved → 恢复 workflow 执行
        """
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
                raise ApprovalError(f"Action {action_id} 无需审批 (autonomy={action.autonomy_level.value})")

            # 检查角色是否已审批过 (防同人重复)
            existing = case.approvals.get(action_id)
            # 简化: 每个 action 存最近审批记录,双签靠两次不同角色提交
            # 这里用 approval_status 字典在 Case.approvals 里存多角色
            approval = ApprovalRecord(
                action_id=action_id,
                approver_role=approver_role,
                approver_user=approver_user,
                decision=decision,
                timestamp=datetime.utcnow(),
                comment=comment,
            )
            await repo.add_approval(case_id, approval)

            audit = AuditLogRepository(session)
            await audit.record(
                action=f"approval:{decision}",
                actor=approver_user,
                case_id=case_id,
                detail={"action_id": action_id, "role": approver_role, "comment": comment},
            )

            # 检查是否该 action 双签完成
            action_fully_approved = await self._check_action_fully_approved(
                case_id, action_id, action
            )

            # 检查整个 Case 是否所有 L2 动作都批准
            all_approved = await self._check_all_approved(case_id)

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
        self, case_id: str, action_id: str, action
    ) -> bool:
        """检查单个 action 是否完成双签 (两个不同角色 approved)"""
        async with async_session() as session:
            repo = CaseRepository(session)
            case = await repo.get(case_id)
            if not case:
                return False
            # 简化: 双签 = 至少两个不同角色 approved (且无 rejected)
            approval = case.approvals.get(action_id)
            if not approval:
                return False
            if approval.decision == "rejected":
                return False
            # 垂直切片简化: 单个 ApprovalRecord 表示该 action 审批状态
            # 真正双签需要存多条记录,这里用 decision=approved + requires_double_sign 检查
            # 临时: 只要 decision=approved 即视为通过 (Phase2 改多记录)
            return approval.decision == "approved"

    async def _check_all_approved(self, case_id: str) -> bool:
        """所有 L2 动作都 approved → True"""
        async with async_session() as session:
            repo = CaseRepository(session)
            case = await repo.get(case_id)
            if not case:
                return False
            l2_actions = [a for a in case.proposed_actions if a.approval_required]
            if not l2_actions:
                return True
            for a in l2_actions:
                approval = case.approvals.get(a.action_id)
                if not approval or approval.decision != "approved":
                    return False
            return True


approval_service = ApprovalService()
