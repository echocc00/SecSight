"""仓储类 — 封装数据库访问,业务层不直接碰 ORM"""
from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import AuditLogModel, CaseModel, EvidencePackModel, PlaybookRunModel
from app.models.schemas import (
    Action,
    Alert,
    ApprovalRecord,
    AutonomyLevel,
    Case,
    CaseStatus,
    ExecutionStep,
    JudgmentReport,
)


class CaseRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def create(self, case: Case) -> Case:
        model = CaseModel(
            case_id=case.case_id,
            status=case.status.value,
            playbook_id=case.playbook_id,
            alerts=[a.model_dump(mode="json") for a in case.alerts],
            enriched_context=case.enriched_context,
            judgment=case.judgment.model_dump(mode="json") if case.judgment else None,
            proposed_actions=[a.model_dump(mode="json") for a in case.proposed_actions],
            approvals={k: v.model_dump(mode="json") for k, v in case.approvals.items()},
            execution_log=[e.model_dump(mode="json") for e in case.execution_log],
            evidence_pack_id=case.evidence_pack_id,
            autonomy_level_default=case.autonomy_level_default.value,
            created_at=case.created_at,
            updated_at=case.updated_at,
            tttr_seconds=case.tttr_seconds,
        )
        self.session.add(model)
        await self.session.commit()
        return case

    async def get(self, case_id: str) -> Case | None:
        model = await self.session.get(CaseModel, case_id)
        if not model:
            return None
        return self._to_domain(model)

    async def list(self, limit: int = 50, status: str | None = None) -> list[Case]:
        stmt = select(CaseModel).order_by(CaseModel.created_at.desc()).limit(limit)
        if status:
            stmt = stmt.where(CaseModel.status == status)
        result = await self.session.execute(stmt)
        return [self._to_domain(m) for m in result.scalars()]

    async def update_status(self, case_id: str, status: CaseStatus) -> None:
        model = await self.session.get(CaseModel, case_id)
        if model:
            model.status = status.value
            model.updated_at = datetime.utcnow()
            await self.session.commit()

    async def update_judgment(self, case_id: str, judgment: JudgmentReport) -> None:
        model = await self.session.get(CaseModel, case_id)
        if model:
            model.judgment = judgment.model_dump(mode="json")
            model.updated_at = datetime.utcnow()
            await self.session.commit()

    async def update_actions(self, case_id: str, actions: list[Action]) -> None:
        model = await self.session.get(CaseModel, case_id)
        if model:
            model.proposed_actions = [a.model_dump(mode="json") for a in actions]
            model.updated_at = datetime.utcnow()
            await self.session.commit()

    async def add_approval(self, case_id: str, approval: ApprovalRecord) -> None:
        model = await self.session.get(CaseModel, case_id)
        if model:
            approvals = dict(model.approvals or {})
            approvals[approval.action_id] = approval.model_dump(mode="json")
            model.approvals = approvals
            model.updated_at = datetime.utcnow()
            await self.session.commit()

    async def append_execution(self, case_id: str, step: ExecutionStep) -> None:
        model = await self.session.get(CaseModel, case_id)
        if model:
            log = list(model.execution_log or [])
            log.append(step.model_dump(mode="json"))
            model.execution_log = log
            model.updated_at = datetime.utcnow()
            await self.session.commit()

    async def set_evidence_pack(self, case_id: str, pack_id: str) -> None:
        model = await self.session.get(CaseModel, case_id)
        if model:
            model.evidence_pack_id = pack_id
            model.updated_at = datetime.utcnow()
            await self.session.commit()

    async def close(self, case_id: str, tttr_seconds: int) -> None:
        model = await self.session.get(CaseModel, case_id)
        if model:
            model.status = CaseStatus.resolved.value
            model.tttr_seconds = tttr_seconds
            model.updated_at = datetime.utcnow()
            await self.session.commit()

    async def create_from_alert(self, alert: Alert) -> Case:
        case = Case(
            case_id=str(uuid4()),
            status=CaseStatus.open,
            alerts=[alert],
            created_at=alert.ts,
        )
        await self.create(case)
        return case

    def _to_domain(self, model: CaseModel) -> Case:
        return Case(
            case_id=model.case_id,
            status=CaseStatus(model.status),
            alerts=[Alert(**a) for a in (model.alerts or [])],
            playbook_id=model.playbook_id,
            enriched_context=model.enriched_context or {},
            judgment=JudgmentReport(**model.judgment) if model.judgment else None,
            proposed_actions=[Action(**a) for a in (model.proposed_actions or [])],
            approvals={
                k: ApprovalRecord(**v)
                for k, v in (model.approvals or {}).items()
            },
            execution_log=[ExecutionStep(**e) for e in (model.execution_log or [])],
            evidence_pack_id=model.evidence_pack_id,
            autonomy_level_default=AutonomyLevel(model.autonomy_level_default),
            created_at=model.created_at,
            updated_at=model.updated_at,
            tttr_seconds=model.tttr_seconds,
        )


class EvidencePackRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def create(self, pack: dict) -> str:
        pack_id = pack.get("pack_id") or str(uuid4())
        model = EvidencePackModel(
            pack_id=pack_id,
            case_id=pack["case_id"],
            process_tree=pack.get("process_tree", {}),
            timeline=pack.get("timeline", []),
            llm_reasoning_trace=pack.get("llm_reasoning_trace", []),
            iocs=pack.get("iocs", {}),
            mitre_mapping=pack.get("mitre_mapping", {}),
        )
        self.session.add(model)
        await self.session.commit()
        return pack_id

    async def get_by_case(self, case_id: str) -> dict | None:
        stmt = select(EvidencePackModel).where(
            EvidencePackModel.case_id == case_id
        )
        result = await self.session.execute(stmt)
        m = result.scalars().first()
        if not m:
            return None
        return {
            "pack_id": m.pack_id,
            "case_id": m.case_id,
            "process_tree": m.process_tree,
            "timeline": m.timeline,
            "llm_reasoning_trace": m.llm_reasoning_trace,
            "iocs": m.iocs,
            "mitre_mapping": m.mitre_mapping,
            "created_at": m.created_at,
        }


class AuditLogRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def record(
        self, action: str, actor: str, case_id: str | None = None, detail: dict | None = None
    ) -> None:
        model = AuditLogModel(
            case_id=case_id,
            action=action,
            actor=actor,
            detail=detail or {},
        )
        self.session.add(model)
        await self.session.commit()

    async def list_by_case(self, case_id: str) -> list[dict]:
        stmt = (
            select(AuditLogModel)
            .where(AuditLogModel.case_id == case_id)
            .order_by(AuditLogModel.ts)
        )
        result = await self.session.execute(stmt)
        return [
            {
                "action": m.action,
                "actor": m.actor,
                "detail": m.detail,
                "ts": m.ts,
            }
            for m in result.scalars()
        ]
