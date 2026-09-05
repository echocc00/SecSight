"""仓储类 — 封装数据库访问,业务层不直接碰 ORM"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import (
    ApprovalRecordModel,
    AuditLogModel,
    CaseModel,
    EvidencePackModel,
    PlaybookRunModel,
    ProactiveRunModel,
    RefreshTokenModel,
    UserModel,
)
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

# 可聚合状态: 已 resolved/closed 的 Case 不再吸收新告警
_AGGREGATABLE_STATUSES = (
    CaseStatus.open.value,
    CaseStatus.investigating.value,
    CaseStatus.pending_approval.value,
    CaseStatus.contained.value,
)


def compute_agg_key(alert: Alert) -> str:
    """告警聚合键 = (规则, 主机, 源IP) 的短哈希

    同一条规则在同一主机上被同一来源反复触发,视为同一事件的多次上报
    (典型场景: 挖矿进程被反复检测、扫描器持续探测)。不含时间戳,窗口由
    查询侧控制。
    """
    parts = [
        alert.rule_id or "",
        alert.asset.hostname or alert.asset.host_id or "",
        alert.src_ip or "",
    ]
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:32]


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

    async def update_enriched_context(self, case_id: str, context: dict) -> None:
        model = await self.session.get(CaseModel, case_id)
        if model:
            model.enriched_context = context
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
        model = await self.session.get(CaseModel, case.case_id)
        if model:
            model.agg_key = compute_agg_key(alert)
            await self.session.commit()
        return case

    async def find_open_case_for_alert(
        self, alert: Alert, window_minutes: int
    ) -> CaseModel | None:
        """查窗口内同 agg_key 的未闭环 Case

        resolved/closed 不参与聚合 —— 攻击复现应开新 Case,否则已归档的
        证据包会被后续告警污染,TTTR 也失真。
        """
        from datetime import timedelta

        since = datetime.utcnow() - timedelta(minutes=window_minutes)
        stmt = (
            select(CaseModel)
            .where(
                CaseModel.agg_key == compute_agg_key(alert),
                CaseModel.status.in_(_AGGREGATABLE_STATUSES),
                CaseModel.updated_at >= since,
            )
            .order_by(CaseModel.updated_at.desc())
            .limit(1)
        )
        result = await self.session.execute(stmt)
        return result.scalars().first()

    async def append_alert(self, case_id: str, alert: Alert) -> int:
        """把告警并入现有 Case,返回并入后的告警总数"""
        model = await self.session.get(CaseModel, case_id)
        if not model:
            return 0
        alerts = list(model.alerts or [])
        alerts.append(alert.model_dump(mode="json"))
        model.alerts = alerts
        model.alert_count = len(alerts)
        model.updated_at = datetime.utcnow()
        await self.session.commit()
        return model.alert_count

    async def ingest_alert(self, alert: Alert) -> tuple[Case, bool]:
        """告警入库入口: 窗口内同源告警并入现有 Case,否则建新 Case

        返回 (case, deduped)。deduped=True 时调用方不应再触发编排 —— 同一 Case
        已有 workflow 在跑,重复触发会产生重复处置动作。
        """
        from app.core.config import settings

        if settings.enable_alert_dedup:
            existing = await self.find_open_case_for_alert(
                alert, settings.alert_dedup_window_minutes
            )
            if existing:
                await self.append_alert(existing.case_id, alert)
                refreshed = await self.session.get(CaseModel, existing.case_id)
                return self._to_domain(refreshed), True

        return await self.create_from_alert(alert), False

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
            compliance=pack.get("compliance", {}),
            escalation=pack.get("escalation", {}),
            ir_decision=pack.get("ir_decision", {}),
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
            "compliance": m.compliance,
            "escalation": m.escalation,
            "ir_decision": m.ir_decision,
            "created_at": m.created_at,
        }


class AuditLogRepository:
    """审计日志仓储 — hash chain 防篡改 (等保2.0三级)

    每条记录含前一条的 entry_hash。篡改/删除任一条会导致后续链断裂,
    verify_chain() 可检测并定位断点。
    """

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    @staticmethod
    def _compute_hash(
        seq: int,
        case_id: str | None,
        action: str,
        actor: str,
        detail: dict,
        ts: datetime,
        prev_hash: str,
    ) -> str:
        """规范化 JSON → SHA256 (sort_keys 保证可重算)"""
        payload = {
            "seq": seq,
            "case_id": case_id,
            "action": action,
            "actor": actor,
            "detail": detail,
            "ts": ts.isoformat(),
            "prev_hash": prev_hash,
        }
        canonical = json.dumps(
            payload, sort_keys=True, ensure_ascii=False, separators=(",", ":")
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    async def record(
        self, action: str, actor: str, case_id: str | None = None, detail: dict | None = None
    ) -> None:
        # 取链尾 (SELECT ... FOR UPDATE 防并发断链;SQLite 无行锁但单写入器)
        stmt = select(AuditLogModel).order_by(AuditLogModel.seq.desc()).limit(1)
        if self.session.bind and self.session.bind.dialect.name == "postgresql":
            stmt = stmt.with_for_update()
        last = (await self.session.execute(stmt)).scalars().first()

        seq = (last.seq + 1) if last else 1
        prev_hash = last.entry_hash if last and last.entry_hash else "0" * 64
        ts = datetime.utcnow()
        detail = detail or {}
        entry_hash = self._compute_hash(
            seq, case_id, action, actor, detail, ts, prev_hash
        )

        model = AuditLogModel(
            case_id=case_id,
            action=action,
            actor=actor,
            detail=detail,
            ts=ts,
            seq=seq,
            prev_hash=prev_hash,
            entry_hash=entry_hash,
        )
        self.session.add(model)
        await self.session.commit()

    async def verify_chain(self) -> dict:
        """重算全链 hash,定位断链位置 (等保合规检查项)"""
        logs = (
            await self.session.execute(
                select(AuditLogModel).order_by(AuditLogModel.seq)
            )
        ).scalars().all()

        prev = "0" * 64
        expected_seq = 1
        for entry in logs:
            if entry.seq != expected_seq:
                return {
                    "valid": False,
                    "broken_at_seq": entry.seq,
                    "reason": f"seq 不连续 (期望 {expected_seq},实际 {entry.seq}) — 记录被删除",
                    "verified_count": expected_seq - 1,
                }
            if entry.prev_hash != prev:
                return {
                    "valid": False,
                    "broken_at_seq": entry.seq,
                    "reason": "prev_hash 不匹配 — 前序记录被篡改",
                    "verified_count": expected_seq - 1,
                }
            recomputed = self._compute_hash(
                entry.seq, entry.case_id, entry.action, entry.actor,
                entry.detail or {}, entry.ts, entry.prev_hash,
            )
            if recomputed != entry.entry_hash:
                return {
                    "valid": False,
                    "broken_at_seq": entry.seq,
                    "reason": "entry_hash 不匹配 — 本条记录被篡改",
                    "verified_count": expected_seq - 1,
                }
            prev = entry.entry_hash
            expected_seq += 1

        return {
            "valid": True,
            "verified_count": len(logs),
            "chain_head": prev,
        }

    async def list_by_case(self, case_id: str) -> list[dict]:
        stmt = (
            select(AuditLogModel)
            .where(AuditLogModel.case_id == case_id)
            .order_by(AuditLogModel.ts)
        )
        result = await self.session.execute(stmt)
        return [self._to_dict(m) for m in result.scalars()]

    async def list_recent(self, limit: int = 100) -> list[dict]:
        stmt = select(AuditLogModel).order_by(AuditLogModel.seq.desc()).limit(limit)
        result = await self.session.execute(stmt)
        return [self._to_dict(m) for m in result.scalars()]

    @staticmethod
    def _to_dict(m: AuditLogModel) -> dict:
        return {
            "seq": m.seq,
            "case_id": m.case_id,
            "action": m.action,
            "actor": m.actor,
            "detail": m.detail,
            "ts": m.ts,
            "prev_hash": m.prev_hash,
            "entry_hash": m.entry_hash,
        }


class UserRepository:
    """用户仓储 — 替代内存字典,支持持久化"""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def create(
        self,
        username: str,
        hashed_password: str,
        role: str,
        email: str | None = None,
    ) -> dict:
        model = UserModel(
            username=username,
            hashed_password=hashed_password,
            role=role,
            email=email,
        )
        self.session.add(model)
        await self.session.commit()
        return {"username": username, "role": role, "email": email}

    async def get_by_username(self, username: str) -> dict | None:
        model = await self.session.get(UserModel, username)
        if not model:
            return None
        return {
            "username": model.username,
            "hashed_password": model.hashed_password,
            "role": model.role,
            "email": model.email,
            "is_active": model.is_active,
            "last_login_at": model.last_login_at,
        }

    async def list(self) -> list[dict]:
        stmt = select(UserModel).order_by(UserModel.created_at)
        result = await self.session.execute(stmt)
        return [
            {
                "username": m.username,
                "role": m.role,
                "email": m.email,
                "is_active": m.is_active,
                "created_at": m.created_at,
                "last_login_at": m.last_login_at,
            }
            for m in result.scalars()
        ]

    async def update_last_login(self, username: str) -> None:
        model = await self.session.get(UserModel, username)
        if model:
            model.last_login_at = datetime.utcnow()
            await self.session.commit()

    async def seed_defaults(self) -> int:
        """种子默认用户 (首次启动),返回创建数

        密码来源优先级: SEED_USER_PASSWORD > 开发默认值 > 随机生成。
        生产未配置时生成随机密码并写日志一次 —— 绝不能让所有部署共用同一
        个已进公开仓库的默认口令。
        """
        import secrets

        import structlog

        from app.auth.service import Role, hash_password
        from app.core.config import settings

        password = settings.seed_user_password
        generated = False
        if not password:
            if settings.env == "production":
                password = secrets.token_urlsafe(16)
                generated = True
            else:
                password = "ChangeMe_123!"

        roles = [
            ("admin", Role.ADMIN),
            ("analyst", Role.ANALYST),
            ("approver", Role.APPROVER),
            ("viewer", Role.VIEWER),
        ]
        created = 0
        for username, role in roles:
            existing = await self.get_by_username(username)
            if existing:
                continue
            await self.create(
                username=username,
                hashed_password=hash_password(password),
                role=role.value,
            )
            created += 1

        if created and generated:
            structlog.get_logger().warning(
                "user.seed.random_password_generated",
                password=password,
                hint="立即登录改密;此口令只打印这一次,未配置 SEED_USER_PASSWORD",
            )
        return created


class ApprovalRecordRepository:
    """审批记录仓储 — 支持双签多记录"""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def add(
        self,
        case_id: str,
        action_id: str,
        approver_role: str,
        approver_user: str,
        decision: str,
        comment: str = "",
    ) -> dict:
        model = ApprovalRecordModel(
            case_id=case_id,
            action_id=action_id,
            approver_role=approver_role,
            approver_user=approver_user,
            decision=decision,
            comment=comment,
        )
        self.session.add(model)
        await self.session.commit()
        return {
            "id": model.id,
            "action_id": action_id,
            "approver_role": approver_role,
            "approver_user": approver_user,
            "decision": decision,
            "comment": comment,
            "ts": model.ts,
        }

    async def list_by_action(self, case_id: str, action_id: str) -> list[dict]:
        stmt = (
            select(ApprovalRecordModel)
            .where(
                ApprovalRecordModel.case_id == case_id,
                ApprovalRecordModel.action_id == action_id,
            )
            .order_by(ApprovalRecordModel.ts)
        )
        result = await self.session.execute(stmt)
        return [
            {
                "id": m.id,
                "approver_role": m.approver_role,
                "approver_user": m.approver_user,
                "decision": m.decision,
                "comment": m.comment,
                "ts": m.ts,
            }
            for m in result.scalars()
        ]

    async def list_by_case(self, case_id: str) -> list[dict]:
        stmt = (
            select(ApprovalRecordModel)
            .where(ApprovalRecordModel.case_id == case_id)
            .order_by(ApprovalRecordModel.ts)
        )
        result = await self.session.execute(stmt)
        return [
            {
                "action_id": m.action_id,
                "approver_role": m.approver_role,
                "approver_user": m.approver_user,
                "decision": m.decision,
                "comment": m.comment,
                "ts": m.ts,
            }
            for m in result.scalars()
        ]

    async def has_role_approved(
        self, case_id: str, action_id: str, role: str
    ) -> bool:
        """检查指定角色是否已 approved 该动作"""
        stmt = select(ApprovalRecordModel).where(
            ApprovalRecordModel.case_id == case_id,
            ApprovalRecordModel.action_id == action_id,
            ApprovalRecordModel.approver_role == role,
            ApprovalRecordModel.decision == "approved",
        )
        result = await self.session.execute(stmt)
        return result.scalars().first() is not None

    async def count_approvals(self, case_id: str, action_id: str) -> int:
        """统计 approved 数量 (双签判定)"""
        stmt = select(ApprovalRecordModel).where(
            ApprovalRecordModel.case_id == case_id,
            ApprovalRecordModel.action_id == action_id,
            ApprovalRecordModel.decision == "approved",
        )
        result = await self.session.execute(stmt)
        return len(result.scalars().all())


class ProactiveRunRepository:
    """Proactive Agent 执行记录仓储"""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def create(
        self,
        run_id: str,
        agent_name: str,
        trigger: str,
        status: str,
        findings_count: int,
        cases_created: int,
        result: dict,
        error: str | None,
        started_at: datetime,
        finished_at: datetime,
    ) -> None:
        self.session.add(
            ProactiveRunModel(
                run_id=run_id,
                agent_name=agent_name,
                trigger=trigger,
                status=status,
                findings_count=findings_count,
                cases_created=cases_created,
                result=result,
                error=error,
                started_at=started_at,
                finished_at=finished_at,
            )
        )
        await self.session.commit()

    async def list(
        self, limit: int = 50, agent_name: str | None = None
    ) -> list[dict]:
        stmt = (
            select(ProactiveRunModel)
            .order_by(ProactiveRunModel.started_at.desc())
            .limit(limit)
        )
        if agent_name:
            stmt = stmt.where(ProactiveRunModel.agent_name == agent_name)
        result = await self.session.execute(stmt)
        return [
            {
                "run_id": m.run_id,
                "agent_name": m.agent_name,
                "trigger": m.trigger,
                "status": m.status,
                "findings_count": m.findings_count,
                "cases_created": m.cases_created,
                "error": m.error,
                "started_at": m.started_at,
                "finished_at": m.finished_at,
            }
            for m in result.scalars()
        ]

    async def get(self, run_id: str) -> dict | None:
        m = await self.session.get(ProactiveRunModel, run_id)
        if not m:
            return None
        return {
            "run_id": m.run_id,
            "agent_name": m.agent_name,
            "trigger": m.trigger,
            "status": m.status,
            "findings_count": m.findings_count,
            "cases_created": m.cases_created,
            "result": m.result,
            "error": m.error,
            "started_at": m.started_at,
            "finished_at": m.finished_at,
        }


class RefreshTokenRepository:
    """Refresh token 仓储 — 存 hash 不存原文,支持吊销 + 轮换"""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    @staticmethod
    def _hash(token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    async def create(
        self, token_id: str, username: str, token: str, expires_at: datetime
    ) -> None:
        self.session.add(
            RefreshTokenModel(
                token_id=token_id,
                username=username,
                token_hash=self._hash(token),
                expires_at=expires_at,
            )
        )
        await self.session.commit()

    async def get_valid(self, token_id: str, token: str) -> dict | None:
        """取未吊销未过期且 hash 匹配的记录"""
        m = await self.session.get(RefreshTokenModel, token_id)
        if not m or m.revoked:
            return None
        if m.expires_at < datetime.utcnow():
            return None
        if m.token_hash != self._hash(token):
            return None
        m.last_used_at = datetime.utcnow()
        await self.session.commit()
        return {"token_id": m.token_id, "username": m.username}

    async def revoke(self, token_id: str) -> None:
        m = await self.session.get(RefreshTokenModel, token_id)
        if m:
            m.revoked = True
            await self.session.commit()

    async def revoke_all_for_user(self, username: str) -> int:
        """吊销用户所有 refresh token (改密/强制登出)"""
        stmt = select(RefreshTokenModel).where(
            RefreshTokenModel.username == username,
            RefreshTokenModel.revoked == False,  # noqa: E712
        )
        rows = (await self.session.execute(stmt)).scalars().all()
        for m in rows:
            m.revoked = True
        await self.session.commit()
        return len(rows)

    async def purge_expired(self) -> int:
        """清理过期记录 (定期维护)"""
        stmt = select(RefreshTokenModel).where(
            RefreshTokenModel.expires_at < datetime.utcnow()
        )
        rows = (await self.session.execute(stmt)).scalars().all()
        for m in rows:
            await self.session.delete(m)
        await self.session.commit()
        return len(rows)
