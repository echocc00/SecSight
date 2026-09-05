"""SQLAlchemy ORM 模型 (持久化层)

对应 schemas.py 的 Pydantic 模型,但带数据库映射。
JSON 存嵌套结构 (alerts/actions/judgment 等),兼顾灵活与查询。
"""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.database import Base


class UserModel(Base):
    """用户表 (Phase2 从内存字典迁移)"""
    __tablename__ = "users"

    username: Mapped[str] = mapped_column(String(64), primary_key=True)
    hashed_password: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(32), index=True)  # admin/analyst/approver/viewer
    email: Mapped[str | None] = mapped_column(String(128), nullable=True)
    is_active: Mapped[bool] = mapped_column(default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class ApprovalRecordModel(Base):
    """审批记录表 (双签多记录)

    一个 L2 动作可有多条审批记录 (incident_commander + approver 各一条),
    达到双签要求才视为通过。
    """
    __tablename__ = "approval_records"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    case_id: Mapped[str] = mapped_column(String(64), ForeignKey("cases.case_id"), index=True)
    action_id: Mapped[str] = mapped_column(String(64), index=True)
    approver_role: Mapped[str] = mapped_column(String(32))  # incident_commander/approver/ciso
    approver_user: Mapped[str] = mapped_column(String(64))
    decision: Mapped[str] = mapped_column(String(16))  # approved/rejected/defer
    comment: Mapped[str] = mapped_column(Text, default="")
    ts: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)



class CaseModel(Base):
    __tablename__ = "cases"

    case_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    status: Mapped[str] = mapped_column(String(32), default="open", index=True)
    playbook_id: Mapped[str | None] = mapped_column(String(64), index=True)
    alerts: Mapped[list] = mapped_column(JSON, default=list)
    enriched_context: Mapped[dict] = mapped_column(JSON, default=dict)
    judgment: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    proposed_actions: Mapped[list] = mapped_column(JSON, default=list)
    approvals: Mapped[dict] = mapped_column(JSON, default=dict)
    execution_log: Mapped[list] = mapped_column(JSON, default=list)
    evidence_pack_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    autonomy_level_default: Mapped[str] = mapped_column(String(8), default="L3")
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, index=True
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )
    tttr_seconds: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # 告警时间窗聚合: 相同 agg_key 的告警在窗口内并入同一 Case
    agg_key: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    alert_count: Mapped[int] = mapped_column(Integer, default=1)

    evidence: Mapped[list["EvidencePackModel"]] = relationship(
        back_populates="case", cascade="all, delete-orphan"
    )


class EvidencePackModel(Base):
    __tablename__ = "evidence_packs"

    pack_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    case_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("cases.case_id"), index=True
    )
    process_tree: Mapped[dict] = mapped_column(JSON, default=dict)
    timeline: Mapped[list] = mapped_column(JSON, default=list)
    llm_reasoning_trace: Mapped[list] = mapped_column(JSON, default=list)
    iocs: Mapped[dict] = mapped_column(JSON, default=dict)
    mitre_mapping: Mapped[dict] = mapped_column(JSON, default=dict)
    # Agent 决策留痕 (ComplianceAgent / SOCManagerAgent / IRLeadAgent)
    compliance: Mapped[dict] = mapped_column(JSON, default=dict)
    escalation: Mapped[dict] = mapped_column(JSON, default=dict)
    ir_decision: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    case: Mapped[CaseModel] = relationship(back_populates="evidence")


class AuditLogModel(Base):
    """审计日志 (hash chain 防篡改,等保2.0三级要求)

    每条记录含前一条的 entry_hash,形成链。篡改/删除任一条会断链,
    可通过 AuditLogRepository.verify_chain() 检测并定位。
    """
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    case_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    action: Mapped[str] = mapped_column(String(64), index=True)
    actor: Mapped[str] = mapped_column(String(64))
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
    ts: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, index=True
    )
    # hash chain 字段
    seq: Mapped[int] = mapped_column(Integer, default=0, index=True)
    prev_hash: Mapped[str] = mapped_column(String(64), default="0" * 64)
    entry_hash: Mapped[str] = mapped_column(String(64), default="", index=True)


class PlaybookRunModel(Base):
    """剧本执行记录 (L3 案例层沉淀)"""
    __tablename__ = "playbook_runs"

    run_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    case_id: Mapped[str] = mapped_column(String(64), ForeignKey("cases.case_id"))
    playbook_id: Mapped[str] = mapped_column(String(64), index=True)
    outcome: Mapped[str] = mapped_column(String(16), default="success")
    lessons_learned: Mapped[str] = mapped_column(Text, default="")
    iocs_collected: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class ProactiveRunModel(Base):
    """Proactive Agent 执行记录 (scheduled cron + manual 共用)"""
    __tablename__ = "proactive_runs"

    run_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    agent_name: Mapped[str] = mapped_column(String(32), index=True)
    trigger: Mapped[str] = mapped_column(String(16), default="scheduled")  # scheduled|manual
    status: Mapped[str] = mapped_column(String(16), default="success")  # success|failed
    findings_count: Mapped[int] = mapped_column(Integer, default=0)
    cases_created: Mapped[int] = mapped_column(Integer, default=0)
    result: Mapped[dict] = mapped_column(JSON, default=dict)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class RefreshTokenModel(Base):
    """Refresh token (存 hash 不存原文,支持吊销 + 轮换)"""
    __tablename__ = "refresh_tokens"

    token_id: Mapped[str] = mapped_column(String(64), primary_key=True)  # jti
    username: Mapped[str] = mapped_column(
        String(64), ForeignKey("users.username"), index=True
    )
    token_hash: Mapped[str] = mapped_column(String(128))
    expires_at: Mapped[datetime] = mapped_column(DateTime, index=True)
    revoked: Mapped[bool] = mapped_column(default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
