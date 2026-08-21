"""SQLAlchemy ORM 模型 (持久化层)

对应 schemas.py 的 Pydantic 模型,但带数据库映射。
JSON 存嵌套结构 (alerts/actions/judgment 等),兼顾灵活与查询。
"""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.database import Base


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
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    case: Mapped[CaseModel] = relationship(back_populates="evidence")


class AuditLogModel(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    case_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    action: Mapped[str] = mapped_column(String(64), index=True)
    actor: Mapped[str] = mapped_column(String(64))
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
    ts: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, index=True
    )


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
