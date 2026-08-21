"""SecSight 核心数据模型 (Pydantic,对应裁决 §3 数据契约)"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class Severity(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class AutonomyLevel(str, Enum):
    """5 级自主性 (裁决 §3.4)"""
    L1 = "L1"  # Manual
    L2 = "L2"  # Advisory, 强制双签
    L3 = "L3"  # Shared, 关键决策需人
    L4 = "L4"  # Supervised, 异步审计
    L5 = "L5"  # Fully Autonomous


class CaseStatus(str, Enum):
    open = "open"
    investigating = "investigating"
    pending_approval = "pending_approval"
    contained = "contained"
    resolved = "resolved"
    closed = "closed"


class ActionType(str, Enum):
    isolate_host = "isolate_host"
    block_ip = "block_ip"
    block_domain = "block_domain"
    kill_process = "kill_process"
    quarantine_file = "quarantine_file"
    freeze_account = "freeze_account"
    notify = "notify"
    create_ticket = "create_ticket"
    query_asset = "query_asset"
    forensic_capture = "forensic_capture"
    report_regulator = "report_regulator"
    service_restart = "service_restart"
    rollback_file = "rollback_file"


class AssetRef(BaseModel):
    host_id: str | None = None
    hostname: str | None = None
    ips: list[str] = Field(default_factory=list)
    criticality: Severity = Severity.medium


class Alert(BaseModel):
    """统一告警 (ECS 子集)"""
    alert_id: str = Field(default_factory=lambda: str(uuid4()))
    ts: datetime = Field(default_factory=datetime.utcnow)
    source: str  # wazuh | suricata | sysmon | firewall | custom
    rule_id: str
    rule_level: int = 0
    severity: Severity = Severity.low
    src_ip: str | None = None
    dst_ip: str | None = None
    user: str | None = None
    asset: AssetRef = Field(default_factory=AssetRef)
    raw: dict[str, Any] = Field(default_factory=dict)
    mitre_tactics: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    message: str = ""


class JudgmentReport(BaseModel):
    """研判报告 (Tier2 输出,强制结构化)"""
    incident_summary: str = Field(max_length=200)
    severity: Severity
    ttps: list[str] = Field(default_factory=list, max_length=10)  # ATT&CK 白名单,RAG 召回才能填
    kill_chain_phase: str = ""
    true_positive: str = "uncertain"  # yes | no | uncertain
    confidence: float = Field(ge=0.0, le=1.0)
    recommended_actions: list[ActionType] = Field(default_factory=list)
    rationale: str = Field(min_length=20, max_length=500)
    citations: list[str] = Field(default_factory=list)  # RAG 文档 ID


class Action(BaseModel):
    """处置动作 (含自主性标注)"""
    action_id: str = Field(default_factory=lambda: str(uuid4()))
    action_type: ActionType
    target: dict[str, Any]  # {ip / pid / host / account ...}
    autonomy_level: AutonomyLevel
    risk: Severity = Severity.medium
    approval_required: bool = False  # L2=True
    requires_double_sign: bool = False  # 高危=True
    timeout_seconds: int = 300
    rollback_action_id: str | None = None
    playbook_id: str | None = None


class ApprovalRecord(BaseModel):
    action_id: str
    approver_role: str  # incident_commander | approver | ciso_or_delegate
    approver_user: str
    decision: str = "pending"  # pending | approved | rejected | deferred
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    comment: str = ""


class ExecutionStep(BaseModel):
    action_id: str
    status: str = "pending"  # pending | executing | success | failed | rolled_back
    started_at: datetime | None = None
    finished_at: datetime | None = None
    result: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None


class Case(BaseModel):
    """案件 (核心聚合根)"""
    case_id: str = Field(default_factory=lambda: str(uuid4()))
    status: CaseStatus = CaseStatus.open
    alerts: list[Alert] = Field(default_factory=list)
    playbook_id: str | None = None
    enriched_context: dict[str, Any] = Field(default_factory=dict)
    judgment: JudgmentReport | None = None
    proposed_actions: list[Action] = Field(default_factory=list)
    approvals: dict[str, ApprovalRecord] = Field(default_factory=dict)
    execution_log: list[ExecutionStep] = Field(default_factory=list)
    evidence_pack_id: str | None = None
    autonomy_level_default: AutonomyLevel = AutonomyLevel.L3
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    tttr_seconds: int | None = None

    def needs_approval(self) -> list[Action]:
        """返回需要审批的动作 (L2)"""
        return [a for a in self.proposed_actions if a.approval_required]


class IntelResult(BaseModel):
    """情报查询结果"""
    indicator: str
    indicator_type: str  # ip | domain | file_hash | url
    provider: str
    confidence: float = Field(ge=0.0, le=1.0, default=0.0)
    malicious: bool = False
    tags: list[str] = Field(default_factory=list)
    mitre_ttps: list[str] = Field(default_factory=list)
    raw: dict[str, Any] = Field(default_factory=dict)
