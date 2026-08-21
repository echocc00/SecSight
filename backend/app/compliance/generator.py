"""合规报告生成 — 等保 2.0 三级事件报告

从 Case 数据生成结构化报告 (HTML/Markdown/PDF)。
Jinja2 模板,可扩展 Word (python-docx)。
"""
from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from app.db.repositories import CaseRepository, EvidencePackRepository
from app.db.database import async_session

import structlog

log = structlog.get_logger()

# 模板目录
TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"


class ReportGenerator:
    """等保 2.0 三级事件报告生成器"""

    def __init__(self) -> None:
        self.env = Environment(
            loader=FileSystemLoader(str(TEMPLATE_DIR)),
            autoescape=select_autoescape(["html"]),
            enable_async=True,
        )

    async def generate(
        self,
        case_id: str,
        format: str = "html",
    ) -> dict:
        """生成报告

        format: html | markdown
        返回: {"case_id", "format", "content", "generated_at"}
        """
        async with async_session() as session:
            case_repo = CaseRepository(session)
            evidence_repo = EvidencePackRepository(session)

            case = await case_repo.get(case_id)
            if not case:
                raise ValueError(f"Case {case_id} not found")

            evidence = await evidence_repo.get_by_case(case_id)
            audit_logs = await _get_audit_logs(session, case_id)

        # 准备报告数据
        report_data = self._build_report_data(case, evidence, audit_logs)
        # 渲染
        template_name = f"compliance_report.{format}.j2"
        try:
            template = self.env.get_template(template_name)
        except Exception:
            template = self.env.get_template("compliance_report.html.j2")
            format = "html"

        content = await template.render_async(**report_data)

        log.info(
            "report.generated",
            case_id=case_id,
            format=format,
            severity=case.judgment.severity.value if case.judgment else "unknown",
        )
        return {
            "case_id": case_id,
            "format": format,
            "content": content,
            "generated_at": datetime.utcnow().isoformat(),
        }

    def _build_report_data(
        self,
        case: Any,
        evidence: dict | None,
        audit_logs: list[dict],
    ) -> dict:
        """构建报告上下文"""
        judgment = case.judgment
        # 审计日志 ts 转 ISO 字符串 (模板里切片需要字符串)
        normalized_logs = []
        for log in audit_logs:
            log_copy = dict(log)
            ts = log_copy.get("ts")
            if ts and hasattr(ts, "isoformat"):
                log_copy["ts"] = ts.isoformat()
            normalized_logs.append(log_copy)
        return {
            "case_id": case.case_id,
            "generated_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
            "case": case.model_dump(mode="json"),
            "judgment": judgment.model_dump(mode="json") if judgment else None,
            "evidence": evidence,
            "audit_logs": normalized_logs,
            "alerts": [a.model_dump(mode="json") for a in case.alerts],
            "actions": [a.model_dump(mode="json") for a in case.proposed_actions],
            "executions": [e.model_dump(mode="json") for e in case.execution_log],
            "tttr_seconds": case.tttr_seconds,
            "created_at": case.created_at.strftime("%Y-%m-%d %H:%M:%S"),
            "severity": judgment.severity.value if judgment else "unknown",
            "mitre_tactics": case.alerts[0].mitre_tactics if case.alerts else [],
            "mitre_techniques": case.alerts[0].mitre_techniques if case.alerts else [],
        }


async def _get_audit_logs(session, case_id: str) -> list[dict]:
    from app.db.repositories import AuditLogRepository

    repo = AuditLogRepository(session)
    return await repo.list_by_case(case_id)


report_generator = ReportGenerator()
