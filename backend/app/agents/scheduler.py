"""Proactive Agent 调度器 — APScheduler cron 驱动

Reactive Agent 由告警触发,Proactive Agent 由时间触发。
统一入口 run_proactive_with_record 保证 scheduled/manual 都落库 proactive_runs。

高价值 finding (critical/high 漏洞、confirmed 狩猎命中) 自动建 Case,
进入 reactive 闭环 — 这是 Proactive → Reactive 的衔接点。

默认 cron (环境变量可覆盖):
  threat_hunting        每 6 小时     PROACTIVE_CRON_THREAT_HUNTING
  vuln_scan             每天 02:00    PROACTIVE_CRON_VULN_SCAN
  detection_engineering 每天 03:00    PROACTIVE_CRON_DETECTION_ENGINEERING
  asset_hardening       每周一 04:00  PROACTIVE_CRON_ASSET_HARDENING
"""
from __future__ import annotations

import os
from datetime import datetime
from uuid import uuid4

import structlog

from app.core.config import settings

log = structlog.get_logger()

_DEFAULT_SCHEDULE: dict[str, str] = {
    "threat_hunting": "0 */6 * * *",
    "vuln_scan": "0 2 * * *",
    "detection_engineering": "0 3 * * *",
    "asset_hardening": "0 4 * * 1",
}

_scheduler = None


def _count_findings(agent_name: str, result: dict) -> int:
    """各 Agent 结果结构不同,统一提取 finding 数"""
    if agent_name == "threat_hunting":
        return len(result.get("findings", []))
    if agent_name == "vuln_scan":
        return int(result.get("total_vulns", 0))
    if agent_name == "detection_engineering":
        return len(result.get("rule_suggestions", [])) or len(
            result.get("coverage_gaps", [])
        )
    if agent_name == "asset_hardening":
        return int(result.get("failures", 0))
    return 0


async def _record_run(
    run_id: str,
    agent_name: str,
    trigger: str,
    status: str,
    findings: int,
    cases_created: int,
    result: dict,
    error: str | None,
    started_at: datetime,
) -> None:
    from app.db.database import async_session
    from app.db.repositories import ProactiveRunRepository

    async with async_session() as session:
        await ProactiveRunRepository(session).create(
            run_id=run_id,
            agent_name=agent_name,
            trigger=trigger,
            status=status,
            findings_count=findings,
            cases_created=cases_created,
            result=result,
            error=error,
            started_at=started_at,
            finished_at=datetime.utcnow(),
        )


async def _create_case_from_finding(
    title: str, severity: str, raw: dict, source: str
) -> str | None:
    """Proactive finding → Alert → Case (进入 reactive 闭环)"""
    from app.agents.workflow import trigger_workflow
    from app.db.database import async_session
    from app.db.repositories import CaseRepository
    from app.models.schemas import Alert, AssetRef, CaseStatus, Severity
    from app.playbooks.engine import engine as playbook_engine

    alert = Alert(
        source=source,
        rule_id=f"proactive_{source}",
        rule_level=10 if severity in ("critical", "high") else 5,
        severity=Severity(severity),
        asset=AssetRef(hostname=raw.get("asset"), host_id=raw.get("asset")),
        raw=raw,
        message=title,
    )
    async with async_session() as session:
        repo = CaseRepository(session)
        case, deduped = await repo.ingest_alert(alert)
        if deduped:
            from app.core.metrics import record_alert_deduped

            record_alert_deduped(source)
            log.info("proactive.finding_merged", case_id=case.case_id, source=source)
            return None
        playbook = playbook_engine.match(alert)
        playbook_id = playbook.id if playbook else None
        if playbook:
            from app.db.models import CaseModel

            await repo.update_status(case.case_id, CaseStatus.investigating)
            model = await session.get(CaseModel, case.case_id)
            if model:
                model.playbook_id = playbook.id
                await session.commit()
    await trigger_workflow(case.case_id, playbook_id)
    log.info(
        "proactive.case_created",
        case_id=case.case_id,
        source=source,
        severity=severity,
    )
    return case.case_id


async def _maybe_create_cases(agent_name: str, result: dict) -> int:
    """高价值 finding 自动建 Case,返回建 Case 数"""
    created = 0
    if agent_name == "vuln_scan":
        for v in result.get("vulnerabilities", []):
            if v.get("severity") in ("critical", "high"):
                cid = await _create_case_from_finding(
                    title=f"漏洞 {v.get('cve')} 影响 {v.get('service')}",
                    severity=v["severity"],
                    raw=v,
                    source="vuln_scan",
                )
                created += 1 if cid else 0
    elif agent_name == "threat_hunting":
        for f in result.get("findings", []):
            # 仅 confirmed 建 Case (hunting 中的假设不建)
            if f.get("status") == "confirmed":
                cid = await _create_case_from_finding(
                    title=f"狩猎命中: {f.get('hypothesis')}",
                    severity=f.get("severity", "high"),
                    raw=f,
                    source="threat_hunting",
                )
                created += 1 if cid else 0
    elif agent_name == "asset_hardening":
        # 基线失败不建 Case (非事件,走加固工单),仅记录
        pass
    return created


async def run_proactive_with_record(
    agent_name: str, trigger: str = "scheduled"
) -> dict:
    """执行 Proactive Agent + 落库 + 高危 finding 建 Case

    scheduled/manual 共用此入口,保证执行历史完整。
    """
    from app.agents.proactive import ProactiveContext, get_proactive_agent

    agent = get_proactive_agent(agent_name)
    if not agent:
        raise ValueError(f"未知 Proactive Agent: {agent_name}")

    run_id = str(uuid4())
    started = datetime.utcnow()
    try:
        result = await agent.run(ProactiveContext())
        findings = _count_findings(agent_name, result)
        cases = await _maybe_create_cases(agent_name, result)
        await _record_run(
            run_id, agent_name, trigger, "success", findings, cases,
            result, None, started,
        )
        log.info(
            "proactive.run_success",
            agent=agent_name,
            trigger=trigger,
            findings=findings,
            cases_created=cases,
        )
        return {**result, "run_id": run_id, "cases_created": cases}
    except Exception as e:  # noqa: BLE001 - 记录失败但不崩调度器
        await _record_run(
            run_id, agent_name, trigger, "failed", 0, 0, {}, str(e), started
        )
        log.error("proactive.run_failed", agent=agent_name, error=str(e))
        raise


def start_scheduler() -> None:
    """启动 APScheduler (lifespan 调用)"""
    global _scheduler
    if _scheduler is not None:
        return
    if not settings.enable_proactive_scheduler:
        log.info("proactive.scheduler_disabled", note="设 ENABLE_PROACTIVE_SCHEDULER=true 启用")
        return

    from apscheduler.schedulers.asyncio import AsyncIOScheduler
    from apscheduler.triggers.cron import CronTrigger

    _scheduler = AsyncIOScheduler(timezone="Asia/Shanghai")
    for name, default_cron in _DEFAULT_SCHEDULE.items():
        expr = os.environ.get(
            f"PROACTIVE_CRON_{name.upper()}", default_cron
        ).strip()
        try:
            _scheduler.add_job(
                run_proactive_with_record,
                CronTrigger.from_crontab(expr),
                args=[name, "scheduled"],
                id=f"proactive_{name}",
                max_instances=1,      # 上次未跑完不重入
                coalesce=True,        # 错过多次只补跑一次
                misfire_grace_time=3600,
                replace_existing=True,
            )
        except ValueError as e:
            log.warning("proactive.invalid_cron", agent=name, expr=expr, error=str(e))
    _scheduler.start()
    log.info(
        "proactive.scheduler_started",
        jobs=[j.id for j in _scheduler.get_jobs()],
    )


async def shutdown_scheduler() -> None:
    global _scheduler
    if _scheduler is not None:
        _scheduler.shutdown(wait=False)
        _scheduler = None
        log.info("proactive.scheduler_stopped")


def scheduler_status() -> dict:
    """调度器状态 (供 /health 和 API 查询)"""
    if _scheduler is None:
        return {"running": False, "enabled": settings.enable_proactive_scheduler, "jobs": []}
    return {
        "running": True,
        "enabled": True,
        "jobs": [
            {
                "id": j.id,
                "agent": j.args[0] if j.args else None,
                "next_run": j.next_run_time.isoformat() if j.next_run_time else None,
            }
            for j in _scheduler.get_jobs()
        ],
    }
