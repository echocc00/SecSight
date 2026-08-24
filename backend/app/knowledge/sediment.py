"""知识反向注入 — L3 案例沉淀 → L1 战术优化

闭环: Case 处置完成后,从案例中提取知识,反向注入 L1 战术层,
优化检测规则覆盖盲区,形成"处置→学习→更强调检测"飞轮。

流程:
  1. 从 resolved Case 提取: TTPs / IoCs / 研判依据 / 处置教训
  2. 向量化入 Qdrant L3 案例库 (供 RAG 召回)
  3. 生成 Sigma/检测规则建议 (覆盖未检测的 TTP)
  4. 注入 L1 战术知识 (剧本 lessons_learned)
"""
from __future__ import annotations

import os
from datetime import datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

import yaml

from app.db.database import async_session
from app.db.repositories import AuditLogRepository, CaseRepository
from app.models.schemas import Case

import structlog

log = structlog.get_logger()

# L1 战术知识根目录 (auto-generated 子目录隔离人工编写)
_L1_ROOT = Path("knowledge/L1_tactic/derived")


# ============ 案例知识提取 ============


def extract_case_knowledge(case: Case) -> dict:
    """从 Case 提取结构化知识

    提取: TTPs / IoCs / 研判依据 / 处置动作 / 教训
    """
    judgment = case.judgment
    alerts = case.alerts

    # IoCs 从告警 raw 提取
    iocs: dict[str, list] = {"ips": [], "domains": [], "hashes": [], "processes": []}
    for alert in alerts:
        raw = alert.raw or {}
        if alert.src_ip:
            iocs["ips"].append(alert.src_ip)
        if alert.dst_ip:
            iocs["ips"].append(alert.dst_ip)
        if "process_name" in raw:
            iocs["processes"].append(raw["process_name"])
        if "domain" in raw:
            iocs["domains"].append(raw["domain"])
        if "hash" in raw or "file_hash" in raw:
            iocs["hashes"].append(raw.get("hash") or raw.get("file_hash"))

    # 去重
    iocs = {k: list(set(v)) for k, v in iocs.items()}

    # 处置动作摘要
    action_summary = [
        {
            "type": a.action_type.value,
            "autonomy": a.autonomy_level.value,
            "risk": a.risk.value,
        }
        for a in case.proposed_actions
    ]

    # 执行结果
    execution_results = [
        {"action_id": e.action_id, "status": e.status}
        for e in case.execution_log
    ]

    return {
        "case_id": case.case_id,
        "playbook_id": case.playbook_id,
        "ttps": judgment.ttps if judgment else [],
        "severity": judgment.severity.value if judgment else "unknown",
        "confidence": judgment.confidence if judgment else 0,
        "rationale": judgment.rationale if judgment else "",
        "iocs": iocs,
        "actions": action_summary,
        "executions": execution_results,
        "tttr_seconds": case.tttr_seconds,
        "extracted_at": datetime.utcnow().isoformat(),
    }


# ============ 检测规则生成 ============


def generate_detection_rules(knowledge: dict) -> list[dict]:
    """从案例知识生成检测规则建议

    针对 TTP 生成 Sigma 规则骨架,覆盖未检测的技术。
    """
    rules: list[dict] = []
    ttps = knowledge.get("ttps", [])
    iocs = knowledge.get("iocs", {})

    # 按 TTP 生成规则
    for ttp in ttps:
        ttp_id = ttp.split(" ")[0]  # "T1496 Resource Hijacking" → "T1496"
        rule = {
            "rule_id": f"sigma-derived-{ttp_id.lower()}-{uuid4().hex[:8]}",
            "title": f"检测 {ttp} (源自案例 {knowledge['case_id'][:8]})",
            "status": "experimental",
            "description": f"从案例 {knowledge['case_id']} 自动生成的检测规则",
            "mitre": {"id": [ttp_id], "tactic": []},
            "detection": _build_detection_condition(ttp_id, iocs),
            "source_case": knowledge["case_id"],
            "playbook_id": knowledge.get("playbook_id"),
        }
        rules.append(rule)

    # IoC-based 规则 (IP/hash)
    if iocs.get("ips"):
        rules.append({
            "rule_id": f"ioc-ips-{uuid4().hex[:8]}",
            "title": f"已知恶意 IP 通信 (源自案例 {knowledge['case_id'][:8]})",
            "status": "experimental",
            "detection": {"condition": "selection", "selection": {"src_ip": iocs["ips"]}},
            "source_case": knowledge["case_id"],
        })
    if iocs.get("processes"):
        rules.append({
            "rule_id": f"ioc-process-{uuid4().hex[:8]}",
            "title": f"已知恶意进程 (源自案例 {knowledge['case_id'][:8]})",
            "status": "experimental",
            "detection": {"condition": "selection", "selection": {"process_name": iocs["processes"]}},
            "source_case": knowledge["case_id"],
        })

    return rules


def _build_detection_condition(ttp_id: str, iocs: dict) -> dict:
    """按 TTP 类型构造检测条件"""
    # 简化映射: TTP → 检测字段
    ttp_fields = {
        "T1496": {"process_name": ["xmrig", "minerd", "cpuminer"]},
        "T1486": {"file_extension": [".locked", ".encrypted"]},
        "T1053": {"file_path": ["/var/spool/cron/", "crontab"]},
        "T1110": {"event_id": ["4625"], "count": {"gte": 100}},
        "T1190": {"url_path": ["'", "OR", "UNION"]},
        "T1071": {"dst_port": [3333, 4444, 5555]},
    }
    return {
        "condition": "selection",
        "selection": ttp_fields.get(ttp_id, {"mitre_id": [ttp_id]}),
    }


# ============ L1 战术注入 ============


def build_l1_injection(knowledge: dict, rules: list[dict]) -> dict:
    """构造 L1 战术层知识注入包"""
    return {
        "target_layer": "L1_tactic",
        "playbook_id": knowledge.get("playbook_id"),
        "case_id": knowledge["case_id"],
        "lessons_learned": knowledge.get("rationale", ""),
        "new_iocs": knowledge["iocs"],
        "new_rules": [r["rule_id"] for r in rules],
        "ttps_covered": knowledge["ttps"],
        "tttr_seconds": knowledge.get("tttr_seconds"),
        "injected_at": datetime.utcnow().isoformat(),
    }


# ============ L3 案例向量化 (Qdrant) ============


def build_case_chunk(knowledge: dict) -> dict:
    """把案例知识打包成 Qdrant L3 案例库的 chunk

    检索时按 TTP/IoC/剧本召回历史案例,供 RAG 使用。
    """
    iocs = knowledge.get("iocs", {})
    return {
        "id": f"case:{knowledge['case_id']}",
        "type": "case",
        "case_id": knowledge["case_id"],
        "playbook_id": knowledge.get("playbook_id"),
        "ttps": knowledge.get("ttps", []),
        "severity": knowledge.get("severity"),
        "confidence": knowledge.get("confidence"),
        "iocs": iocs,
        "rationale": knowledge.get("rationale", ""),
        "actions": knowledge.get("actions", []),
        "tttr_seconds": knowledge.get("tttr_seconds"),
        "extracted_at": knowledge.get("extracted_at"),
        # 用于向量化的文本 (name + description 字段,供 embed 使用)
        "name": f"案例 {knowledge['case_id'][:8]} ({knowledge.get('playbook_id', 'unknown')})",
        "description": (
            f"TTPs: {', '.join(knowledge.get('ttps', []))}. "
            f"IoCs: {iocs}. "
            f"研判: {knowledge.get('rationale', '')}"
        ),
    }


async def vectorize_to_qdrant(knowledge: dict) -> int:
    """向量化案例知识写入 Qdrant L3 案例库

    ENABLE_QDRANT=true 时执行,失败不阻塞沉淀 (仅告警)。
    返回写入点数 (0 表示未启用或失败)。
    """
    from app.core.config import settings

    if not settings.enable_qdrant:
        log.info("knowledge.qdrant_skipped", reason="enable_qdrant=false")
        return 0

    try:
        from app.retrieval.qdrant_retriever import QdrantRetriever

        retriever = QdrantRetriever(
            url=settings.qdrant_url, api_key=settings.qdrant_api_key
        )
        chunk = build_case_chunk(knowledge)
        count = await retriever.ingest_knowledge([chunk])
        log.info("knowledge.qdrant_ingested", case_id=knowledge["case_id"], points=count)
        return count
    except Exception as e:  # noqa: BLE001
        log.warning("knowledge.qdrant_failed", case_id=knowledge["case_id"], error=str(e))
        return 0


# ============ L1 战术 YAML 写入 ============


def write_l1_yaml(knowledge: dict, rules: list[dict]) -> str | None:
    """把案例沉淀的检测规则 + 教训写入 L1 战术 YAML 文件

    写入 knowledge/L1_tactic/derived/case-{short}.yaml
    幂等: 同一 case 重写覆盖。返回文件路径 (失败返回 None)。
    """
    try:
        _L1_ROOT.mkdir(parents=True, exist_ok=True)
        short = knowledge["case_id"][:12]
        path = _L1_ROOT / f"case-{short}.yaml"

        doc = {
            "source_case": knowledge["case_id"],
            "playbook_id": knowledge.get("playbook_id"),
            "auto_generated": True,
            "generated_at": datetime.utcnow().isoformat(),
            "ttps_covered": knowledge.get("ttps", []),
            "lessons_learned": knowledge.get("rationale", ""),
            "new_iocs": knowledge.get("iocs", {}),
            "detection_rules": [
                {
                    "rule_id": r["rule_id"],
                    "title": r["title"],
                    "status": r["status"],
                    "mitre": r.get("mitre", {}),
                    "detection": r["detection"],
                }
                for r in rules
            ],
        }
        with open(path, "w", encoding="utf-8") as f:
            yaml.safe_dump(doc, f, allow_unicode=True, sort_keys=False)
        log.info("knowledge.l1_yaml_written", case_id=knowledge["case_id"], path=str(path))
        return str(path)
    except Exception as e:  # noqa: BLE001
        log.warning("knowledge.l1_yaml_failed", case_id=knowledge["case_id"], error=str(e))
        return None


# ============ 主入口:案例沉淀 ============


async def sediment_case(case_id: str) -> dict:
    """案例沉淀 — 主入口

    从 resolved Case 提取知识 → 生成检测规则 → 向量化入 Qdrant L3 → 写入 L1 YAML。
    应在 Case resolved 后自动调用 (update_case_node)。
    """
    async with async_session() as session:
        repo = CaseRepository(session)
        case = await repo.get(case_id)
        if not case:
            raise ValueError(f"Case {case_id} not found")

    # 1. 提取知识
    knowledge = extract_case_knowledge(case)

    # 2. 生成检测规则
    rules = generate_detection_rules(knowledge)

    # 3. 构造 L1 注入包
    l1_injection = build_l1_injection(knowledge, rules)

    # 4. 向量化入 Qdrant L3 案例库
    qdrant_points = await vectorize_to_qdrant(knowledge)

    # 5. 写入 L1 战术知识 YAML 文件
    l1_yaml_path = write_l1_yaml(knowledge, rules)

    # 6. 审计
    async with async_session() as session:
        audit = AuditLogRepository(session)
        await audit.record(
            action="knowledge_sedimented",
            actor="system",
            case_id=case_id,
            detail={
                "ttps": knowledge["ttps"],
                "rules_generated": len(rules),
                "qdrant_points": qdrant_points,
                "l1_yaml_path": l1_yaml_path,
            },
        )

    log.info(
        "knowledge.sedimented",
        case_id=case_id,
        ttps=knowledge["ttps"],
        rules_generated=len(rules),
        qdrant_points=qdrant_points,
    )

    return {
        "case_id": case_id,
        "knowledge": knowledge,
        "generated_rules": rules,
        "l1_injection": l1_injection,
        "qdrant_points": qdrant_points,
        "l1_yaml_path": l1_yaml_path,
        "sedimented_at": datetime.utcnow().isoformat(),
    }
