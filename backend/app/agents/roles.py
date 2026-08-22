"""Agent 角色定义 — 3 → 7 角色扩展 (裁决 §3.4)

Phase1: Triage / Investigation / Containment (已实现为节点函数)
Phase2: + DFIR / IR Lead / Compliance / SOC Manager

每个 Agent 有清晰职责 + LLM tier 分工,可独立测试。
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

from app.models.schemas import Case, JudgmentReport


@dataclass
class AgentContext:
    """Agent 执行上下文"""
    case: Case
    retrieved_knowledge: list[dict]
    enriched_context: dict


class BaseAgent(ABC):
    """Agent 抽象基类"""

    name: str = "base"
    role: str = "base"
    llm_tier: str = "tier2"  # LLM 分工: tier1 分诊 / tier2 推理 / tier3 代码
    description: str = ""

    @abstractmethod
    async def run(self, ctx: AgentContext) -> dict:
        """执行 Agent 职责,返回结果 dict"""
        ...


# ============ Phase1 已有 (节点函数封装为 Agent) ============


class TriageAgent(BaseAgent):
    """Tier1 分诊: 告警去重/降噪/关联/定级"""

    name = "triage"
    role = "Triage Analyst"
    llm_tier = "tier1"
    description = "告警去重、降噪、关联、定级"

    async def run(self, ctx: AgentContext) -> dict:
        # 当前由 ingest_alerts + 剧本匹配实现
        return {
            "agent": self.name,
            "severity": ctx.case.alerts[0].severity.value if ctx.case.alerts else "low",
            "alert_count": len(ctx.case.alerts),
        }


class InvestigationAgent(BaseAgent):
    """Tier2 调查: RAG 召回 + LLM 推理 → JudgmentReport"""

    name = "investigation"
    role = "Investigation Analyst"
    llm_tier = "tier2"
    description = "RAG 召回 ATT&CK 知识 + LLM 结构化研判"

    async def run(self, ctx: AgentContext) -> dict:
        # 当前由 retrieve_knowledge + analyze 节点实现
        judgment = ctx.case.judgment
        return {
            "agent": self.name,
            "judgment": judgment.model_dump(mode="json") if judgment else None,
            "confidence": judgment.confidence if judgment else 0,
        }


class ContainmentAgent(BaseAgent):
    """Containment: 剧本提取动作 + 执行"""

    name = "containment"
    role = "Containment Specialist"
    llm_tier = "tier2"
    description = "从剧本提取处置动作 + 执行"

    async def run(self, ctx: AgentContext) -> dict:
        return {
            "agent": self.name,
            "action_count": len(ctx.case.proposed_actions),
            "executed": len(ctx.case.execution_log),
        }


# ============ Phase2 新增 4 角色 ============


class DFIRAgent(BaseAgent):
    """DFIR: 数字取证 — 进程树/内存/磁盘证据收集

    在 Containment 前执行,捕获完整取证镜像。
    """

    name = "dfir"
    role = "Digital Forensics Investigator"
    llm_tier = "tier2"
    description = "进程树/内存/磁盘证据收集与保全"

    async def run(self, ctx: AgentContext) -> dict:
        case = ctx.case
        # 取证数据从 enriched_context 获取 (实际由 Sysmon/osquery MCP 提供)
        process_tree = ctx.enriched_context.get("process_tree", {})
        memory_capture = ctx.enriched_context.get("memory_capture", {})
        network_connections = ctx.enriched_context.get("network_connections", [])

        evidence = {
            "process_tree": process_tree,
            "memory_artifacts": memory_capture,
            "network_connections": network_connections,
            "host": case.alerts[0].asset.hostname if case.alerts else "unknown",
            "captured_at": case.created_at.isoformat() if case.created_at else None,
        }
        return {
            "agent": self.name,
            "evidence": evidence,
            "forensic_ready": bool(process_tree),
        }


class IRLeadAgent(BaseAgent):
    """IR Lead: 事件响应指挥 — 协调各 Agent + 优先级决策

    类比 SOC 的 Incident Commander,统筹全局。
    """

    name = "ir_lead"
    role = "Incident Response Lead"
    llm_tier = "tier2"
    description = "协调 Agent + 优先级决策 + 资源调配"

    async def run(self, ctx: AgentContext) -> dict:
        case = ctx.case
        judgment = case.judgment

        # 优先级决策: severity + confidence + 资产关键度
        severity = judgment.severity.value if judgment else "low"
        confidence = judgment.confidence if judgment else 0
        asset_criticality = (
            case.alerts[0].asset.criticality.value if case.alerts else "medium"
        )

        # 优先级矩阵
        priority = self._decide_priority(severity, confidence, asset_criticality)

        # 协调指令
        instructions = self._coordinate(priority, case)
        return {
            "agent": self.name,
            "priority": priority,
            "severity": severity,
            "confidence": confidence,
            "coordination": instructions,
        }

    def _decide_priority(self, severity: str, confidence: float, criticality: str) -> str:
        if severity == "critical" or criticality == "critical":
            return "P0"
        if severity == "high" and confidence > 0.7:
            return "P1"
        if severity == "medium":
            return "P2"
        return "P3"

    def _coordinate(self, priority: str, case: Case) -> list[str]:
        cmds: list[str] = []
        if priority in ("P0", "P1"):
            cmds.append("DFIR: 立即取证保全")
            cmds.append("Containment: 准备隔离方案")
        if priority == "P0":
            cmds.append("SOC Manager: 升级 CISO")
            cmds.append("Compliance: 启动合规上报流程")
        cmds.append(f"Investigation: 深挖 {case.playbook_id or '未知剧本'} 根因")
        return cmds


class ComplianceAgent(BaseAgent):
    """Compliance: 合规 — 等保上报 + 审计留痕

    确保等保2.0三级事件 24h 内上报,审计日志完整。
    """

    name = "compliance"
    role = "Compliance Officer"
    llm_tier = "tier2"
    description = "等保上报 + 审计留痕 + 监管沟通"

    async def run(self, ctx: AgentContext) -> dict:
        case = ctx.case
        judgment = case.judgment

        # 合规判定: critical/high 需上报
        needs_report = judgment and judgment.severity.value in ("critical", "high")
        deadline_hours = 24 if needs_report else 0

        return {
            "agent": self.name,
            "needs_regulatory_report": needs_report,
            "deadline_hours": deadline_hours,
            "dengbao_level": 3,
            "audit_trail_complete": len(case.execution_log) > 0,
            "report_case": case.case_id,
        }


class SOCManagerAgent(BaseAgent):
    """SOC Manager: 升级处理 + 资源调配 + 跨团队协调

    P0 事件自动升级,协调 CISO/法务/PR。
    """

    name = "soc_manager"
    role = "SOC Manager"
    llm_tier = "tier2"
    description = "升级处理 + 资源调配 + 跨团队协调"

    async def run(self, ctx: AgentContext) -> dict:
        case = ctx.case
        judgment = case.judgment
        severity = judgment.severity.value if judgment else "low"

        escalation: dict[str, Any] = {"agent": self.name}
        if severity == "critical":
            escalation["escalate_to"] = "CISO"
            escalation["notify"] = ["ciso", "legal", "pr", "ceo"]
            escalation["war_room"] = True
        elif severity == "high":
            escalation["escalate_to"] = "SOC Lead"
            escalation["notify"] = ["soc_lead", "it_manager"]
            escalation["war_room"] = False
        else:
            escalation["escalate_to"] = None
            escalation["notify"] = []
            escalation["war_room"] = False

        escalation["resource_allocation"] = self._allocate(severity)
        return escalation

    def _allocate(self, severity: str) -> dict:
        if severity == "critical":
            return {"analysts": 3, "ir_specialists": 2, "forensics": 1}
        if severity == "high":
            return {"analysts": 2, "ir_specialists": 1, "forensics": 0}
        return {"analysts": 1, "ir_specialists": 0, "forensics": 0}


# ============ Agent 注册表 ============

AGENTS: dict[str, type[BaseAgent]] = {
    "triage": TriageAgent,
    "investigation": InvestigationAgent,
    "containment": ContainmentAgent,
    "dfir": DFIRAgent,
    "ir_lead": IRLeadAgent,
    "compliance": ComplianceAgent,
    "soc_manager": SOCManagerAgent,
}


def get_agent(name: str) -> BaseAgent | None:
    cls = AGENTS.get(name)
    return cls() if cls else None


def list_agents() -> list[dict]:
    return [
        {
            "name": cls.name,
            "role": cls.role,
            "llm_tier": cls.llm_tier,
            "description": cls.description,
        }
        for cls in AGENTS.values()
    ]
