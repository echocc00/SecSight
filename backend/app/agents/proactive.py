"""Proactive Agent — 主动防御 (裁决 §3.4 Phase4)

与 Reactive Agent (Triage/Investigation/Containment 响应告警) 相对,
Proactive Agent 主动发现风险、优化检测、加固资产。

4 个 Proactive Agent:
  - ThreatHuntingAgent: 基于情报主动狩猎 (假设已被入侵,寻找痕迹)
  - VulnerabilityScanAgent: 漏洞扫描 + 资产暴露面
  - DetectionEngineeringAgent: 检测规则优化 + 知识反向注入 (L3→L1)
  - AssetHardeningAgent: 资产加固建议 (基线核查 + 配置漂移)
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from app.agents.roles import BaseAgent
from app.models.schemas import Case

import structlog

log = structlog.get_logger()


@dataclass
class ProactiveContext:
    """Proactive Agent 上下文 (无具体 Case,面向全局)"""
    time_window_hours: int = 24
    target_assets: list[str] | None = None
    hunt_hypotheses: list[str] | None = None


# ============ 4 个 Proactive Agent ============


class ThreatHuntingAgent(BaseAgent):
    """主动威胁狩猎 — 基于假设寻找已存在入侵

    与 Reactive 区别: 无告警触发,基于 MITRE 技术假设 + 情报驱动狩猎。
    """

    name = "threat_hunting"
    role = "Threat Hunter"
    llm_tier = "tier2"
    description = "基于情报 + MITRE 假设主动狩猎已存在入侵"

    async def run(self, ctx: ProactiveContext | Any) -> dict:
        # 假设列表 (实际从 L3 案例知识 + 情报生成)
        hypotheses = ctx.hunt_hypotheses or [
            "TA0008 横向移动: 检查 SMB 管理共享异常",
            "T1053 持久化: 扫描 crontab/systemd 异常",
            "T1071 C2: 检测周期性信标流量",
        ]
        # 模拟狩猎结果 (实际调 osquery/Sysmon MCP)
        findings: list[dict] = []
        for h in hypotheses:
            # 简化: 每个假设返回一个模拟 finding
            findings.append({
                "hypothesis": h,
                "status": "hunting",
                "assets_scanned": ctx.target_assets or ["all"],
            })
        return {
            "agent": self.name,
            "hypotheses_count": len(hypotheses),
            "findings": findings,
            "hunt_window_hours": ctx.time_window_hours,
        }


class VulnerabilityScanAgent(BaseAgent):
    """漏洞扫描 + 攻击面管理"""

    name = "vuln_scan"
    role = "Vulnerability Manager"
    llm_tier = "tier3"  # 代码/配置分析
    description = "漏洞扫描 + 资产暴露面 + 修复优先级"

    async def run(self, ctx: ProactiveContext | Any) -> dict:
        # 模拟扫描结果 (实际调 Nuclei/Trivy/kube-bench)
        vulnerabilities = [
            {"asset": "web-prod-01", "cve": "CVE-2024-1234", "severity": "high", "service": "nginx"},
            {"asset": "db-prod-01", "cve": "CVE-2024-5678", "severity": "medium", "service": "postgres"},
        ]
        # 修复优先级: 按 severity + 资产暴露度
        priority_fixes = [v for v in vulnerabilities if v["severity"] in ("critical", "high")]
        return {
            "agent": self.name,
            "total_vulns": len(vulnerabilities),
            "high_priority": len(priority_fixes),
            "vulnerabilities": vulnerabilities,
        }


class DetectionEngineeringAgent(BaseAgent):
    """检测规则工程 — 知识反向注入 (L3 案例 → L1 战术优化检测)

    核心: 从已处置案例中学习,优化检测规则覆盖盲区。
    """

    name = "detection_engineering"
    role = "Detection Engineer"
    llm_tier = "tier2"
    description = "L3 案例知识反向注入 L1 战术 + 检测规则优化"

    async def run(self, ctx: Any) -> dict:
        # ctx 可以是 Case (从案例学习) 或 ProactiveContext (全局优化)
        if isinstance(ctx, Case):
            return await self._learn_from_case(ctx)
        return await self._global_optimization(ctx)

    async def _learn_from_case(self, case: Case) -> dict:
        """从单个案例提取检测规则改进建议"""
        judgment = case.judgment
        ttps = judgment.ttps if judgment else []
        return {
            "agent": self.name,
            "source_case": case.case_id,
            "ttps_observed": ttps,
            "rule_suggestions": [
                f"新增 Sigma 规则: 检测 {ttp}" for ttp in ttps
            ],
            "knowledge_injection": {
                "target_layer": "L1_tactic",
                "playbook_id": case.playbook_id,
                "lessons": judgment.rationale if judgment else "",
            },
        }

    async def _global_optimization(self, ctx: Any) -> dict:
        """全局检测规则覆盖率分析"""
        return {
            "agent": self.name,
            "coverage_gaps": ["T1486 勒索检测可加强", "T1053.003 cron 检测盲区"],
            "rules_optimized": 0,
            "rules_added": 0,
        }


class AssetHardeningAgent(BaseAgent):
    """资产加固 — 基线核查 + 配置漂移检测"""

    name = "asset_hardening"
    role = "Asset Hardening Specialist"
    llm_tier = "tier3"
    description = "基线核查 + 配置漂移 + 加固建议"

    async def run(self, ctx: ProactiveContext | Any) -> dict:
        # 模拟基线核查 (实际调 kube-bench/CIS-CAT/osquery)
        baselines = [
            {"asset": "web-prod-01", "control": "CIS-1.1", "status": "pass", "category": "file_permissions"},
            {"asset": "web-prod-01", "control": "CIS-4.1", "status": "fail", "category": "firewall"},
            {"asset": "db-prod-01", "control": "CIS-2.3", "status": "fail", "category": "service_disabled"},
        ]
        failures = [b for b in baselines if b["status"] == "fail"]
        return {
            "agent": self.name,
            "assets_checked": len({b["asset"] for b in baselines}),
            "total_controls": len(baselines),
            "failures": len(failures),
            "hardening_suggestions": [
                f"{b['asset']}: 修复 {b['control']} ({b['category']})" for b in failures
            ],
        }


# ============ 注册表 ============

PROACTIVE_AGENTS: dict[str, type[BaseAgent]] = {
    "threat_hunting": ThreatHuntingAgent,
    "vuln_scan": VulnerabilityScanAgent,
    "detection_engineering": DetectionEngineeringAgent,
    "asset_hardening": AssetHardeningAgent,
}


def get_proactive_agent(name: str) -> BaseAgent | None:
    cls = PROACTIVE_AGENTS.get(name)
    return cls() if cls else None


def list_proactive_agents() -> list[dict]:
    return [
        {"name": cls.name, "role": cls.role, "llm_tier": cls.llm_tier, "description": cls.description}
        for cls in PROACTIVE_AGENTS.values()
    ]
