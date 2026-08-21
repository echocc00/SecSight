"""Mock LLM 网关 — 返回预设研判报告 (开发用,替代真实 LLM)"""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel

from app.models.schemas import ActionType, JudgmentReport, Severity


# 预设研判报告 (按告警类型)
PRESET_REPORTS: dict[str, JudgmentReport] = {
    "cryptominer": JudgmentReport(
        incident_summary="检测到 xmrig 挖矿进程连接矿池 pool.supportxmr.com",
        severity=Severity.high,
        ttps=["T1496", "T1071.001"],
        kill_chain_phase="impact",
        true_positive="yes",
        confidence=0.88,
        recommended_actions=[
            ActionType.isolate_host,
            ActionType.kill_process,
            ActionType.block_domain,
            ActionType.quarantine_file,
        ],
        rationale=(
            "进程名 xmrig + stratum+tcp 命令行 + 矿池 IP 连接三重证据确认挖矿。"
            "CPU 持续 97% 占用,父进程 /tmp/.xmrig/xmrig 提示隐藏目录持久化。"
        ),
        citations=["attck:T1496", "attck:T1071.001", "case_hist:2025-cryptominer-001"],
    ),
    "ransomware": JudgmentReport(
        incident_summary="检测到批量文件加密行为,疑似勒索病毒",
        severity=Severity.critical,
        ttps=["T1486", "T1490"],
        kill_chain_phase="impact",
        true_positive="yes",
        confidence=0.92,
        recommended_actions=[
            ActionType.isolate_host,
            ActionType.block_ip,
            ActionType.freeze_account,
        ],
        rationale="批量文件改名 .lock 后缀 + vssadmin delete shadows 命令,高度疑似勒索。",
        citations=["attck:T1486", "attck:T1490"],
    ),
    "bruteforce": JudgmentReport(
        incident_summary="SSH 暴力破解,短时间内大量认证失败",
        severity=Severity.medium,
        ttps=["T1110"],
        kill_chain_phase="initial-access",
        true_positive="uncertain",
        confidence=0.65,
        recommended_actions=[ActionType.block_ip],
        rationale="5 分钟内 200+ 次认证失败,但无成功登录,暂判定为撞库尝试。",
        citations=["attck:T1110"],
    ),
}


def _detect_scenario(messages: list[dict]) -> str:
    """从 prompt 内容推断场景类型"""
    text = " ".join(str(m.get("content", "")) for m in messages).lower()
    if "xmrig" in text or "stratum" in text or "mining" in text or "t1496" in text:
        return "cryptominer"
    if "ransomware" in text or "encrypt" in text or "t1486" in text:
        return "ransomware"
    if "brute" in text or "ssh" in text or "t1110" in text:
        return "bruteforce"
    return "cryptominer"  # 默认


class MockLLMGateway:
    """Mock LLM,根据告警场景返回预设结构化研判报告"""

    async def tier1_complete(self, messages: list[dict], **kw: Any) -> str:
        scenario = _detect_scenario(messages)
        report = PRESET_REPORTS.get(scenario, PRESET_REPORTS["cryptominer"])
        return f"[MOCK Tier1] 严重性={report.severity.value}, 场景={scenario}"

    async def tier2_complete(self, messages: list[dict], **kw: Any) -> str:
        scenario = _detect_scenario(messages)
        report = PRESET_REPORTS.get(scenario, PRESET_REPORTS["cryptominer"])
        return report.model_dump_json()

    async def tier3_complete(self, messages: list[dict], **kw: Any) -> str:
        return "[MOCK Tier3] 代码/剧本生成 (stub)"

    async def tier2_structured(
        self, messages: list[dict], schema: type[BaseModel], **kw: Any
    ) -> BaseModel:
        scenario = _detect_scenario(messages)
        report = PRESET_REPORTS.get(scenario, PRESET_REPORTS["cryptominer"])
        # 校验 schema 兼容
        if schema is JudgmentReport:
            return report
        return schema.model_validate(report.model_dump())

    async def audit_complete(self, messages: list[dict], **kw: Any) -> str:
        return "[MOCK Audit] 高风险决策审计通过"


def get_llm():
    """LLM 网关工厂: mock_mode → MockLLMGateway,否则真实 LLMGateway"""
    from app.core.config import settings

    if settings.mock_mode:
        return MockLLMGateway()
    from app.llm_gateway.client import LLMGateway

    return LLMGateway()
