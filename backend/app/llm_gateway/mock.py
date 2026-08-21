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
        ttps=["T1110", "T1110.001"],
        kill_chain_phase="credential-access",
        true_positive="yes",
        confidence=0.82,
        recommended_actions=[
            ActionType.block_ip,
            ActionType.freeze_account,
        ],
        rationale="5 分钟内 247 次认证失败,源 IP 情报标记恶意,暂判定为撞库攻击。",
        citations=["attck:T1110", "intel:45.10.0.1"],
    ),
    "persistence": JudgmentReport(
        incident_summary="检测到 crontab 持久化植入,远程 payload 定时执行",
        severity=Severity.high,
        ttps=["T1053.003"],
        kill_chain_phase="persistence",
        true_positive="yes",
        confidence=0.86,
        recommended_actions=[
            ActionType.isolate_host,
            ActionType.kill_process,
            ActionType.quarantine_file,
        ],
        rationale="crontab 新增每分钟 curl|bash 远程脚本执行,典型持久化后门,需清除并排查横向。",
        citations=["attck:T1053.003"],
    ),
    "log_compliance": JudgmentReport(
        incident_summary="日志采集中断 18 分钟,agent 断连,存在检测盲区与合规风险",
        severity=Severity.medium,
        ttps=["T1562", "T1562.008"],
        kill_chain_phase="defense-evasion",
        true_positive="uncertain",
        confidence=0.6,
        recommended_actions=[
            ActionType.service_restart,
            ActionType.query_asset,
        ],
        rationale="filebeat agent 断连 18 分钟,需确认是故障还是人为停止,恢复采集并评估日志缺口。",
        citations=["attck:T1562"],
    ),
    "service_crash": JudgmentReport(
        incident_summary="关键服务 nginx 被 SIGKILL 终止,疑似恶意 kill,业务中断",
        severity=Severity.high,
        ttps=["T1489"],
        kill_chain_phase="impact",
        true_positive="yes",
        confidence=0.8,
        recommended_actions=[
            ActionType.service_restart,
            ActionType.query_asset,
        ],
        rationale="nginx 被 kill -9 终止,来源进程/用户未知,需重启恢复并排查是否恶意,必要时封禁来源。",
        citations=["attck:T1489"],
    ),
}


def _detect_scenario(messages: list[dict]) -> str:
    """从 prompt 内容推断场景类型

    优先按告警自带 MITRE 技术 ID 精确判定 (不受召回知识污染),
    关键词作兜底。
    """
    text = " ".join(str(m.get("content", "")) for m in messages).lower()
    # 技术 ID 精确匹配 (告警 scene_hint 携带)
    if "t1496" in text:
        return "cryptominer"
    if "t1486" in text:
        return "ransomware"
    if "t1110" in text:
        return "bruteforce"
    if "t1053" in text:
        return "persistence"
    if "t1562" in text:
        return "log_compliance"
    if "t1489" in text:
        return "service_crash"
    # 关键词兜底
    if "xmrig" in text or "stratum" in text or "mining" in text:
        return "cryptominer"
    if "ransomware" in text or "encrypt" in text:
        return "ransomware"
    if "brute" in text or "authentication fail" in text:
        return "bruteforce"
    if "crontab" in text or "authorized_keys" in text:
        return "persistence"
    if "log collection" in text or "filebeat" in text:
        return "log_compliance"
    if "sigkill" in text or "kill -9" in text:
        return "service_crash"
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
