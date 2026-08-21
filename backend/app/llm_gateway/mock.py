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
    "web_attack": JudgmentReport(
        incident_summary="检测到 SQL 注入尝试,攻击者尝试绕过登录认证",
        severity=Severity.high,
        ttps=["T1190"],
        kill_chain_phase="initial-access",
        true_positive="yes",
        confidence=0.85,
        recommended_actions=[ActionType.block_ip],
        rationale="URL 含 ' OR 1=1-- 经典 SQL 注入载荷,响应码 200 提示可能成功,需封禁源 IP 并修补漏洞。",
        citations=["attck:T1190"],
    ),
    "data_exfiltration": JudgmentReport(
        incident_summary="检测到 8.2GB 数据外传至未知域名 exfil.evil.com",
        severity=Severity.critical,
        ttps=["T1048", "T1567"],
        kill_chain_phase="exfiltration",
        true_positive="yes",
        confidence=0.9,
        recommended_actions=[ActionType.block_ip, ActionType.block_domain, ActionType.isolate_host],
        rationale="异常大流量外传至可疑域名,目标 IP 情报待查,需立即封禁+隔离+24h 合规上报。",
        citations=["attck:T1048", "attck:T1567"],
    ),
    "lateral_movement": JudgmentReport(
        incident_summary="检测到 SMB 管理共享 + PsExec 横向移动到 10.0.2.20",
        severity=Severity.high,
        ttps=["T1021", "T1570"],
        kill_chain_phase="lateral-movement",
        true_positive="yes",
        confidence=0.83,
        recommended_actions=[ActionType.isolate_host, ActionType.block_ip],
        rationale="PsExec 访问 ADMIN$ 共享是典型横向手法,需隔离源主机+目标,重置凭据。",
        citations=["attck:T1021", "attck:T1570"],
    ),
    "privilege_escalation": JudgmentReport(
        incident_summary="www-data 用户执行 sudo -i 提权至 root",
        severity=Severity.critical,
        ttps=["T1068", "T1548.001"],
        kill_chain_phase="privilege-escalation",
        true_positive="yes",
        confidence=0.88,
        recommended_actions=[ActionType.isolate_host, ActionType.kill_process],
        rationale="Web 服务账户不应有 sudo 权限,提权成功意味着系统被完全控制,需立即隔离+排查漏洞。",
        citations=["attck:T1068"],
    ),
    "c2_communication": JudgmentReport(
        incident_summary="检测到 60 秒周期信标流量到 c2.evil-bot.net",
        severity=Severity.high,
        ttps=["T1071", "T1573"],
        kill_chain_phase="command-and-control",
        true_positive="yes",
        confidence=0.87,
        recommended_actions=[ActionType.block_ip, ActionType.block_domain, ActionType.isolate_host],
        rationale="固定周期小流量外联是 C2 信标特征,域名含 evil-bot 提示恶意,需封禁+隔离+取证。",
        citations=["attck:T1071"],
    ),
    "phishing": JudgmentReport(
        incident_summary="检测到钓鱼邮件含恶意附件 invoice.xlsm,42 人收到",
        severity=Severity.medium,
        ttps=["T1566", "T1566.001"],
        kill_chain_phase="initial-access",
        true_positive="yes",
        confidence=0.78,
        recommended_actions=[ActionType.quarantine_file, ActionType.block_domain, ActionType.notify],
        rationale="伪造 HR 邮箱发送宏附件,典型钓鱼,需隔离邮件+封禁发件人+通知收件人。",
        citations=["attck:T1566"],
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
    # Phase2 P1
    if "t1190" in text or "sql injection" in text or "web_attack" in text:
        return "web_attack"
    if "t1048" in text or "exfiltration" in text or "data_exfil" in text:
        return "data_exfiltration"
    if "t1021" in text or "t1570" in text or "lateral" in text or "psexec" in text:
        return "lateral_movement"
    if "t1068" in text or "privilege" in text or "sudo -i" in text:
        return "privilege_escalation"
    if "t1071" in text or "c2_beacon" in text or "beacon" in text or "c2_communication" in text:
        return "c2_communication"
    if "t1566" in text or "phishing" in text or "invoice.xlsm" in text:
        return "phishing"
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
    """LLM 网关工厂

    mock_mode=True  → MockLLMGateway (预设报告,无需 key)
    mock_mode=False → ResilientLLMGateway (真 LLM 主 + 故障降级 mock)
                      provider 由 settings.llm_provider 决定 (minimax | litellm)
    """
    from app.core.config import settings

    if settings.mock_mode:
        return MockLLMGateway()

    from app.llm_gateway.provider import RealLLMProvider
    from app.llm_gateway.resilient import ResilientLLMGateway

    if settings.llm_provider == "litellm":
        real = RealLLMProvider(
            base_url=settings.litellm_base_url,
            api_key=settings.litellm_master_key,
            model=settings.model_tier2,
            timeout=settings.llm_timeout_seconds,
        )
    else:  # minimax 直连 (默认)
        real = RealLLMProvider(
            base_url=settings.minimax_base_url,
            api_key=settings.minimax_api_key,
            model=settings.minimax_model,
            timeout=settings.llm_timeout_seconds,
        )
    return ResilientLLMGateway(
        real=real,
        fallback=MockLLMGateway(),
        fallback_enabled=settings.llm_fallback_to_mock,
    )
