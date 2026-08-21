"""RAG 检索层 (mock + 真实接口)"""
from __future__ import annotations

from abc import ABC, abstractmethod


class KnowledgeRetriever(ABC):
    """知识检索抽象"""

    @abstractmethod
    async def search(self, query: str | list[dict], top_k: int = 5) -> list[dict]: ...


# 预设 ATT&CK 知识 chunks (mock)
_MOCK_KNOWLEDGE: list[dict] = [
    {
        "id": "attck:T1496",
        "type": "technique",
        "name": "Resource Hijacking",
        "tactic": "TA0040 Impact",
        "description": "攻击者劫持系统资源执行计算密集型任务,典型如加密货币挖矿。",
        "detection": "高 CPU + 可疑进程(xmrig/minerd) + 矿池域名/端口(3333/4444/5555)",
        "mitigation": "隔离主机 + kill 进程 + 清理持久化 + 封禁矿池域名",
    },
    {
        "id": "attck:T1071.001",
        "type": "technique",
        "name": "Web Protocols",
        "tactic": "TA0011 Command and Control",
        "description": "使用 Web 协议(HTTP/HTTPS/Stratum)进行 C2 通信。",
        "detection": "Suricata 矿池 Stratum 协议规则 + 异常出站连接",
        "mitigation": "阻断 C2 域名/IP + DNS 黑洞",
    },
    {
        "id": "attck:T1486",
        "type": "technique",
        "name": "Data Encrypted for Impact",
        "tactic": "TA0040 Impact",
        "description": "勒索软件加密用户数据以勒索赎金。",
        "detection": "批量文件高熵修改 + 加密后缀 + vssadmin delete shadows",
        "mitigation": "立即隔离主机 + 阻断 C2 + 评估备份恢复",
    },
    {
        "id": "case_hist:2025-cryptominer-001",
        "type": "case",
        "name": "2025 挖矿事件案例",
        "description": "web-prod-01 感染 xmrig,经 Web 漏洞入侵,持久化在 crontab。",
        "iocs": ["xmrig hash", "pool.supportxmr.com", "192.168.64.1"],
        "lessons": "清理 crontab + systemd 双持久化点,封矿池域名。",
    },
    {
        "id": "attck:T1053.003",
        "type": "technique",
        "name": "Cron",
        "tactic": "TA0003 Persistence",
        "description": "利用 cron 定时任务实现持久化,定时执行恶意脚本。",
        "detection": "FIM 监控 /var/spool/cron + crontab 修改 + curl|bash 定时任务",
        "mitigation": "清除恶意 crontab 条目 + 隔离主机 + 排查横向",
    },
    {
        "id": "attck:T1110",
        "type": "technique",
        "name": "Brute Force",
        "tactic": "TA0006 Credential Access",
        "description": "暴力破解/撞库获取凭据,SSH/RDP 常见。",
        "detection": "短时间大量认证失败 (Wazuh 5710/5712) + 源 IP 情报",
        "mitigation": "封禁源 IP + 冻结账户 + 强制 MFA + 登录限速",
    },
    {
        "id": "attck:T1562",
        "type": "technique",
        "name": "Impair Defenses",
        "tactic": "TA0005 Defense Evasion",
        "description": "削弱/禁用防御,如停止日志采集、关闭 EDR。",
        "detection": "agent 断连 + 日志断流 + 采集服务被停止",
        "mitigation": "重启采集服务 + 验证日志恢复 + 评估缺口",
    },
    {
        "id": "attck:T1489",
        "type": "technique",
        "name": "Service Stop",
        "tactic": "TA0040 Impact",
        "description": "停止关键服务造成业务中断。",
        "detection": "关键进程被 SIGKILL + systemctl stop + 服务健康检查失败",
        "mitigation": "重启服务 + 排查恶意来源 + 启用守护",
    },
]


class MockRetriever(KnowledgeRetriever):
    """mock 检索: 关键词匹配预设知识"""

    async def search(self, query: str | list[dict], top_k: int = 5) -> list[dict]:
        text = (
            query
            if isinstance(query, str)
            else " ".join(str(m.get("content", "")) for m in query)
        ).lower()

        scored: list[tuple[float, dict]] = []
        for chunk in _MOCK_KNOWLEDGE:
            score = 0.0
            blob = (chunk.get("name", "") + " " + chunk.get("description", "") + " " + chunk.get("id", "")).lower()
            keywords = [
                "xmrig", "mining", "stratum", "t1496", "t1071", "cryptominer",
                "ransomware", "t1486", "encrypt",
                "crontab", "t1053", "persistence", "cron",
                "brute", "t1110", "authentication",
                "log collection", "t1562", "filebeat", "agent",
                "service", "t1489", "sigkill", "nginx",
            ]
            for kw in keywords:
                if kw in text and kw in blob:
                    score += 1.0
                elif kw in text and any(kw in c.lower() for c in chunk.values() if isinstance(c, str)):
                    score += 0.3
            if score > 0:
                scored.append((score, chunk))

        scored.sort(key=lambda x: x[0], reverse=True)
        return [c for _, c in scored[:top_k]]


class QdrantRetriever(KnowledgeRetriever):
    """真实 Qdrant 检索 (Phase2 接入)

    实现:
      1. embedding = BGE-m3(query)
      2. Qdrant HNSW search top_k=20
      3. BGE-reranker-v2-m3 cross-encoder 截 top 5
      4. 返回 chunks
    """

    async def search(self, query: str | list[dict], top_k: int = 5) -> list[dict]:
        raise NotImplementedError("Qdrant retriever 未实现,当前用 MockRetriever")


def get_retriever() -> KnowledgeRetriever:
    from app.core.config import settings

    if settings.mock_mode:
        return MockRetriever()
    return QdrantRetriever()  # Phase2 实现后切换
