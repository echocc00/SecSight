"""Mock 威胁情报 provider (开发用)"""
from __future__ import annotations

from app.models.schemas import IntelResult
from app.threat_intel.base import ThreatIntelProvider

# 已知矿池 IP/域名 (mock 数据)
KNOWN_MINING_POOL_IPS = {
    "192.168.64.1",   # mock 矿池 IP
    "146.190.62.1",
    "45.10.0.1",
}
KNOWN_MINING_POOL_DOMAINS = {
    "pool.supportxmr.com",
    "pool.minexmr.com",
    "xmr.pool.minergate.com",
    "monero.pool.minergate.com",
}


class MockThreatIntelProvider(ThreatIntelProvider):
    """mock 情报: 已知矿池/恶意 IP 返回高置信度恶意"""

    name = "mock"
    is_paid = False

    async def query_ip(self, ip: str) -> IntelResult:
        if ip in KNOWN_MINING_POOL_IPS:
            return IntelResult(
                indicator=ip,
                indicator_type="ip",
                provider=self.name,
                confidence=0.85,
                malicious=True,
                tags=["cryptomining", "botnet", "mining-pool"],
                mitre_ttps=["T1496", "T1071.001"],
            )
        # 内网 IP 默认无害
        if ip.startswith(("10.", "172.", "192.168.")):
            return IntelResult(
                indicator=ip,
                indicator_type="ip",
                provider=self.name,
                confidence=0.1,
                malicious=False,
                tags=["internal"],
            )
        return IntelResult(
            indicator=ip, indicator_type="ip", provider=self.name, confidence=0.3
        )

    async def query_domain(self, domain: str) -> IntelResult:
        domain_lower = domain.lower()
        for pool in KNOWN_MINING_POOL_DOMAINS:
            if pool in domain_lower:
                return IntelResult(
                    indicator=domain,
                    indicator_type="domain",
                    provider=self.name,
                    confidence=0.92,
                    malicious=True,
                    tags=["mining-pool", "cryptomining"],
                    mitre_ttps=["T1496", "T1071.001"],
                )
        return IntelResult(
            indicator=domain, indicator_type="domain", provider=self.name, confidence=0.1
        )

    async def query_file_hash(self, hash: str) -> IntelResult:
        # mock: xmrig hash 命中
        if hash.startswith("a1b2c3") or "xmrig" in hash.lower():
            return IntelResult(
                indicator=hash,
                indicator_type="file_hash",
                provider=self.name,
                confidence=0.9,
                malicious=True,
                tags=["cryptominer", "xmrig"],
                mitre_ttps=["T1496"],
            )
        return IntelResult(
            indicator=hash, indicator_type="file_hash", provider=self.name, confidence=0.1
        )

    async def query_url(self, url: str) -> IntelResult:
        return IntelResult(
            indicator=url, indicator_type="url", provider=self.name, confidence=0.2
        )
