"""威胁情报 Provider 抽象 (裁决 §3.5.1)

免费源为 Phase1 实现;付费厂商仅定义适配器类,很长一段时间不接入。
新增 provider 实现此接口,上层代码不改。
"""
from __future__ import annotations

from abc import ABC, abstractmethod

from app.models.schemas import IntelResult


class ThreatIntelProvider(ABC):
    """威胁情报 provider 抽象接口"""

    name: str = "base"
    is_paid: bool = False  # 付费 provider 标记

    @abstractmethod
    async def query_ip(self, ip: str) -> IntelResult: ...

    @abstractmethod
    async def query_domain(self, domain: str) -> IntelResult: ...

    @abstractmethod
    async def query_file_hash(self, hash: str) -> IntelResult: ...

    @abstractmethod
    async def query_url(self, url: str) -> IntelResult: ...


# ============ Phase1 免费源实现 ============


class AbuseIPDBProvider(ThreatIntelProvider):
    """AbuseIPDB (免费,IP 信誉)"""

    name = "abuseipdb"
    is_paid = False

    def __init__(self, api_key: str) -> None:
        self.api_key = api_key
        self.base_url = "https://api.abuseipdb.com/api/v2"

    async def query_ip(self, ip: str) -> IntelResult:
        # TODO: httpx 调用 AbuseIPDB check endpoint
        return IntelResult(
            indicator=ip,
            indicator_type="ip",
            provider=self.name,
        )

    async def query_domain(self, domain: str) -> IntelResult:
        return IntelResult(indicator=domain, indicator_type="domain", provider=self.name)

    async def query_file_hash(self, hash: str) -> IntelResult:
        return IntelResult(indicator=hash, indicator_type="file_hash", provider=self.name)

    async def query_url(self, url: str) -> IntelResult:
        return IntelResult(indicator=url, indicator_type="url", provider=self.name)


class OTXProvider(ThreatIntelProvider):
    """AlienVault OTX (免费,TAXII 2.1 拉取)"""

    name = "otx"
    is_paid = False

    def __init__(self, api_key: str) -> None:
        self.api_key = api_key
        self.base_url = "https://otx.alienvault.com/api/v1"

    async def query_ip(self, ip: str) -> IntelResult:
        return IntelResult(indicator=ip, indicator_type="ip", provider=self.name)

    async def query_domain(self, domain: str) -> IntelResult:
        return IntelResult(indicator=domain, indicator_type="domain", provider=self.name)

    async def query_file_hash(self, hash: str) -> IntelResult:
        return IntelResult(indicator=hash, indicator_type="file_hash", provider=self.name)

    async def query_url(self, url: str) -> IntelResult:
        return IntelResult(indicator=url, indicator_type="url", provider=self.name)


class MISPCommunityProvider(ThreatIntelProvider):
    """MISP 社区 feed (免费)"""

    name = "misp_community"
    is_paid = False

    def __init__(self, feed_url: str) -> None:
        self.feed_url = feed_url

    async def query_ip(self, ip: str) -> IntelResult:
        return IntelResult(indicator=ip, indicator_type="ip", provider=self.name)

    async def query_domain(self, domain: str) -> IntelResult:
        return IntelResult(indicator=domain, indicator_type="domain", provider=self.name)

    async def query_file_hash(self, hash: str) -> IntelResult:
        return IntelResult(indicator=hash, indicator_type="file_hash", provider=self.name)

    async def query_url(self, url: str) -> IntelResult:
        return IntelResult(indicator=url, indicator_type="url", provider=self.name)


# ============ 付费 Provider 适配器 (仅类定义,不实现,接口预留) ============


class ThreatBookProvider(ThreatIntelProvider):
    """微步在线 X 情报云 (付费,很长一段时间不接入)

    接入时实现以下方法,调用微步 API:
      POST /api/v3/ip/reputation
      POST /api/v3/domain/reputation
      POST /api/v3/file/reputation
      POST /api/v3/url/reputation
    """

    name = "threatbook"
    is_paid = True

    def __init__(self, api_key: str) -> None:
        self.api_key = api_key  # 预留,暂不使用

    async def query_ip(self, ip: str) -> IntelResult:
        raise NotImplementedError("付费 provider 未接入,见裁决 §3.5.1")

    async def query_domain(self, domain: str) -> IntelResult:
        raise NotImplementedError("付费 provider 未接入")

    async def query_file_hash(self, hash: str) -> IntelResult:
        raise NotImplementedError("付费 provider 未接入")

    async def query_url(self, url: str) -> IntelResult:
        raise NotImplementedError("付费 provider 未接入")


class QianxinProvider(ThreatIntelProvider):
    """奇安信威胁情报中心 (付费,合规报送硬需求时接入)"""

    name = "qianxin"
    is_paid = True

    def __init__(self, api_key: str) -> None:
        self.api_key = api_key

    async def query_ip(self, ip: str) -> IntelResult:
        raise NotImplementedError("付费 provider 未接入")

    async def query_domain(self, domain: str) -> IntelResult:
        raise NotImplementedError("付费 provider 未接入")

    async def query_file_hash(self, hash: str) -> IntelResult:
        raise NotImplementedError("付费 provider 未接入")

    async def query_url(self, url: str) -> IntelResult:
        raise NotImplementedError("付费 provider 未接入")


class Qihu360Provider(ThreatIntelProvider):
    """360 威胁情报中心 (付费,兜底样本覆盖)"""

    name = "qihu360"
    is_paid = True

    def __init__(self, api_key: str) -> None:
        self.api_key = api_key

    async def query_ip(self, ip: str) -> IntelResult:
        raise NotImplementedError("付费 provider 未接入")

    async def query_domain(self, domain: str) -> IntelResult:
        raise NotImplementedError("付费 provider 未接入")

    async def query_file_hash(self, hash: str) -> IntelResult:
        raise NotImplementedError("付费 provider 未接入")

    async def query_url(self, url: str) -> IntelResult:
        raise NotImplementedError("付费 provider 未接入")


# ============ 置信度合成器 (多源交叉验证) ============


class ConfidenceSynthesizer:
    """多源置信度合成 (缓解免费源单源置信度低的问题)

    规则:
      - 多源命中 (>=2) → confidence 0.7+
      - 仅单源 → confidence 0.4 (标黄人工复核)
      - 付费源加入后 → 可提升至 0.9
    """

    async def synthesize(self, results: list[IntelResult]) -> IntelResult:
        if not results:
            return IntelResult(
                indicator="",
                indicator_type="unknown",
                provider="synthesizer",
                confidence=0.0,
            )

        hit_count = sum(1 for r in results if r.malicious)
        if hit_count >= 2:
            confidence = 0.75
        elif hit_count == 1:
            confidence = 0.45  # 标黄
        else:
            confidence = 0.1

        # 合并 TTP / tags
        all_ttps = list({ttp for r in results for ttp in r.mitre_ttps})
        all_tags = list({tag for r in results for tag in r.tags})

        return IntelResult(
            indicator=results[0].indicator,
            indicator_type=results[0].indicator_type,
            provider="synthesizer",
            confidence=confidence,
            malicious=hit_count > 0,
            tags=all_tags,
            mitre_ttps=all_ttps,
        )
