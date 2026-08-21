"""威胁情报 Provider 抽象 (裁决 §3.5.1)

免费源为 Phase1 实现;付费厂商仅定义适配器类,很长一段时间不接入。
新增 provider 实现此接口,上层代码不改。
"""
from __future__ import annotations

from abc import ABC, abstractmethod

import httpx

from app.models.schemas import IntelResult


class ThreatIntelProvider(ABC):
    """威胁情报 provider 抽象接口"""

    name: str = "base"
    is_paid: bool = False  # 付费 provider 标记
    # 该 provider 支持的查询类型 (用于多源聚合时跳过不支持的)
    supports: tuple[str, ...] = ("ip", "domain", "file_hash", "url")

    @abstractmethod
    async def query_ip(self, ip: str) -> IntelResult: ...

    @abstractmethod
    async def query_domain(self, domain: str) -> IntelResult: ...

    @abstractmethod
    async def query_file_hash(self, hash: str) -> IntelResult: ...

    @abstractmethod
    async def query_url(self, url: str) -> IntelResult: ...


class ThreatIntelError(Exception):
    """情报查询失败 (触发降级)"""
    pass


# ============ Phase1 免费源实现 ============


class AbuseIPDBProvider(ThreatIntelProvider):
    """AbuseIPDB (免费,仅 IP 信誉)

    API: GET /api/v2/check?ipAddress=x&maxAgeInDays=90
    返回 abuseConfidenceScore (0-100) + isWhitelisted + usageType
    """

    name = "abuseipdb"
    supports = ("ip",)  # 仅支持 IP

    def __init__(self, api_key: str, timeout: int = 10) -> None:
        if not api_key:
            raise ThreatIntelError("AbuseIPDB api_key 未配置")
        self.api_key = api_key
        self.base_url = "https://api.abuseipdb.com/api/v2"
        self.timeout = timeout

    async def query_ip(self, ip: str) -> IntelResult:
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(
                    f"{self.base_url}/check",
                    params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
                    headers={"Key": self.api_key, "Accept": "application/json"},
                )
                resp.raise_for_status()
                data = resp.json()
        except Exception as e:  # noqa: BLE001
            raise ThreatIntelError(f"AbuseIPDB 查询失败: {e}") from e

        score = data.get("abuseConfidenceScore", 0)
        is_whitelisted = data.get("isWhitelisted", False)
        usage = data.get("usageType", "")
        domain = data.get("domain", "")

        # score 0-100 → confidence 0-1;>50 视为恶意
        confidence = min(score / 100, 1.0)
        malicious = score >= 50 and not is_whitelisted
        tags = []
        if usage:
            tags.append(usage.lower())
        if domain:
            tags.append(f"domain:{domain}")

        return IntelResult(
            indicator=ip,
            indicator_type="ip",
            provider=self.name,
            confidence=confidence,
            malicious=malicious,
            tags=tags,
            raw=data,
        )

    async def query_domain(self, domain: str) -> IntelResult:
        raise ThreatIntelError("AbuseIPDB 不支持 domain 查询")

    async def query_file_hash(self, hash: str) -> IntelResult:
        raise ThreatIntelError("AbuseIPDB 不支持 file_hash 查询")

    async def query_url(self, url: str) -> IntelResult:
        raise ThreatIntelError("AbuseIPDB 不支持 url 查询")


class OTXProvider(ThreatIntelProvider):
    """AlienVault OTX (免费,支持 IP/domain/hash/url)

    API:
      GET /api/v1/indicators/ip/{ip}/general
      GET /api/v1/indicators/domain/{domain}/general
      GET /api/v1/indicators/file/{hash}/general
      GET /api/v1/indicators/url/{url}/general
    返回 pulse_count (关联情报数),pulse_count>0 视为可疑
    """

    name = "otx"
    supports = ("ip", "domain", "file_hash", "url")

    def __init__(self, api_key: str, timeout: int = 10) -> None:
        self.api_key = api_key  # OTX 大部分 endpoint 无需 key,有则更高速率
        self.base_url = "https://otx.alienvault.com/api/v1"
        self.timeout = timeout

    async def _query_indicator(self, indicator_type: str, value: str) -> IntelResult:
        type_map = {
            "ip": "ip",
            "domain": "domain",
            "file_hash": "file",
            "url": "url",
        }
        otx_type = type_map.get(indicator_type, indicator_type)
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(
                    f"{self.base_url}/indicators/{otx_type}/{value}/general",
                    headers={"X-OTX-API-KEY": self.api_key} if self.api_key else {},
                )
                resp.raise_for_status()
                data = resp.json()
        except Exception as e:  # noqa: BLE001
            raise ThreatIntelError(f"OTX 查询失败: {e}") from e

        pulse_count = data.get("pulse_count", 0)
        # pulse_count 越多置信度越高;>3 视为恶意
        confidence = min(pulse_count / 10, 1.0)
        malicious = pulse_count >= 3

        # 提取 TTP (OTX pulses 里的 adversary TTPs)
        ttps: list[str] = []
        for pulse in (data.get("pulses", []) or [])[:5]:
            for ttp in (pulse.get("adversary_ttps") or []):
                ttps.append(ttp)

        return IntelResult(
            indicator=value,
            indicator_type=indicator_type,
            provider=self.name,
            confidence=confidence,
            malicious=malicious,
            tags=[f"pulse_count:{pulse_count}"] if pulse_count else [],
            mitre_ttps=ttps,
            raw={"pulse_count": pulse_count},
        )

    async def query_ip(self, ip: str) -> IntelResult:
        return await self._query_indicator("ip", ip)

    async def query_domain(self, domain: str) -> IntelResult:
        return await self._query_indicator("domain", domain)

    async def query_file_hash(self, hash: str) -> IntelResult:
        return await self._query_indicator("file_hash", hash)

    async def query_url(self, url: str) -> IntelResult:
        return await self._query_indicator("url", url)


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
