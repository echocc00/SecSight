"""威胁情报聚合服务 — 多源查询 + 置信度合成 + 降级 mock

策略:
  - 从告警提取 IoC (IP/域名/hash)
  - 并行查所有支持的 provider (AbuseIPDB 仅 IP, OTX 全类型)
  - 用 ConfidenceSynthesizer 合成多源结果
  - 真实 provider 失败/未配置 → 降级 MockThreatIntelProvider
  - 单个 provider 失败不影响其他源
"""
from __future__ import annotations

import asyncio
import ipaddress
import re
from typing import Any

import structlog

from app.models.schemas import IntelResult
from app.threat_intel.base import (
    AbuseIPDBProvider,
    OTXProvider,
    ThreatIntelError,
    ThreatIntelProvider,
)
from app.threat_intel.mock import MockThreatIntelProvider

log = structlog.get_logger()


# ============ IoC 提取 ============

_IPV4_RE = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
_DOMAIN_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(com|net|org|io|cn|ru|top|xyz|info)\b",
    re.IGNORECASE,
)
# 简化: 仅匹配 sha256 (64位十六进制) / md5 (32位)
_HASH_RE = re.compile(r"\b([a-fA-F0-9]{32}|[a-fA-F0-9]{64})\b")


def _is_public_ip(ip: str) -> bool:
    """过滤内网 IP (10./172.16-31./192.168.)"""
    try:
        addr = ipaddress.ip_address(ip)
        return not (addr.is_private or addr.is_loopback or addr.is_multicast)
    except ValueError:
        return False


def extract_iocs(alert_data: dict) -> list[tuple[str, str]]:
    """从告警数据提取 IoC → [(type, value), ...]

    type: ip | domain | file_hash
    去重 + 过滤内网 IP + 过滤已知良性域名 (mining pool mock 等留 mock provider 处理)
    """
    text = str(alert_data)
    iocs: list[tuple[str, str]] = []

    # IP
    seen: set[str] = set()
    for match in _IPV4_RE.findall(text):
        if match not in seen and _is_public_ip(match):
            iocs.append(("ip", match))
            seen.add(match)

    # 域名 (仅排除情报 API 服务域名,矿池等恶意域名必须提取为 IoC)
    api_domains = {"alienvault.com", "abuseipdb.com", "otx.alienvault.com"}
    for m in _DOMAIN_RE.finditer(text):
        domain = m.group(0).lower()
        # 去掉查询路径
        domain = domain.split("/")[0]
        if domain not in seen and not any(ad in domain for ad in api_domains):
            iocs.append(("domain", domain))
            seen.add(domain)

    # hash
    for match in _HASH_RE.findall(text):
        htype = "file_hash"
        if (htype, match) not in iocs:
            iocs.append((htype, match))

    return iocs


# ============ 聚合服务 ============


class ThreatIntelService:
    """多源情报聚合 + 降级"""

    def __init__(
        self,
        providers: list[ThreatIntelProvider],
        fallback: MockThreatIntelProvider | None = None,
        fallback_enabled: bool = True,
    ) -> None:
        self.providers = providers
        self.fallback = fallback
        self.fallback_enabled = fallback_enabled

    async def query(self, indicator_type: str, value: str) -> IntelResult:
        """查询单个 IoC,多源并行 + 合成"""
        results = await self._query_all(indicator_type, value)

        if not results:
            # 全部失败 → 降级 mock
            if self.fallback and self.fallback_enabled:
                log.warning("threat_intel.all_failed_fallback", indicator=value)
                return await self._query_fallback(indicator_type, value)
            return IntelResult(
                indicator=value,
                indicator_type=indicator_type,
                provider="none",
                confidence=0.0,
            )

        if len(results) == 1:
            return results[0]

        # 多源合成
        from app.threat_intel.base import ConfidenceSynthesizer

        synth = ConfidenceSynthesizer()
        return await synth.synthesize(results)

    async def enrich_alert(self, alert_data: dict) -> dict[str, IntelResult]:
        """富化告警: 提取 IoC + 批量查询 → {ioc_key: result}"""
        iocs = extract_iocs(alert_data)
        if not iocs:
            return {}

        tasks = {
            f"{t}:{v}": self.query(t, v) for t, v in iocs
        }
        keys = list(tasks.keys())
        coros = list(tasks.values())
        done = await asyncio.gather(*coros, return_exceptions=True)

        enriched: dict[str, IntelResult] = {}
        for key, res in zip(keys, done):
            if isinstance(res, Exception):
                log.warning("threat_intel.enrich_failed", ioc=key, error=str(res))
                continue
            enriched[key] = res
        return enriched

    async def _query_all(
        self, indicator_type: str, value: str
    ) -> list[IntelResult]:
        """并行查所有支持该类型的 provider,单个失败跳过"""
        method_map = {
            "ip": "query_ip",
            "domain": "query_domain",
            "file_hash": "query_file_hash",
            "url": "query_url",
        }
        method_name = method_map.get(indicator_type)
        if not method_name:
            return []

        async def _safe_query(p: ThreatIntelProvider) -> IntelResult | None:
            if indicator_type not in p.supports:
                return None
            try:
                fn = getattr(p, method_name)
                return await fn(value)
            except (ThreatIntelError, Exception) as e:  # noqa: BLE001
                log.warning(
                    "threat_intel.provider_failed",
                    provider=p.name,
                    indicator=value,
                    error=str(e),
                )
                return None

        results = await asyncio.gather(*[_safe_query(p) for p in self.providers])
        return [r for r in results if r is not None]

    async def _query_fallback(
        self, indicator_type: str, value: str
    ) -> IntelResult:
        if not self.fallback:
            return IntelResult(
                indicator=value, indicator_type=indicator_type, provider="none"
            )
        method_map = {
            "ip": self.fallback.query_ip,
            "domain": self.fallback.query_domain,
            "file_hash": self.fallback.query_file_hash,
            "url": self.fallback.query_url,
        }
        fn = method_map.get(indicator_type)
        if not fn:
            return IntelResult(
                indicator=value, indicator_type=indicator_type, provider="none"
            )
        return await fn(value)


# ============ 工厂 ============


def get_threat_intel_service() -> ThreatIntelService:
    """情报服务工厂

    mock_mode=True 或 enable_threat_intel=False → 纯 mock
    否则 → 真实 AbuseIPDB+OTX + mock 降级
    """
    from app.core.config import settings

    mock = MockThreatIntelProvider()

    if settings.mock_mode or not settings.enable_threat_intel:
        return ThreatIntelService(providers=[mock], fallback=None, fallback_enabled=False)

    providers: list[ThreatIntelProvider] = []
    if settings.abuseipdb_api_key:
        try:
            providers.append(
                AbuseIPDBProvider(settings.abuseipdb_api_key, settings.threat_intel_timeout_seconds)
            )
        except ThreatIntelError as e:
            log.warning("threat_intel.abuseipdb_init_failed", error=str(e))
    if settings.otx_api_key or True:  # OTX 无 key 也能用 (限速)
        providers.append(
            OTXProvider(settings.otx_api_key, settings.threat_intel_timeout_seconds)
        )

    if not providers:
        log.warning("threat_intel.no_real_providers_fallback_mock")
        return ThreatIntelService(providers=[mock], fallback=None, fallback_enabled=False)

    return ThreatIntelService(
        providers=providers,
        fallback=mock,
        fallback_enabled=settings.threat_intel_fallback_to_mock,
    )
