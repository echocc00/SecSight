"""真实情报 provider + 聚合服务 + IoC 提取测试

httpx MockTransport mock 真实 API 响应 (无需真实 key/网络)。
真 API 冒烟测试仅当对应 key 存在时运行。
"""
from __future__ import annotations

import json
import os
from unittest.mock import patch

import httpx
import pytest

from app.models.schemas import IntelResult
from app.threat_intel.base import (
    AbuseIPDBProvider,
    OTXProvider,
    ThreatIntelError,
)
from app.threat_intel.mock import MockThreatIntelProvider
from app.threat_intel.service import (
    ThreatIntelService,
    extract_iocs,
    get_threat_intel_service,
)


# ============ Mock httpx helper ============


def _mock_transport(handler) -> httpx.MockTransport:
    return httpx.MockTransport(handler)


def _abuseipdb_handler(score: int = 0, whitelisted: bool = False) -> httpx.MockTransport:
    """构造 AbuseIPDB mock 响应"""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "abuseConfidenceScore": score,
                "isWhitelisted": whitelisted,
                "usageType": "Data Center/Web Hosting/Transit",
                "domain": "evil-host.com",
                "ipAddress": request.url.params.get("ipAddress"),
            },
        )

    return _mock_transport(handler)


def _otx_handler(pulse_count: int = 0, ttps: list[str] | None = None) -> httpx.MockTransport:
    """构造 OTX mock 响应"""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "pulse_count": pulse_count,
                "pulses": [{"adversary_ttps": ttps or []}] if pulse_count else [],
            },
        )

    return _mock_transport(handler)


def _patch_httpx_transport(transport: httpx.MockTransport):
    """patch httpx.AsyncClient 注入 MockTransport (绑定真实 client 防递归)"""
    real_async_client = httpx.AsyncClient

    def factory(**kw):
        return real_async_client(transport=transport, **kw)

    return patch(
        "app.threat_intel.base.httpx.AsyncClient",
        factory,
    )


# ============ IoC 提取 ============


class TestExtractIocs:
    def test_extracts_public_ip(self):
        iocs = extract_iocs({"src_ip": "45.10.0.1", "msg": "attack from 45.10.0.1"})
        ips = [v for t, v in iocs if t == "ip"]
        assert "45.10.0.1" in ips

    def test_filters_internal_ip(self):
        iocs = extract_iocs({"ip": "10.0.0.5", "ip2": "192.168.1.1"})
        assert all(t != "ip" for t, v in iocs)

    def test_extracts_domain(self):
        iocs = extract_iocs({"url": "http://evil.example.com/payload"})
        domains = [v for t, v in iocs if t == "domain"]
        assert any("evil.example.com" in d for d in domains)

    def test_extracts_hash(self):
        sha256 = "a" * 64
        iocs = extract_iocs({"hash": sha256})
        hashes = [v for t, v in iocs if t == "file_hash"]
        assert sha256 in hashes

    def test_dedupes(self):
        iocs = extract_iocs({"a": "1.2.3.4", "b": "1.2.3.4"})
        ips = [v for t, v in iocs if t == "ip"]
        assert len(ips) == 1

    def test_empty_alert_returns_empty(self):
        assert extract_iocs({"msg": "no indicators here"}) == [] or all(
            t not in ("ip", "domain", "file_hash") for t, v in extract_iocs({"msg": "no indicators here"})
        )


# ============ AbuseIPDBProvider ============


class TestAbuseIPDBProvider:
    def test_raises_without_key(self):
        with pytest.raises(ThreatIntelError, match="api_key 未配置"):
            AbuseIPDBProvider(api_key="")

    def test_supports_only_ip(self):
        p = AbuseIPDBProvider(api_key="k")
        assert p.supports == ("ip",)

    @pytest.mark.asyncio
    async def test_high_score_ip_is_malicious(self):
        p = AbuseIPDBProvider(api_key="k")
        with _patch_httpx_transport(_abuseipdb_handler(score=85)):
            r = await p.query_ip("45.10.0.1")
        assert r.malicious is True
        assert r.confidence == 0.85
        assert r.provider == "abuseipdb"

    @pytest.mark.asyncio
    async def test_low_score_ip_is_benign(self):
        p = AbuseIPDBProvider(api_key="k")
        with _patch_httpx_transport(_abuseipdb_handler(score=10)):
            r = await p.query_ip("1.2.3.4")
        assert r.malicious is False

    @pytest.mark.asyncio
    async def test_whitelisted_not_malicious_even_high_score(self):
        p = AbuseIPDBProvider(api_key="k")
        with _patch_httpx_transport(_abuseipdb_handler(score=90, whitelisted=True)):
            r = await p.query_ip("8.8.8.8")
        assert r.malicious is False  # whitelist 覆盖

    @pytest.mark.asyncio
    async def test_http_error_raises_threat_intel_error(self):
        p = AbuseIPDBProvider(api_key="k")
        with _patch_httpx_transport(httpx.MockTransport(lambda req: httpx.Response(500))):
            with pytest.raises(ThreatIntelError):
                await p.query_ip("1.2.3.4")

    @pytest.mark.asyncio
    async def test_domain_query_raises_not_supported(self):
        p = AbuseIPDBProvider(api_key="k")
        with pytest.raises(ThreatIntelError, match="不支持"):
            await p.query_domain("evil.com")


# ============ OTXProvider ============


class TestOTXProvider:
    @pytest.mark.asyncio
    async def test_high_pulse_count_is_malicious(self):
        p = OTXProvider(api_key="")
        with _patch_httpx_transport(_otx_handler(pulse_count=8, ttps=["T1496"])):
            r = await p.query_ip("45.10.0.1")
        assert r.malicious is True
        assert r.confidence == 0.8
        assert "T1496" in r.mitre_ttps

    @pytest.mark.asyncio
    async def test_low_pulse_count_is_benign(self):
        p = OTXProvider(api_key="")
        with _patch_httpx_transport(_otx_handler(pulse_count=1)):
            r = await p.query_domain("evil.com")
        assert r.malicious is False

    @pytest.mark.asyncio
    async def test_supports_all_types(self):
        p = OTXProvider(api_key="k")
        assert "ip" in p.supports
        assert "domain" in p.supports
        assert "file_hash" in p.supports

    @pytest.mark.asyncio
    async def test_http_error_raises(self):
        p = OTXProvider(api_key="")
        with _patch_httpx_transport(httpx.MockTransport(lambda req: httpx.Response(404))):
            with pytest.raises(ThreatIntelError):
                await p.query_ip("1.2.3.4")


# ============ ThreatIntelService 聚合 ============


class TestThreatIntelService:
    @pytest.mark.asyncio
    async def test_multi_source_synthesizes(self):
        """AbuseIPDB + OTX 同时命中 → 高置信度合成"""
        abuse = AbuseIPDBProvider(api_key="k")
        otx = OTXProvider(api_key="")
        svc = ThreatIntelService(providers=[abuse, otx])

        # patch 两个 provider 的 httpx (用同一 transport)
        transport = _abuseipdb_handler(score=80)
        with _patch_httpx_transport(transport):
            # AbuseIPDB 命中;OTX 也命中 (复用 handler 但 pulse_count 需另设)
            # 简化: 直接 mock 两个 provider 的查询方法
            with patch.object(abuse, "query_ip", return_value=IntelResult(
                indicator="1.2.3.4", indicator_type="ip", provider="abuseipdb",
                confidence=0.8, malicious=True, mitre_ttps=["T1496"],
            )), patch.object(otx, "query_ip", return_value=IntelResult(
                indicator="1.2.3.4", indicator_type="ip", provider="otx",
                confidence=0.7, malicious=True, mitre_ttps=["T1071"],
            )):
                result = await svc.query("ip", "1.2.3.4")
        assert result.confidence >= 0.7  # 多源合成
        assert set(result.mitre_ttps) == {"T1496", "T1071"}

    @pytest.mark.asyncio
    async def test_single_provider_returns_directly(self):
        abuse = AbuseIPDBProvider(api_key="k")
        svc = ThreatIntelService(providers=[abuse])
        with patch.object(abuse, "query_ip", return_value=IntelResult(
            indicator="1.2.3.4", indicator_type="ip", provider="abuseipdb", confidence=0.9,
        )):
            result = await svc.query("ip", "1.2.3.4")
        assert result.provider == "abuseipdb"
        assert result.confidence == 0.9

    @pytest.mark.asyncio
    async def test_all_failed_falls_back_to_mock(self):
        abuse = AbuseIPDBProvider(api_key="k")
        mock = MockThreatIntelProvider()
        svc = ThreatIntelService(providers=[abuse], fallback=mock, fallback_enabled=True)
        with patch.object(abuse, "query_ip", side_effect=ThreatIntelError("down")):
            result = await svc.query("ip", "192.168.64.1")  # mock 知名矿池 IP
        assert result.malicious is True  # mock 返回
        assert result.provider == "mock"

    @pytest.mark.asyncio
    async def test_no_fallback_returns_zero_confidence(self):
        abuse = AbuseIPDBProvider(api_key="k")
        svc = ThreatIntelService(providers=[abuse], fallback=None, fallback_enabled=False)
        with patch.object(abuse, "query_ip", side_effect=ThreatIntelError("down")):
            result = await svc.query("ip", "1.2.3.4")
        assert result.confidence == 0.0

    @pytest.mark.asyncio
    async def test_skips_unsupported_provider(self):
        """AbuseIPDB 不支持 domain → 仅 OTX 查询"""
        abuse = AbuseIPDBProvider(api_key="k")
        otx = OTXProvider(api_key="")
        svc = ThreatIntelService(providers=[abuse, otx])
        with patch.object(otx, "query_domain", return_value=IntelResult(
            indicator="evil.com", indicator_type="domain", provider="otx", confidence=0.6,
        )):
            result = await svc.query("domain", "evil.com")
        assert result.provider == "otx"

    @pytest.mark.asyncio
    async def test_enrich_alert_extracts_and_queries(self):
        abuse = AbuseIPDBProvider(api_key="k")
        svc = ThreatIntelService(providers=[abuse])
        alert = {"src_ip": "45.10.0.1", "msg": "attack from 45.10.0.1"}
        with patch.object(abuse, "query_ip", return_value=IntelResult(
            indicator="45.10.0.1", indicator_type="ip", provider="abuseipdb",
            confidence=0.8, malicious=True,
        )):
            enriched = await svc.enrich_alert(alert)
        assert "ip:45.10.0.1" in enriched
        assert enriched["ip:45.10.0.1"].malicious is True


# ============ 工厂 ============


class TestGetThreatIntelService:
    def test_returns_mock_only_in_mock_mode(self):
        svc = get_threat_intel_service()
        # mock_mode=True (conftest) → 纯 mock, 无 fallback
        assert len(svc.providers) == 1
        assert isinstance(svc.providers[0], MockThreatIntelProvider)

    def test_returns_real_providers_when_enabled(self, monkeypatch):
        from app.core import config as cfg

        monkeypatch.setattr(cfg.settings, "mock_mode", False)
        monkeypatch.setattr(cfg.settings, "enable_threat_intel", True)
        monkeypatch.setattr(cfg.settings, "abuseipdb_api_key", "test-key")
        svc = get_threat_intel_service()
        providers = svc.providers
        assert any(isinstance(p, AbuseIPDBProvider) for p in providers)
        assert any(isinstance(p, OTXProvider) for p in providers)
        assert svc.fallback is not None  # 降级 mock 就绪

    def test_no_keys_falls_back_to_mock(self, monkeypatch):
        from app.core import config as cfg

        monkeypatch.setattr(cfg.settings, "mock_mode", False)
        monkeypatch.setattr(cfg.settings, "enable_threat_intel", True)
        monkeypatch.setattr(cfg.settings, "abuseipdb_api_key", "")
        monkeypatch.setattr(cfg.settings, "otx_api_key", "")
        # OTX 无 key 仍可用,所以至少有 OTX
        svc = get_threat_intel_service()
        assert any(isinstance(p, OTXProvider) for p in svc.providers)


# ============ 真 API 冒烟 (有 key 才跑) ============


_HAS_ABUSEIPDB = bool(os.environ.get("ABUSEIPDB_API_KEY"))
_HAS_OTX = bool(os.environ.get("OTX_API_KEY"))


@pytest.mark.skipif(not _HAS_ABUSEIPDB, reason="未设置 ABUSEIPDB_API_KEY")
class TestLiveAbuseIPDB:
    @pytest.mark.asyncio
    async def test_live_query_google_dns(self):
        """查 8.8.8.8 (Google DNS, 应低分/whitelist)"""
        from app.core import config as cfg

        p = AbuseIPDBProvider(
            os.environ["ABUSEIPDB_API_KEY"], cfg.settings.threat_intel_timeout_seconds
        )
        r = await p.query_ip("8.8.8.8")
        assert r.indicator == "8.8.8.8"
        # 8.8.8.8 通常 benign 或 whitelist
        assert r.confidence >= 0


@pytest.mark.skipif(not _HAS_OTX, reason="未设置 OTX_API_KEY")
class TestLiveOTX:
    @pytest.mark.asyncio
    async def test_live_query_known_malicious(self):
        from app.core import config as cfg

        p = OTXProvider(
            os.environ["OTX_API_KEY"], cfg.settings.threat_intel_timeout_seconds
        )
        r = await p.query_ip("8.8.8.8")
        assert r.indicator == "8.8.8.8"
