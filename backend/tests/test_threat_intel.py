"""威胁情报测试 — 置信度合成 + mock provider"""
from __future__ import annotations

import pytest

from app.models.schemas import IntelResult
from app.threat_intel.base import ConfidenceSynthesizer
from app.threat_intel.mock import MockThreatIntelProvider


class TestConfidenceSynthesizer:
    @pytest.mark.asyncio
    async def test_multi_source_hits_yield_high_confidence(self):
        synth = ConfidenceSynthesizer()
        results = [
            IntelResult(indicator="1.2.3.4", indicator_type="ip", provider="a", malicious=True),
            IntelResult(indicator="1.2.3.4", indicator_type="ip", provider="b", malicious=True),
        ]
        merged = await synth.synthesize(results)
        assert merged.confidence >= 0.7
        assert merged.malicious is True

    @pytest.mark.asyncio
    async def test_single_source_yields_medium_confidence(self):
        synth = ConfidenceSynthesizer()
        results = [
            IntelResult(indicator="1.2.3.4", indicator_type="ip", provider="a", malicious=True),
            IntelResult(indicator="1.2.3.4", indicator_type="ip", provider="b", malicious=False),
        ]
        merged = await synth.synthesize(results)
        assert 0.4 <= merged.confidence < 0.7

    @pytest.mark.asyncio
    async def test_no_hits_yield_low_confidence(self):
        synth = ConfidenceSynthesizer()
        results = [
            IntelResult(indicator="1.2.3.4", indicator_type="ip", provider="a", malicious=False),
        ]
        merged = await synth.synthesize(results)
        assert merged.confidence < 0.4
        assert merged.malicious is False

    @pytest.mark.asyncio
    async def test_empty_results_return_zero_confidence(self):
        synth = ConfidenceSynthesizer()
        merged = await synth.synthesize([])
        assert merged.confidence == 0.0

    @pytest.mark.asyncio
    async def test_merges_ttps_and_tags_across_sources(self):
        synth = ConfidenceSynthesizer()
        results = [
            IntelResult(indicator="x", indicator_type="ip", provider="a", malicious=True, mitre_ttps=["T1496"], tags=["mining"]),
            IntelResult(indicator="x", indicator_type="ip", provider="b", malicious=True, mitre_ttps=["T1071"], tags=["botnet"]),
        ]
        merged = await synth.synthesize(results)
        assert set(merged.mitre_ttps) == {"T1496", "T1071"}
        assert set(merged.tags) == {"mining", "botnet"}


class TestMockThreatIntelProvider:
    @pytest.mark.asyncio
    async def test_known_mining_pool_ip_is_malicious(self):
        p = MockThreatIntelProvider()
        r = await p.query_ip("192.168.64.1")
        assert r.malicious is True
        assert r.confidence > 0.7

    @pytest.mark.asyncio
    async def test_internal_ip_is_benign(self):
        p = MockThreatIntelProvider()
        r = await p.query_ip("10.0.0.5")
        assert r.malicious is False

    @pytest.mark.asyncio
    async def test_known_mining_domain_is_malicious(self):
        p = MockThreatIntelProvider()
        r = await p.query_domain("pool.supportxmr.com")
        assert r.malicious is True
        assert "T1496" in r.mitre_ttps

    @pytest.mark.asyncio
    async def test_unknown_domain_is_benign(self):
        p = MockThreatIntelProvider()
        r = await p.query_domain("example.com")
        assert r.malicious is False

    @pytest.mark.asyncio
    async def test_xmrig_hash_is_malicious(self):
        p = MockThreatIntelProvider()
        r = await p.query_file_hash("xmrig-abc123")
        assert r.malicious is True
