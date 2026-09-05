"""OpenCTI 集成 — GraphQL 客户端 / APT 归因 / provider 接线 / 降级

全部用 mock HTTP,不需要真实 OpenCTI 容器。真实容器冒烟设
SECSIGHT_OPENCTI_LIVE=1 + OPENCTI_ADMIN_TOKEN。
"""
from __future__ import annotations

import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.integrations.opencti import (
    OpenCTIClient,
    OpenCTIError,
    OpenCTIProvider,
    health_check,
)


def _observable_payload(
    score: int = 80,
    indicators: list[dict] | None = None,
    labels: list[str] | None = None,
) -> dict:
    return {
        "data": {
            "stixCyberObservables": {
                "edges": [
                    {
                        "node": {
                            "id": "obs-1",
                            "entity_type": "IPv4-Addr",
                            "observable_value": "45.33.32.156",
                            "x_opencti_score": score,
                            "objectLabel": [{"value": lbl} for lbl in (labels or [])],
                            "indicators": {
                                "edges": [
                                    {"node": ind} for ind in (indicators or [])
                                ]
                            },
                            "reports": {"edges": []},
                        }
                    }
                ]
            }
        }
    }


def _attribution_payload(
    intrusion_set: str | None = "APT41",
    technique: str | None = "T1496",
    malware: str | None = None,
) -> dict:
    edges = []
    if intrusion_set:
        edges.append(
            {
                "node": {
                    "relationship_type": "attributed-to",
                    "confidence": 85,
                    "from": {
                        "id": "is-1",
                        "name": intrusion_set,
                        "aliases": ["Winnti"],
                        "description": "",
                    },
                    "to": {},
                }
            }
        )
    if technique:
        edges.append(
            {
                "node": {
                    "relationship_type": "uses",
                    "confidence": 70,
                    "from": {},
                    "to": {"id": "ap-1", "name": "Resource Hijacking", "x_mitre_id": technique},
                }
            }
        )
    if malware:
        edges.append(
            {
                "node": {
                    "relationship_type": "related-to",
                    "confidence": 60,
                    "from": {"id": "mw-1", "name": malware, "malware_types": ["miner"]},
                    "to": {},
                }
            }
        )
    return {"data": {"stixCoreObject": {"id": "obs-1", "stixCoreRelationships": {"edges": edges}}}}


class _FakeResponse:
    def __init__(self, payload: dict, status: int = 200) -> None:
        self._payload = payload
        self.status_code = status

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")

    def json(self) -> dict:
        return self._payload


def _mock_post(payloads: list[dict]):
    """按调用顺序返回 payload (observable 查询 → attribution 查询)"""
    calls = {"n": 0}

    async def _post(url, **kwargs):
        idx = min(calls["n"], len(payloads) - 1)
        calls["n"] += 1
        return _FakeResponse(payloads[idx])

    return _post, calls


def _patched_client(payloads: list[dict]):
    post, calls = _mock_post(payloads)
    client = MagicMock()
    client.post = post
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=False)
    return patch("httpx.AsyncClient", return_value=client), calls


class TestClientConstruction:
    def test_requires_token(self):
        with pytest.raises(OpenCTIError):
            OpenCTIClient("http://opencti:8080", "")

    def test_strips_trailing_slash(self):
        client = OpenCTIClient("http://opencti:8080/", "tok")
        assert client.base_url == "http://opencti:8080"


class TestGraphQLErrorHandling:
    async def test_graphql_errors_raise(self):
        """GraphQL 200 也可能带 errors —— 不检查会把失败当成"查无此 IoC\""""
        ctx, _ = _patched_client([{"errors": [{"message": "Not authorized"}]}])
        with ctx:
            client = OpenCTIClient("http://opencti:8080", "tok")
            with pytest.raises(OpenCTIError, match="Not authorized"):
                await client.search_observable("ip", "1.2.3.4")

    async def test_http_failure_raises(self):
        client_mock = MagicMock()
        client_mock.post = AsyncMock(side_effect=RuntimeError("connection refused"))
        client_mock.__aenter__ = AsyncMock(return_value=client_mock)
        client_mock.__aexit__ = AsyncMock(return_value=False)
        with patch("httpx.AsyncClient", return_value=client_mock):
            client = OpenCTIClient("http://opencti:8080", "tok")
            with pytest.raises(OpenCTIError, match="请求失败"):
                await client.search_observable("ip", "1.2.3.4")

    async def test_unknown_indicator_type_raises(self):
        client = OpenCTIClient("http://opencti:8080", "tok")
        with pytest.raises(OpenCTIError, match="不支持的 indicator_type"):
            await client.search_observable("mac_address", "aa:bb")


class TestObservableSearch:
    async def test_returns_none_when_not_found(self):
        ctx, _ = _patched_client([{"data": {"stixCyberObservables": {"edges": []}}}])
        with ctx:
            client = OpenCTIClient("http://opencti:8080", "tok")
            assert await client.search_observable("ip", "8.8.8.8") is None

    async def test_returns_node_when_found(self):
        ctx, _ = _patched_client([_observable_payload()])
        with ctx:
            client = OpenCTIClient("http://opencti:8080", "tok")
            node = await client.search_observable("ip", "45.33.32.156")
            assert node["id"] == "obs-1"
            assert node["x_opencti_score"] == 80


class TestAttribution:
    async def test_extracts_intrusion_set_and_technique(self):
        ctx, _ = _patched_client([_attribution_payload()])
        with ctx:
            client = OpenCTIClient("http://opencti:8080", "tok")
            attribution = await client.get_attribution("obs-1")
        assert attribution["intrusion_sets"][0]["name"] == "APT41"
        assert "Winnti" in attribution["intrusion_sets"][0]["aliases"]
        assert attribution["mitre_techniques"] == ["T1496"]

    async def test_extracts_malware(self):
        ctx, _ = _patched_client([_attribution_payload(intrusion_set=None, malware="XMRig")])
        with ctx:
            client = OpenCTIClient("http://opencti:8080", "tok")
            attribution = await client.get_attribution("obs-1")
        assert attribution["malwares"][0]["name"] == "XMRig"

    async def test_empty_relationships_yield_empty_lists(self):
        ctx, _ = _patched_client(
            [{"data": {"stixCoreObject": {"id": "obs-1", "stixCoreRelationships": {"edges": []}}}}]
        )
        with ctx:
            client = OpenCTIClient("http://opencti:8080", "tok")
            attribution = await client.get_attribution("obs-1")
        assert attribution["intrusion_sets"] == []
        assert attribution["mitre_techniques"] == []


class TestProviderQuery:
    async def test_not_found_yields_zero_confidence(self):
        """库里没有 ≠ 安全,只是无情报 — confidence 必须为 0 以免影响合成"""
        ctx, _ = _patched_client([{"data": {"stixCyberObservables": {"edges": []}}}])
        with ctx:
            provider = OpenCTIProvider("http://opencti:8080", "tok")
            result = await provider.query_ip("8.8.8.8")
        assert result.confidence == 0.0
        assert result.malicious is False
        assert "opencti:not_found" in result.tags

    async def test_high_score_marks_malicious(self):
        ctx, _ = _patched_client([_observable_payload(score=90), _attribution_payload(intrusion_set=None, technique=None)])
        with ctx:
            provider = OpenCTIProvider("http://opencti:8080", "tok")
            result = await provider.query_ip("45.33.32.156")
        assert result.malicious is True
        assert result.confidence >= 0.9

    async def test_low_score_without_indicator_not_malicious(self):
        ctx, _ = _patched_client([_observable_payload(score=10), _attribution_payload(intrusion_set=None, technique=None)])
        with ctx:
            provider = OpenCTIProvider("http://opencti:8080", "tok")
            result = await provider.query_ip("1.1.1.1")
        assert result.malicious is False

    async def test_revoked_indicator_does_not_count_as_hit(self):
        """情报被撤回后不能再算命中,否则会按过期情报误封"""
        ctx, _ = _patched_client(
            [
                _observable_payload(
                    score=10,
                    indicators=[{"id": "i1", "revoked": True, "confidence": 90, "killChainPhases": []}],
                ),
                _attribution_payload(intrusion_set=None, technique=None),
            ]
        )
        with ctx:
            provider = OpenCTIProvider("http://opencti:8080", "tok")
            result = await provider.query_ip("1.1.1.1")
        assert result.malicious is False
        assert result.raw["active_indicator_count"] == 0
        assert result.raw["indicator_count"] == 1

    async def test_active_indicator_marks_malicious_despite_low_score(self):
        ctx, _ = _patched_client(
            [
                _observable_payload(
                    score=5,
                    indicators=[{"id": "i1", "revoked": False, "confidence": 80, "killChainPhases": []}],
                ),
                _attribution_payload(intrusion_set=None, technique=None),
            ]
        )
        with ctx:
            provider = OpenCTIProvider("http://opencti:8080", "tok")
            result = await provider.query_ip("1.1.1.1")
        assert result.malicious is True
        assert result.confidence >= 0.6

    async def test_apt_attribution_boosts_confidence_and_tags(self):
        """APT 归因是 OpenCTI 相对云端源的独有价值,必须体现在结果里"""
        ctx, _ = _patched_client([_observable_payload(score=20), _attribution_payload()])
        with ctx:
            provider = OpenCTIProvider("http://opencti:8080", "tok")
            result = await provider.query_ip("45.33.32.156")
        assert result.confidence >= 0.8
        assert "apt:APT41" in result.tags
        assert "T1496" in result.mitre_ttps

    async def test_kill_chain_phase_in_tags(self):
        ctx, _ = _patched_client(
            [
                _observable_payload(
                    score=60,
                    indicators=[
                        {
                            "id": "i1",
                            "revoked": False,
                            "confidence": 80,
                            "killChainPhases": [{"phase_name": "command-and-control"}],
                        }
                    ],
                ),
                _attribution_payload(intrusion_set=None, technique=None),
            ]
        )
        with ctx:
            provider = OpenCTIProvider("http://opencti:8080", "tok")
            result = await provider.query_ip("1.2.3.4")
        assert "kill_chain:command-and-control" in result.tags

    async def test_custom_malicious_score_threshold(self):
        ctx, _ = _patched_client([_observable_payload(score=30), _attribution_payload(intrusion_set=None, technique=None)])
        with ctx:
            provider = OpenCTIProvider("http://opencti:8080", "tok", malicious_score=25)
            result = await provider.query_ip("1.2.3.4")
        assert result.malicious is True

    async def test_supports_all_indicator_types(self):
        provider = OpenCTIProvider("http://opencti:8080", "tok")
        assert set(provider.supports) == {"ip", "domain", "file_hash", "url"}

    async def test_domain_query_uses_domain_stix_type(self):
        ctx, calls = _patched_client([{"data": {"stixCyberObservables": {"edges": []}}}])
        with ctx:
            provider = OpenCTIProvider("http://opencti:8080", "tok")
            await provider.query_domain("pool.supportxmr.com")
        assert calls["n"] == 1


class TestServiceWiring:
    def test_not_registered_when_disabled(self, monkeypatch):
        from app.core import config
        from app.threat_intel.service import get_threat_intel_service

        monkeypatch.setattr(config.settings, "mock_mode", False)
        monkeypatch.setattr(config.settings, "enable_threat_intel", True)
        monkeypatch.setattr(config.settings, "enable_opencti", False)

        service = get_threat_intel_service()
        assert "opencti" not in [p.name for p in service.providers]

    def test_registered_as_third_provider(self, monkeypatch):
        from app.core import config
        from app.threat_intel.service import get_threat_intel_service

        monkeypatch.setattr(config.settings, "mock_mode", False)
        monkeypatch.setattr(config.settings, "enable_threat_intel", True)
        monkeypatch.setattr(config.settings, "enable_opencti", True)
        monkeypatch.setattr(config.settings, "opencti_token", "tok")
        monkeypatch.setattr(config.settings, "abuseipdb_api_key", "key")

        names = [p.name for p in get_threat_intel_service().providers]
        assert names == ["abuseipdb", "otx", "opencti"]

    def test_missing_token_does_not_break_service(self, monkeypatch):
        """token 没配就跳过 OpenCTI,不能让整个情报层起不来"""
        from app.core import config
        from app.threat_intel.service import get_threat_intel_service

        monkeypatch.setattr(config.settings, "mock_mode", False)
        monkeypatch.setattr(config.settings, "enable_threat_intel", True)
        monkeypatch.setattr(config.settings, "enable_opencti", True)
        monkeypatch.setattr(config.settings, "opencti_token", "")

        names = [p.name for p in get_threat_intel_service().providers]
        assert "opencti" not in names
        assert "otx" in names

    def test_mock_mode_ignores_opencti(self, monkeypatch):
        from app.core import config
        from app.threat_intel.service import get_threat_intel_service

        monkeypatch.setattr(config.settings, "mock_mode", True)
        monkeypatch.setattr(config.settings, "enable_opencti", True)
        names = [p.name for p in get_threat_intel_service().providers]
        assert names == ["mock"]


class TestServiceDegradation:
    async def test_opencti_failure_does_not_block_other_sources(self, monkeypatch):
        from app.models.schemas import IntelResult
        from app.threat_intel.mock import MockThreatIntelProvider
        from app.threat_intel.service import ThreatIntelService

        class _Broken(OpenCTIProvider):
            def __init__(self):
                self.malicious_score = 50

            async def query_ip(self, ip: str) -> IntelResult:
                raise OpenCTIError("down")

        class _Working(MockThreatIntelProvider):
            name = "working"

            async def query_ip(self, ip: str) -> IntelResult:
                return IntelResult(
                    indicator=ip, indicator_type="ip", provider="working",
                    confidence=0.6, malicious=True,
                )

        service = ThreatIntelService(providers=[_Broken(), _Working()])
        result = await service.query("ip", "1.2.3.4")
        assert result.malicious is True


class TestHealthCheck:
    async def test_disabled_reports_disabled(self, monkeypatch):
        from app.core import config

        monkeypatch.setattr(config.settings, "enable_opencti", False)
        assert (await health_check())["status"] == "disabled"

    async def test_missing_token_reports_misconfigured(self, monkeypatch):
        from app.core import config

        monkeypatch.setattr(config.settings, "enable_opencti", True)
        monkeypatch.setattr(config.settings, "opencti_token", "")
        assert (await health_check())["status"] == "misconfigured"

    async def test_unreachable_reports_down(self, monkeypatch):
        from app.core import config

        monkeypatch.setattr(config.settings, "enable_opencti", True)
        monkeypatch.setattr(config.settings, "opencti_token", "tok")
        monkeypatch.setattr(config.settings, "opencti_base_url", "http://127.0.0.1:1")
        result = await health_check()
        assert result["status"] == "down"

    async def test_ok_when_reachable(self, monkeypatch):
        from app.core import config

        monkeypatch.setattr(config.settings, "enable_opencti", True)
        monkeypatch.setattr(config.settings, "opencti_token", "tok")
        ctx, _ = _patched_client([{"data": {"about": {"version": "6.2.0"}}}])
        with ctx:
            assert (await health_check())["status"] == "ok"

    async def test_health_endpoint_omits_opencti_when_disabled(self, client):
        resp = await client.get("/health")
        assert "opencti" not in resp.json()["components"]


class TestLicenseIsolation:
    def test_no_opencti_sdk_import(self):
        """OpenCTI AGPL-3.0: 只能走 HTTP,不能 import pycti"""
        import pathlib

        source = pathlib.Path("app/integrations/opencti.py").read_text(encoding="utf-8")
        assert "import pycti" not in source
        assert "from pycti" not in source
        assert "httpx" in source


_LIVE = os.environ.get("SECSIGHT_OPENCTI_LIVE") == "1"


@pytest.mark.skipif(not _LIVE, reason="需 OpenCTI 容器,设 SECSIGHT_OPENCTI_LIVE=1 启用")
class TestLiveOpenCTI:
    async def test_live_health(self):
        from app.core.config import settings

        client = OpenCTIClient(settings.opencti_base_url, settings.opencti_token)
        data = await client._graphql("query { about { version } }", {})
        assert data["about"]["version"]

    async def test_live_query_known_bad_ip(self):
        from app.core.config import settings

        provider = OpenCTIProvider(settings.opencti_base_url, settings.opencti_token)
        result = await provider.query_ip("45.33.32.156")
        assert result.provider == "opencti"
