"""OpenSearch 集成测试 — 告警索引 + 全文检索"""
from __future__ import annotations

import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.integrations.opensearch import OpenSearchClient, OpenSearchError
from app.mock.alerts import xmrig_process_alert


def _alert() -> Alert:
    return xmrig_process_alert()


def _mock_httpx_response(json_data: dict, raise_error: Exception | None = None) -> MagicMock:
    """构造同步的 httpx Response mock (raise_for_status 是同步方法)"""
    resp = MagicMock()
    resp.json.return_value = json_data
    if raise_error:
        resp.raise_for_status.side_effect = raise_error
    else:
        resp.raise_for_status.return_value = None
    return resp


class TestOpenSearchDocBuild:
    def test_build_doc_contains_ecs_fields(self):
        client = OpenSearchClient(base_url="http://x", user="u", password="p")
        doc = client._build_doc(_alert())
        assert doc["event"]["id"]
        assert doc["source"]["ip"] == "10.0.1.15"
        assert doc["host"]["name"] == "web-prod-01"
        assert doc["rule"]["id"] == "5710"
        assert "T1496" in str(doc["threat"]["technique"]["id"])

    def test_index_name_uses_date_pattern(self):
        client = OpenSearchClient()
        from datetime import datetime

        name = client._index_name(datetime(2026, 8, 22))
        assert name == "secsiem-alerts-2026.08.22"


class TestOpenSearchIndexAlert:
    @pytest.mark.asyncio
    async def test_index_alert_returns_id(self):
        client = OpenSearchClient(base_url="http://x", user="u", password="p")
        mock_resp = _mock_httpx_response({"_id": "doc-123"})
        with patch.object(client, "_get_client", return_value=mock_resp):
            # _get_client 返回的 client 需要有 post 方法
            mock_resp.post = AsyncMock(return_value=_mock_httpx_response({"_id": "doc-123"}))
            result = await client.index_alert(_alert())
        assert result == "doc-123"

    @pytest.mark.asyncio
    async def test_index_alert_wraps_error(self):
        client = OpenSearchClient(base_url="http://x", user="u", password="p")
        error_resp = _mock_httpx_response({}, raise_error=Exception("503"))
        mock_client = MagicMock()
        mock_client.post = AsyncMock(return_value=error_resp)
        with patch.object(client, "_get_client", return_value=mock_client):
            with pytest.raises(OpenSearchError, match="索引失败"):
                await client.index_alert(_alert())


class TestOpenSearchSearch:
    @pytest.mark.asyncio
    async def test_search_returns_formatted_hits(self):
        client = OpenSearchClient(base_url="http://x", user="u", password="p")
        hits_data = {
            "hits": {
                "hits": [
                    {
                        "_id": "h1", "_score": 1.5,
                        "_source": {
                            "@timestamp": "2026-08-21T10:00:00",
                            "event": {"id": "a1", "action": "xmrig", "severity": "high", "original": {"x": 1}},
                            "source": {"ip": "10.0.1.15"},
                            "destination": {"ip": "1.2.3.4"},
                            "host": {"name": "web-prod-01"},
                            "rule": {"id": "5710", "level": 12},
                            "threat": {"tactic": {"name": ["Impact"]}, "technique": {"id": ["T1496"]}},
                        },
                    }
                ]
            }
        }
        mock_client = MagicMock()
        mock_client.post = AsyncMock(return_value=_mock_httpx_response(hits_data))
        with patch.object(client, "_get_client", return_value=mock_client):
            results = await client.search_alerts("xmrig", size=5)
        assert len(results) == 1
        assert results[0]["alert_id"] == "a1"
        assert results[0]["severity"] == "high"
        assert "T1496" in results[0]["mitre_techniques"]
        assert results[0]["score"] == 1.5

    @pytest.mark.asyncio
    async def test_search_wraps_error(self):
        client = OpenSearchClient(base_url="http://x", user="u", password="p")
        error_resp = _mock_httpx_response({}, raise_error=Exception("timeout"))
        mock_client = MagicMock()
        mock_client.post = AsyncMock(return_value=error_resp)
        with patch.object(client, "_get_client", return_value=mock_client):
            with pytest.raises(OpenSearchError, match="搜索失败"):
                await client.search_alerts("x")


class TestOpenSearchHealth:
    @pytest.mark.asyncio
    async def test_health_returns_status(self):
        client = OpenSearchClient(base_url="http://x", user="u", password="p")
        mock_client = MagicMock()
        mock_client.get = AsyncMock(return_value=_mock_httpx_response({"status": "green"}))
        with patch.object(client, "_get_client", return_value=mock_client):
            result = await client.health()
        assert result["status"] == "green"

    @pytest.mark.asyncio
    async def test_health_returns_unreachable_on_error(self):
        client = OpenSearchClient(base_url="http://x", user="u", password="p")
        mock_client = MagicMock()
        mock_client.get = AsyncMock(side_effect=Exception("conn refused"))
        with patch.object(client, "_get_client", return_value=mock_client):
            result = await client.health()
        assert result["status"] == "unreachable"


# ============ 真实 OpenSearch 冒烟 (需 docker 容器) ============
_HAS_OS = bool(os.environ.get("SECSIGHT_OS_LIVE"))


@pytest.mark.skipif(not _HAS_OS, reason="未设 SECSIGHT_OS_LIVE=1,跳过真实 OpenSearch 冒烟")
class TestLiveOpenSearch:
    @pytest.mark.asyncio
    async def test_live_index_and_search(self):
        """真实 OpenSearch: 索引告警 → 搜索 → 命中"""
        import asyncio

        await asyncio.sleep(20)  # 等容器初始化
        client = OpenSearchClient(
            base_url="http://localhost:9200",
            user="admin",
            password="SecSightAdmin123",
        )
        alert = _alert()
        doc_id = await client.index_alert(alert)
        assert doc_id
        await asyncio.sleep(2)
        results = await client.search_alerts("xmrig", size=5, time_range_hours=1)
        assert len(results) >= 1
        await client.close()
