"""Wazuh 接入测试 — 告警解析 + API 客户端 + 文件模式"""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import httpx
import pytest

from app.integrations.wazuh import (
    WazuhClient,
    WazuhError,
    _level_to_severity,
    _parse_wazuh_alert,
    read_alerts_json,
)
from app.models.schemas import Severity


def _sample_wazuh_alert(
    level: int = 12,
    rule_id: str = "5710",
    srcip: str = "45.10.0.1",
) -> dict:
    """构造一条 Wazuh alert JSON"""
    return {
        "rule": {
            "id": rule_id,
            "level": level,
            "description": "Suspicious process detected",
            "mitre": {"tactic": ["TA0040 Impact"], "id": ["T1496"]},
        },
        "agent": {"id": "001", "name": "web-prod-01", "ip": "10.0.1.15"},
        "data": {"srcip": srcip, "srcuser": "www-data"},
    }


class TestLevelToSeverity:
    def test_level_12_plus_is_critical(self):
        assert _level_to_severity(12) == Severity.critical

    def test_level_8_to_11_is_high(self):
        assert _level_to_severity(8) == Severity.high

    def test_level_5_to_7_is_medium(self):
        assert _level_to_severity(5) == Severity.medium

    def test_below_5_is_low(self):
        assert _level_to_severity(3) == Severity.low


class TestParseWazuhAlert:
    def test_parses_full_alert(self):
        data = _sample_wazuh_alert()
        alert = _parse_wazuh_alert(data)
        assert alert.source == "wazuh"
        assert alert.rule_id == "5710"
        assert alert.severity == Severity.critical
        assert alert.src_ip == "45.10.0.1"
        assert alert.user == "www-data"
        assert alert.asset.hostname == "web-prod-01"
        assert "T1496" in alert.mitre_techniques

    def test_mitre_string_form_normalized_to_list(self):
        data = _sample_wazuh_alert()
        data["rule"]["mitre"] = {"tactic": "TA0040", "id": "T1496"}
        alert = _parse_wazuh_alert(data)
        assert alert.mitre_tactics == ["TA0040"]
        assert alert.mitre_techniques == ["T1496"]

    def test_missing_fields_use_defaults(self):
        alert = _parse_wazuh_alert({"rule": {}})
        assert alert.severity == Severity.low
        assert alert.rule_id == ""


class TestReadAlertsJson:
    def test_reads_jsonl_file(self, tmp_path: Path):
        f = tmp_path / "alerts.json"
        f.write_text(
            json.dumps(_sample_wazuh_alert()) + "\n"
            + json.dumps(_sample_wazuh_alert(level=8, rule_id="5712")) + "\n"
        )
        alerts = read_alerts_json(str(f))
        assert len(alerts) == 2
        assert alerts[0].severity == Severity.critical
        assert alerts[1].severity == Severity.high

    def test_skips_invalid_json_lines(self, tmp_path: Path):
        f = tmp_path / "alerts.json"
        f.write_text('{"valid": "rule", "rule": {"id":"1","level":5}}\ninvalid line\n{"rule":{}}\n')
        alerts = read_alerts_json(str(f))
        assert len(alerts) == 2  # 跳过 invalid line

    def test_raises_for_missing_file(self):
        with pytest.raises(WazuhError, match="不存在"):
            read_alerts_json("/nonexistent/path/alerts.json")

    def test_respects_max_alerts(self, tmp_path: Path):
        f = tmp_path / "alerts.json"
        f.write_text("\n".join(json.dumps(_sample_wazuh_alert()) for _ in range(10)))
        alerts = read_alerts_json(str(f), max_alerts=3)
        assert len(alerts) == 3


class TestWazuhClient:
    def test_raises_without_base_url(self):
        with pytest.raises(WazuhError, match="base_url"):
            WazuhClient(base_url="", username="u", password="p")

    @pytest.mark.asyncio
    async def test_login_returns_token(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"data": {"token": "test-token"}})

        client = WazuhClient(base_url="http://w:55000", username="u", password="p")
        real = httpx.AsyncClient

        def factory(**kw):
            return real(transport=httpx.MockTransport(handler), **kw)

        with patch("app.integrations.wazuh.httpx.AsyncClient", factory):
            token = await client._login()
        assert token == "test-token"

    @pytest.mark.asyncio
    async def test_query_alerts_returns_parsed(self):
        def handler(request: httpx.Request) -> httpx.Response:
            if "authenticate" in str(request.url):
                return httpx.Response(200, json={"data": {"token": "t"}})
            return httpx.Response(
                200,
                json={"data": {"affected_items": [_sample_wazuh_alert()]}},
            )

        client = WazuhClient(base_url="http://w:55000", username="u", password="p")
        real = httpx.AsyncClient

        def factory(**kw):
            return real(transport=httpx.MockTransport(handler), **kw)

        with patch("app.integrations.wazuh.httpx.AsyncClient", factory):
            alerts = await client.query_alerts(limit=10)
        assert len(alerts) == 1
        assert alerts[0].source == "wazuh"

    @pytest.mark.asyncio
    async def test_login_failure_raises(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(401, text="unauthorized")

        client = WazuhClient(base_url="http://w:55000", username="u", password="bad")
        real = httpx.AsyncClient

        def factory(**kw):
            return real(transport=httpx.MockTransport(handler), **kw)

        with patch("app.integrations.wazuh.httpx.AsyncClient", factory):
            with pytest.raises(WazuhError, match="登录失败"):
                await client.query_alerts()
