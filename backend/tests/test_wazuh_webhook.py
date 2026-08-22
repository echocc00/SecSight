"""Wazuh webhook 接收器测试 — 真实 Wazuh alert JSON → Alert → workflow"""
from __future__ import annotations

import pytest


# 真实 Wazuh alert JSON 样本 (来自 Wazuh alerts.json)
WAZUH_ALERT = {
    "timestamp": "2026-08-21T10:15:30.000+0000",
    "rule": {
        "level": 12,
        "id": "5710",
        "description": "Suspicious process xmrig detected",
        "groups": ["syscheck", "malware"],
        "mitre": {
            "id": ["T1496"],
            "tactic": ["Impact"],
        },
    },
    "data": {"srcip": "10.0.1.15", "dstip": "192.168.64.1", "srcuser": "www-data"},
    "agent": {"name": "web-prod-01", "id": "003", "ip": "10.0.1.15"},
    "full_log": "Process xmrig with stratum cmdline detected",
}


class TestWazuhAlertParser:
    def test_parse_extracts_core_fields(self):
        from app.integrations.wazuh import parse_wazuh_alert

        alert = parse_wazuh_alert(WAZUH_ALERT)
        assert alert.source == "wazuh"
        assert alert.rule_id == "5710"
        assert alert.rule_level == 12
        assert alert.severity.value == "critical"  # level 12 → critical
        assert alert.src_ip == "10.0.1.15"
        assert alert.dst_ip == "192.168.64.1"
        assert alert.user == "www-data"

    def test_parse_extracts_asset(self):
        from app.integrations.wazuh import parse_wazuh_alert

        alert = parse_wazuh_alert(WAZUH_ALERT)
        assert alert.asset.hostname == "web-prod-01"
        assert alert.asset.host_id == "003"
        assert "10.0.1.15" in alert.asset.ips

    def test_parse_extracts_mitre(self):
        from app.integrations.wazuh import parse_wazuh_alert

        alert = parse_wazuh_alert(WAZUH_ALERT)
        assert "T1496" in alert.mitre_techniques
        assert "Impact" in alert.mitre_tactics

    def test_parse_handles_missing_mitre(self):
        from app.integrations.wazuh import parse_wazuh_alert

        data = {"rule": {"id": "100", "level": 3, "description": "test"}, "data": {}, "agent": {}}
        alert = parse_wazuh_alert(data)
        assert alert.mitre_tactics == []
        assert alert.mitre_techniques == []

    def test_parse_handles_string_mitre(self):
        from app.integrations.wazuh import parse_wazuh_alert

        data = {
            "rule": {"id": "100", "level": 5, "description": "x", "mitre": {"id": "T1059", "tactic": "Execution"}},
        }
        alert = parse_wazuh_alert(data)
        assert alert.mitre_techniques == ["T1059"]
        assert alert.mitre_tactics == ["Execution"]

    def test_level_to_severity_mapping(self):
        from app.integrations.wazuh import _level_to_severity
        from app.models.schemas import Severity

        assert _level_to_severity(3) == Severity.low
        assert _level_to_severity(7) == Severity.medium
        assert _level_to_severity(10) == Severity.high
        assert _level_to_severity(14) == Severity.critical


class TestWazuhWebhookEndpoint:
    @pytest.mark.asyncio
    async def test_webhook_creates_case_and_matches_playbook(self, client):
        r = await client.post("/api/alerts/wazuh-webhook", json=WAZUH_ALERT)
        assert r.status_code == 200
        data = r.json()["data"]
        assert data["source"] == "wazuh_webhook"
        assert data["case_id"]
        # xmrig 告警应匹配 cryptominer 剧本
        assert data["playbook_id"] == "pb_cryptominer_v1"

    @pytest.mark.asyncio
    async def test_webhook_case_has_alert_with_wazuh_source(self, client):
        r = await client.post("/api/alerts/wazuh-webhook", json=WAZUH_ALERT)
        case_id = r.json()["data"]["case_id"]

        r = await client.get(f"/api/cases/{case_id}")
        case = r.json()["data"]
        assert case["alerts"][0]["source"] == "wazuh"
        assert case["alerts"][0]["rule_id"] == "5710"

    @pytest.mark.asyncio
    async def test_webhook_triggers_workflow_to_pending(self, client):
        r = await client.post("/api/alerts/wazuh-webhook", json=WAZUH_ALERT)
        case_id = r.json()["data"]["case_id"]

        r = await client.get(f"/api/cases/{case_id}")
        case = r.json()["data"]
        # xmrig (L2) → 应到 pending_approval
        assert case["status"] == "pending_approval"
        assert case["judgment"] is not None

    @pytest.mark.asyncio
    async def test_webhook_handles_minimal_alert(self, client):
        """缺字段的告警仍能处理"""
        minimal = {"rule": {"id": "999", "level": 3, "description": "unknown event"}}
        r = await client.post("/api/alerts/wazuh-webhook", json=minimal)
        assert r.status_code == 200
        assert r.json()["success"] is True
        # 无匹配剧本 → playbook_id 为 None
        assert r.json()["data"]["playbook_id"] is None

    @pytest.mark.asyncio
    async def test_webhook_bruteforce_alert(self, client):
        """SSH 暴破告警应匹配 bruteforce 剧本"""
        bruteforce = {
            "rule": {
                "level": 10,
                "id": "5712",
                "description": "SSH brute force attempt",
                "mitre": {"id": ["T1110"], "tactic": ["Credential Access"]},
            },
            "data": {"srcip": "45.10.0.1"},
            "agent": {"name": "web-prod-01", "id": "003"},
        }
        r = await client.post("/api/alerts/wazuh-webhook", json=bruteforce)
        data = r.json()["data"]
        assert data["playbook_id"] == "pb_bruteforce_v1"
