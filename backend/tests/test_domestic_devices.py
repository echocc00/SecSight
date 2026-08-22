"""国产设备 syslog 适配器测试"""
from __future__ import annotations

import pytest

from app.integrations.domestic_devices import (
    DEVICE_PARSERS,
    DeviceParseError,
    list_supported_devices,
    parse_device_alert,
    parse_nsfocus,
    parse_qianxin,
    parse_sangfor,
    parse_topsec,
)
from app.models.schemas import Severity


class TestSeverityMapping:
    def test_chinese_severity(self):
        from app.integrations.domestic_devices import _map_severity

        assert _map_severity("紧急") == Severity.critical
        assert _map_severity("高") == Severity.high
        assert _map_severity("中") == Severity.medium
        assert _map_severity("低") == Severity.low

    def test_english_severity(self):
        from app.integrations.domestic_devices import _map_severity

        assert _map_severity("critical") == Severity.critical
        assert _map_severity("high") == Severity.high

    def test_numeric_severity(self):
        from app.integrations.domestic_devices import _map_severity

        assert _map_severity(10) == Severity.critical
        assert _map_severity(5) == Severity.high
        assert _map_severity(3) == Severity.medium

    def test_unknown_defaults_medium(self):
        from app.integrations.domestic_devices import _map_severity

        assert _map_severity("unknown") == Severity.medium
        assert _map_severity(None) == Severity.medium


class TestQianxinParser:
    def test_parse_full_alert(self):
        alert = parse_qianxin({
            "alert_name": "SQL注入攻击",
            "severity": "高",
            "src_ip": "45.10.0.1",
            "dst_ip": "10.0.1.15",
            "device": "qianxin-sensor-01",
            "mitre_technique": "T1190",
            "mitre_tactic": "Initial Access",
        })
        assert alert.source == "qianxin"
        assert alert.severity == Severity.high
        assert alert.src_ip == "45.10.0.1"
        assert "T1190" in alert.mitre_techniques
        assert alert.message == "SQL注入攻击"

    def test_parse_minimal(self):
        alert = parse_qianxin({"alert_name": "test"})
        assert alert.severity == Severity.medium  # 默认


class TestTopsecParser:
    def test_parse(self):
        alert = parse_topsec({
            "alert_name": "端口扫描",
            "severity": "中危",
            "src_ip": "1.2.3.4",
        })
        assert alert.source == "topsec"
        assert alert.severity == Severity.medium
        assert alert.src_ip == "1.2.3.4"


class TestSangforParser:
    def test_parse(self):
        alert = parse_sangfor({
            "app_name": "恶意文件下载",
            "level": "高",
            "src_ip": "1.2.3.4",
            "dst_ip": "5.6.7.8",
        })
        assert alert.source == "sangfor"
        assert alert.severity == Severity.high
        assert alert.message == "恶意文件下载"


class TestNsfocusParser:
    def test_parse(self):
        alert = parse_nsfocus({
            "alert_name": "暴力破解",
            "severity": "高",
            "src_ip": "1.2.3.4",
            "sensor": "nsfocus-ids-01",
        })
        assert alert.source == "nsfocus"
        assert alert.severity == Severity.high
        assert alert.asset.hostname == "nsfocus-ids-01"


class TestRegistry:
    def test_four_devices_supported(self):
        assert len(DEVICE_PARSERS) == 4
        assert set(DEVICE_PARSERS.keys()) == {"qianxin", "topsec", "sangfor", "nsfocus"}

    def test_list_supported(self):
        devices = list_supported_devices()
        assert len(devices) == 4

    def test_parse_unknown_device_raises(self):
        with pytest.raises(DeviceParseError, match="未知设备类型"):
            parse_device_alert("cisco", {})


class TestDeviceWebhookEndpoint:
    @pytest.mark.asyncio
    async def test_qianxin_webhook_creates_case(self, client):
        r = await client.post(
            "/api/alerts/devices/qianxin/webhook",
            json={
                "alert_name": "SQL注入",
                "severity": "高",
                "src_ip": "45.10.0.1",
                "dst_ip": "10.0.1.15",
                "mitre_technique": "T1190",
            },
        )
        assert r.status_code == 200
        data = r.json()["data"]
        assert data["source"] == "qianxin"
        assert data["case_id"]
        # SQL注入应匹配 web_attack 剧本
        assert data["playbook_id"] == "pb_web_attack_v1"

    @pytest.mark.asyncio
    async def test_unknown_device_returns_error(self, client):
        r = await client.post(
            "/api/alerts/devices/cisco/webhook",
            json={"x": 1},
        )
        assert r.json()["success"] is False

    @pytest.mark.asyncio
    async def test_list_supported_devices(self, client):
        r = await client.get("/api/alerts/devices/supported")
        assert r.status_code == 200
        devices = r.json()["data"]["devices"]
        assert "qianxin" in devices
