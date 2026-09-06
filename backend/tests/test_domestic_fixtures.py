"""国产设备适配器 — 真实告警样本 fixture 覆盖

每厂商 2 个真实格式样本 (奇安信天眼/太阳、天融信 FW/IDS、深信服 AF/SIP、
绿盟 IDS/RSAS),校验关键字段归一化。字段名来自公开设备日志样例。

注意奇安信部分版本 syslog 用无下划线 srcip/dstip —— 适配器必须兼容。
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.integrations.domestic_devices import parse_device_alert
from app.models.schemas import Severity

_FIXTURES = Path(__file__).resolve().parent / "fixtures" / "domestic"


def _load(device: str, name: str) -> dict:
    path = _FIXTURES / device / f"{name}.json"
    return json.loads(path.read_text(encoding="utf-8"))


# (device, fixture, expected) — 断言解析后关键字段
_CASES = [
    (
        "qianxin",
        "web_sql_injection",
        {
            "source": "qianxin",
            "severity": Severity.high,
            "src_ip": "45.33.32.156",
            "dst_ip": "10.0.1.15",
            "rule_id": "QINX-2001",
            "message": "SQL 注入攻击",
            "mitre_techniques": ["T1190"],
            "asset_hostname": "qianxin-tianqing-01",
        },
    ),
    (
        "qianxin",
        "webshell_detected",
        {
            "source": "qianxin",
            "severity": Severity.high,
            "src_ip": "198.51.100.7",
            "dst_ip": "10.0.2.20",
            "asset_hostname": "qianxin-taiyang",
            "mitre_techniques": ["T1505.003"],
        },
    ),
    (
        "topsec",
        "fw_overflow",
        {
            "source": "topsec",
            "severity": Severity.medium,
            "src_ip": "10.1.0.5",
            "dst_ip": "10.2.0.8",
            "rule_id": "TS-3321",
            "message": "异常下行流量",
        },
    ),
    (
        "topsec",
        "ids_exploit",
        {
            "source": "topsec",
            "severity": Severity.critical,
            "src_ip": "45.10.0.133",
            "dst_ip": "10.0.3.44",
            "rule_id": "TS-ID-7788",
        },
    ),
    (
        "sangfor",
        "af_attack",
        {
            "source": "sangfor",
            "severity": Severity.high,
            "src_ip": "203.0.113.5",
            "dst_ip": "10.0.4.9",
            "asset_hostname": "sangfor-AF-01",
        },
    ),
    (
        "sangfor",
        "sip_event",
        {
            "source": "sangfor",
            "severity": Severity.critical,
            "src_ip": "10.0.5.33",
            "dst_ip": "45.33.32.156",
            "message": "主机中毒-挖矿木马",
            "rule_id": "",
        },
    ),
    (
        "nsfocus",
        "ids_rce",
        {
            "source": "nsfocus",
            "severity": Severity.high,
            "src_ip": "185.220.101.4",
            "dst_ip": "10.0.6.30",
            "rule_id": "NS-ID-9001",
            "asset_hostname": "nsfocus-ids-rc",
        },
    ),
    (
        "nsfocus",
        "rsas_vuln",
        {
            "source": "nsfocus",
            "severity": Severity.critical,
            # RSAS 漏洞扫描无 src/dst IP,host_ip 归一化到资产 IP + 资产名
            "src_ip": None,
            "dst_ip": None,
            "asset_hostname": "nsfocus-rsas-01",
            "asset_ips": ["10.0.7.11"],
            "rule_id": "CNVD-2021-95914",
            "message": "Apache Log4j2 远程代码执行",
        },
    ),
]


class TestRealDeviceFixtures:
    @pytest.mark.parametrize("device,fixture,expected", _CASES, ids=lambda v: str(v))
    def test_parse_real_sample(self, device, fixture, expected):
        alert = parse_device_alert(device, _load(device, fixture))

        assert alert.source == expected["source"]
        assert alert.severity == expected["severity"]
        if "src_ip" in expected:
            assert alert.src_ip == expected["src_ip"], f"src_ip: {alert.src_ip}"
        if "dst_ip" in expected:
            assert alert.dst_ip == expected["dst_ip"]
        if "rule_id" in expected:
            assert alert.rule_id == expected["rule_id"], f"rule_id: {alert.rule_id}"
        if "message" in expected:
            assert expected["message"] in alert.message, alert.message
        if "mitre_techniques" in expected:
            assert alert.mitre_techniques == expected["mitre_techniques"]
        if "asset_hostname" in expected:
            assert alert.asset.hostname == expected["asset_hostname"], alert.asset.hostname
        if "asset_ips" in expected:
            assert alert.asset.ips == expected["asset_ips"], alert.asset.ips


class TestVendorNoUnderscoreKeys:
    """奇安信部分版本 syslog 用 srcip/dstip (无下划线) —— 归一化必须兼容"""

    def test_qianxin_srcip_variant(self):
        alert = parse_device_alert(
            "qianxin",
            {
                "alert_name": "RDP 暴破",
                "severity": "高",
                "srcip": "45.10.0.99",
                "dstip": "10.0.1.99",
            },
        )
        assert alert.src_ip == "45.10.0.99"
        assert alert.dst_ip == "10.0.1.99"

    def test_sangfor_proto_port_variant(self):
        """深信服事件还可能带 app 端口字段,不应丢 src/dst"""
        alert = parse_device_alert(
            "sangfor",
            {
                "alert_name": "横向渗透",
                "severity": "高",
                "srcip": "10.0.5.1",
                "dstip": "10.0.5.200",
                "app_proto": "445",
            },
        )
        assert alert.src_ip == "10.0.5.1"
        assert alert.dst_ip == "10.0.5.200"


class TestWebhookEndToEndRealShapes:
    @pytest.mark.asyncio
    async def test_webhook_sanfor_creates_case(self, client):
        """深信服挖矿样本喂 webhook → 命中 cryptominer 剧本"""
        r = await client.post(
            "/api/alerts/devices/sangfor/webhook",
            json={
                "alert_name": "主机中毒-挖矿木马",
                "level": "严重",
                "src_ip": "10.0.5.33",
                "dst_ip": "45.33.32.156",
                "device": "sangfor-SIP",
            },
        )
        assert r.status_code == 200
        data = r.json()["data"]
        assert data["source"] == "sangfor"
        assert data["severity"] == "critical"

    @pytest.mark.asyncio
    async def test_webhook_topsec_ids_creates_case(self, client):
        r = await client.post(
            "/api/alerts/devices/topsec/webhook",
            json={
                "alert_name": "Apache 漏洞攻击尝试",
                "severity": "critical",
                "src_ip": "45.10.0.133",
                "dst_ip": "10.0.3.44",
                "rule_id": "TS-ID-7788",
            },
        )
        assert r.status_code == 200
        assert r.json()["data"]["source"] == "topsec"