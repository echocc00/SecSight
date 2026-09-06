"""国产设备 syslog 适配器 — 奇安信/天融信/深信服/绿盟

国产安全设备 syslog 格式各异,归一化为 SecSight Alert (ECS 子集)。
通过 Vector syslog input 接收,或直接 POST /api/alerts/device-webhook。
"""
from __future__ import annotations

import re
from datetime import datetime
from uuid import uuid4

from app.models.schemas import Alert, AssetRef, Severity

import structlog

log = structlog.get_logger()


class DeviceParseError(Exception):
    """设备日志解析失败"""
    pass


# ============ 严重性映射 ============

# 国产设备常见严重性字符串 → SecSight Severity
_SEVERITY_MAP: dict[str, Severity] = {
    "紧急": Severity.critical,
    "严重": Severity.critical,
    "critical": Severity.critical,
    "高": Severity.high,
    "高危": Severity.high,
    "high": Severity.high,
    "warning": Severity.medium,
    "中": Severity.medium,
    "中危": Severity.medium,
    "medium": Severity.medium,
    "低": Severity.low,
    "低危": Severity.low,
    "low": Severity.low,
    "info": Severity.low,
    "信息": Severity.low,
}


def _map_severity(raw: str | int | None) -> Severity:
    if raw is None:
        return Severity.medium
    if isinstance(raw, int):
        if raw >= 8:
            return Severity.critical
        if raw >= 5:
            return Severity.high
        if raw >= 3:
            return Severity.medium
        return Severity.low
    return _SEVERITY_MAP.get(str(raw).strip().lower(), Severity.medium)


def _srcip(data: dict) -> str | None:
    """兼容带/不带下划线字段 —— 奇安信/深信服部分版本 syslog 用 srcip/dstip"""
    return data.get("src_ip") or data.get("srcip")


def _dstip(data: dict) -> str | None:
    return data.get("dst_ip") or data.get("dstip")


def _hostname(data: dict, *keys: str, default: str) -> str:
    for key in keys:
        if data.get(key):
            return str(data[key])
    return default


# ============ 奇安信态势感知 ============


def parse_qianxin(data: dict) -> Alert:
    """奇安信态势感知告警

    典型字段: alert_name, severity, src_ip, dst_ip, device, event_type, mitre_technique
    兼容变体: srcip/dstip (部分版本无下划线), sensor (天眼设备名)
    """
    severity = _map_severity(data.get("severity") or data.get("level") or data.get("serverity"))
    techniques = []
    if t := data.get("mitre_technique"):
        techniques = [t] if isinstance(t, str) else t
    tactics = []
    if tac := data.get("mitre_tactic"):
        tactics = [tac] if isinstance(tac, str) else tac

    return Alert(
        alert_id=str(uuid4()),
        ts=datetime.utcnow(),
        source="qianxin",
        rule_id=str(data.get("rule_id") or data.get("alert_id") or ""),
        rule_level=_severity_to_level(severity),
        severity=severity,
        src_ip=_srcip(data),
        dst_ip=_dstip(data),
        user=data.get("user"),
        asset=AssetRef(
            hostname=_hostname(data, "sensor", "device", "asset", default="qianxin-sensor"),
            ips=[data.get("device_ip")] if data.get("device_ip") else [],
        ),
        raw=data,
        mitre_tactics=tactics,
        mitre_techniques=techniques,
        message=data.get("alert_name") or data.get("event_type") or "qianxin alert",
    )


# ============ 天融信 ============


def parse_topsec(data: dict) -> Alert:
    """天融信防火墙/IDS 告警"""
    severity = _map_severity(data.get("severity") or data.get("priority"))
    return Alert(
        alert_id=str(uuid4()),
        ts=datetime.utcnow(),
        source="topsec",
        rule_id=str(data.get("rule_id") or data.get("sig_id") or ""),
        rule_level=_severity_to_level(severity),
        severity=severity,
        src_ip=data.get("src_ip"),
        dst_ip=data.get("dst_ip"),
        asset=AssetRef(hostname=data.get("device") or "topsec-fw"),
        raw=data,
        message=data.get("alert_name") or data.get("name") or "topsec alert",
    )


# ============ 深信服 ============


def parse_sangfor(data: dict) -> Alert:
    """深信服 AC/AF/SIP 告警"""
    severity = _map_severity(data.get("level") or data.get("severity"))
    return Alert(
        alert_id=str(uuid4()),
        ts=datetime.utcnow(),
        source="sangfor",
        rule_id=str(data.get("rule_id") or ""),
        rule_level=_severity_to_level(severity),
        severity=severity,
        src_ip=_srcip(data),
        dst_ip=_dstip(data),
        user=data.get("user"),
        asset=AssetRef(
            hostname=data.get("device") or "sangfor-ac",
            ips=[data.get("device_ip")] if data.get("device_ip") else [],
        ),
        raw=data,
        message=data.get("app_name") or data.get("alert_name") or "sangfor alert",
    )


# ============ 绿盟 ============


def parse_nsfocus(data: dict) -> Alert:
    """绿盟 IDS/RSAS 告警

    IDS: alert_name/name + src_ip/dst_ip
    RSAS 漏洞扫描: vuln_name + host_ip (无 src/dst,目标主机在 host_ip)
    """
    severity = _map_severity(data.get("severity") or data.get("risk"))
    asset_ip = data.get("host_ip") or data.get("dst_ip")
    return Alert(
        alert_id=str(uuid4()),
        ts=datetime.utcnow(),
        source="nsfocus",
        rule_id=str(data.get("rule_id") or data.get("sig_id") or data.get("vuln_id") or ""),
        rule_level=_severity_to_level(severity),
        severity=severity,
        src_ip=data.get("src_ip"),
        dst_ip=data.get("dst_ip"),
        asset=AssetRef(
            hostname=_hostname(data, "sensor", "device", default="nsfocus-ids"),
            ips=[asset_ip] if asset_ip else [],
        ),
        raw=data,
        message=(
            data.get("alert_name")
            or data.get("name")
            or data.get("vuln_name")
            or f"{severity.value} {data.get('cve') or 'nsfocus alert'}"
        ),
    )


def _severity_to_level(sev: Severity) -> int:
    return {Severity.critical: 12, Severity.high: 10, Severity.medium: 6, Severity.low: 3}.get(sev, 5)


# ============ 注册表 + 解析器 ============

DEVICE_PARSERS: dict[str, callable] = {  # type: ignore[type-arg]
    "qianxin": parse_qianxin,
    "topsec": parse_topsec,
    "sangfor": parse_sangfor,
    "nsfocus": parse_nsfocus,
}


def parse_device_alert(device_type: str, data: dict) -> Alert:
    """根据设备类型解析告警

    device_type: qianxin | topsec | sangfor | nsfocus
    """
    parser = DEVICE_PARSERS.get(device_type)
    if not parser:
        raise DeviceParseError(f"未知设备类型: {device_type},支持: {list(DEVICE_PARSERS.keys())}")
    try:
        return parser(data)
    except Exception as e:  # noqa: BLE001
        raise DeviceParseError(f"{device_type} 告警解析失败: {e}") from e


def list_supported_devices() -> list[str]:
    return list(DEVICE_PARSERS.keys())
