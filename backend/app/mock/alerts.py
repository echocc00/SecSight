"""Mock 预设告警 (开发用,替代真实 Wazuh/Suricata 告警源)"""
from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from app.models.schemas import Alert, AssetRef, Severity


def xmrig_process_alert(
    hostname: str = "web-prod-01",
    src_ip: str = "10.0.1.15",
    dst_ip: str | None = None,
    pid: int = 28371,
) -> Alert:
    """Wazuh 可疑进程告警: xmrig + stratum cmdline"""
    return Alert(
        alert_id=str(uuid4()),
        ts=datetime.utcnow(),
        source="wazuh",
        rule_id="5710",
        rule_level=12,
        severity=Severity.high,
        src_ip=src_ip,
        dst_ip=dst_ip,
        user="www-data",
        asset=AssetRef(
            host_id=hostname,
            hostname=hostname,
            ips=[src_ip],
            criticality=Severity.high,
        ),
        raw={
            "sigma_id": "suspicious_cryptominer_process",
            "process_name": "xmrig",
            "pid": pid,
            "cmdline": "xmrig -o stratum+tcp://pool.supportxmr.com:3333 -u 48Bit... --cpu-max-threads-hint=75",
            "ppid": 28365,
            "parent_process": "/tmp/.xmrig/xmrig",
        },
        mitre_tactics=["TA0040 Impact"],
        mitre_techniques=["T1496 Resource Hijacking", "T1071.001 Web Protocols"],
        message="Suspicious cryptominer process xmrig detected with stratum cmdline",
    )


def mining_pool_connection_alert(
    hostname: str = "web-prod-01",
    src_ip: str = "10.0.1.15",
    dst_ip: str = "192.168.64.1",
) -> Alert:
    """Suricata 矿池连接告警"""
    return Alert(
        alert_id=str(uuid4()),
        ts=datetime.utcnow(),
        source="suricata",
        rule_id="ET MALWARE Cryptomining",
        rule_level=2,
        severity=Severity.high,
        src_ip=src_ip,
        dst_ip=dst_ip,
        asset=AssetRef(
            hostname=hostname,
            ips=[src_ip],
            criticality=Severity.high,
        ),
        raw={
            "sigma_id": "cryptomining_stratum_protocol",
            "dst_port": 3333,
            "protocol": "stratum+tcp",
            "dst_domain": "pool.supportxmr.com",
            "signature": "ET POLICY Cryptocurrency Mining Pool Connection",
        },
        mitre_tactics=["TA0040 Impact", "TA0011 Command and Control"],
        mitre_techniques=["T1496 Resource Hijacking", "T1071.001 Web Protocols"],
        message="Outbound connection to known mining pool pool.supportxmr.com:3333",
    )


def high_cpu_anomaly_alert(
    hostname: str = "web-prod-01",
    src_ip: str = "10.0.1.15",
    dst_ip: str | None = None,
    pid: int = 28371,
) -> Alert:
    """CPU 持续高占用异常"""
    return Alert(
        alert_id=str(uuid4()),
        ts=datetime.utcnow(),
        source="wazuh",
        rule_id="cpu_anomaly",
        rule_level=7,
        severity=Severity.medium,
        src_ip=src_ip,
        asset=AssetRef(hostname=hostname, ips=[src_ip]),
        raw={
            "cpu_usage": 97,
            "duration_minutes": 12,
            "top_process": "xmrig",
        },
        mitre_tactics=["TA0040 Impact"],
        mitre_techniques=["T1496 Resource Hijacking"],
        message="CPU usage 97% for 12 minutes, top process xmrig",
    )


# 预设告警类型注册表
MOCK_ALERTS = {
    "xmrig_process": xmrig_process_alert,
    "mining_pool_connection": mining_pool_connection_alert,
    "high_cpu_anomaly": high_cpu_anomaly_alert,
}
