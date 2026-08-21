"""Wazuh 告警接入 — API 查询 + alerts.json 读取 → 归一化 Alert

两种接入模式:
  1. API 模式: 查 Wazuh Manager API /security/events (需 WAZUH_API_USER/PASSWORD)
  2. 文件模式: 读 alerts.json (Vector/Filebeat 已采集,适合旁路)

License 隔离: Wazuh GPL-2.0,仅 HTTP/文件读取,不 import 其代码。
"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from uuid import uuid4

import httpx
import structlog

from app.models.schemas import Alert, AssetRef, Severity

log = structlog.get_logger()


class WazuhError(Exception):
    """Wazuh 接入失败"""
    pass


# Wazuh rule level → Severity 映射
def _level_to_severity(level: int) -> Severity:
    if level >= 12:
        return Severity.critical
    if level >= 8:
        return Severity.high
    if level >= 5:
        return Severity.medium
    return Severity.low


def _parse_wazuh_alert(data: dict) -> Alert:
    """Wazuh alert JSON → SecSight Alert (ECS 子集)"""
    rule = data.get("rule", {})
    agent = data.get("agent", {})
    agent_data = data.get("data", {})

    level = int(rule.get("level", 3))
    mitre = rule.get("mitre", {}) or {}
    tactics = mitre.get("tactic", [])
    if isinstance(tactics, str):
        tactics = [tactics]
    techniques = mitre.get("id", [])
    if isinstance(techniques, str):
        techniques = [techniques]

    # 资产
    agent_name = agent.get("name", "")
    agent_ip = agent.get("ip", "")

    return Alert(
        alert_id=str(uuid4()),
        ts=datetime.utcnow(),
        source="wazuh",
        rule_id=str(rule.get("id", "")),
        rule_level=level,
        severity=_level_to_severity(level),
        src_ip=agent_data.get("srcip"),
        dst_ip=agent_data.get("dstip"),
        user=agent_data.get("srcuser") or agent_data.get("user"),
        asset=AssetRef(
            host_id=agent.get("id"),
            hostname=agent_name,
            ips=[agent_ip] if agent_ip else [],
        ),
        raw=data,
        mitre_tactics=tactics,
        mitre_techniques=techniques,
        message=rule.get("description", ""),
    )


class WazuhClient:
    """Wazuh Manager API 客户端 (REST,GPL 隔离)"""

    def __init__(
        self,
        base_url: str,
        username: str,
        password: str,
        timeout: int = 15,
    ) -> None:
        if not base_url:
            raise WazuhError("Wazuh base_url 未配置")
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password
        self.timeout = timeout
        self._token: str | None = None

    async def _login(self) -> str:
        """获取 API token"""
        try:
            async with httpx.AsyncClient(timeout=self.timeout, verify=False) as client:
                resp = await client.post(
                    f"{self.base_url}/security/user/authenticate",
                    auth=(self.username, self.password),
                )
                resp.raise_for_status()
                token = resp.json().get("data", {}).get("token")
                if not token:
                    raise WazuhError("Wazuh 登录未返回 token")
                self._token = token
                return token
        except Exception as e:  # noqa: BLE001
            raise WazuhError(f"Wazuh 登录失败: {e}") from e

    async def query_alerts(self, limit: int = 50) -> list[Alert]:
        """查询最近告警 → Alert 列表"""
        token = self._token or await self._login()
        try:
            async with httpx.AsyncClient(timeout=self.timeout, verify=False) as client:
                resp = await client.get(
                    f"{self.base_url}/security/events",
                    params={"limit": limit},
                    headers={"Authorization": f"Bearer {token}"},
                )
                resp.raise_for_status()
                body = resp.json()
        except Exception as e:  # noqa: BLE001
            raise WazuhError(f"Wazuh 告警查询失败: {e}") from e

        affected = body.get("data", {}).get("affected_items", [])
        alerts = [_parse_wazuh_alert(item) for item in affected]
        log.info("wazuh.query_alerts", count=len(alerts))
        return alerts


def read_alerts_json(file_path: str, max_alerts: int = 100) -> list[Alert]:
    """读 Wazuh alerts.json → Alert 列表 (文件模式,适合 Vector 已采集)"""
    path = Path(file_path)
    if not path.exists():
        raise WazuhError(f"alerts.json 不存在: {file_path}")

    alerts: list[Alert] = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                alerts.append(_parse_wazuh_alert(data))
                if len(alerts) >= max_alerts:
                    break
            except json.JSONDecodeError:
                continue
    log.info("wazuh.read_alerts_json", path=file_path, count=len(alerts))
    return alerts
