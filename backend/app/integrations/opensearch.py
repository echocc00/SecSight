"""OpenSearch 客户端 — 告警全文检索 (替代 PG JSONB 查询)

Case 主体仍在 Postgres (事务一致性),OpenSearch 仅存告警副本用于检索。
写入: 告警注入时同步索引到 OpenSearch
查询: /api/alerts/search 全文检索告警内容

索引: secsiem-alerts-{YYYY.MM.dd} (按日滚动)
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

import httpx

from app.core.config import settings
from app.models.schemas import Alert

import structlog

log = structlog.get_logger()


class OpenSearchError(Exception):
    """OpenSearch 调用失败"""
    pass


class OpenSearchClient:
    """OpenSearch 告警索引客户端 (Apache-2.0,无 license 隔离要求)"""

    def __init__(
        self,
        base_url: str | None = None,
        user: str | None = None,
        password: str | None = None,
        timeout: int = 10,
    ) -> None:
        self.base_url = (base_url or settings.opensearch_url).rstrip("/")
        self.user = user or settings.opensearch_user
        self.password = password or settings.opensearch_password
        self.timeout = timeout
        self._client: httpx.AsyncClient | None = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            auth = (self.user, self.password) if self.user else None
            self._client = httpx.AsyncClient(
                base_url=self.base_url,
                auth=auth,
                timeout=self.timeout,
                verify=False,  # OpenSearch 默认自签证书,生产收紧
            )
        return self._client

    def _index_name(self, ts: datetime | None = None) -> str:
        ts = ts or datetime.utcnow()
        return f"secsiem-alerts-{ts.strftime('%Y.%m.%d')}"

    async def index_alert(self, alert: Alert) -> str:
        """索引告警到 OpenSearch"""
        client = await self._get_client()
        doc = self._build_doc(alert)
        index = self._index_name(alert.ts)
        try:
            resp = await client.post(
                f"/{index}/_doc",
                params={"refresh": "false"},
                json=doc,
            )
            resp.raise_for_status()
            log.info("opensearch.indexed", alert_id=alert.alert_id, index=index)
            return resp.json().get("_id", "")
        except Exception as e:  # noqa: BLE001
            raise OpenSearchError(f"OpenSearch 索引失败: {e}") from e

    def _build_doc(self, alert: Alert) -> dict:
        """Alert → OpenSearch 文档 (ECS 子集)"""
        return {
            "@timestamp": alert.ts.isoformat(),
            "event": {
                "id": alert.alert_id,
                "action": alert.message,
                "severity": alert.severity.value,
                "original": alert.raw,
            },
            "source": {"ip": alert.src_ip, "user": {"name": alert.user}},
            "destination": {"ip": alert.dst_ip},
            "host": {"name": alert.asset.hostname, "id": alert.asset.host_id},
            "rule": {"id": alert.rule_id, "level": alert.rule_level},
            "threat": {
                "tactic": {"name": alert.mitre_tactics},
                "technique": {"id": alert.mitre_techniques},
            },
            "secsight": {
                "source": alert.source,
                "ingested_at": datetime.utcnow().isoformat(),
            },
        }

    async def search_alerts(
        self,
        query: str,
        size: int = 20,
        time_range_hours: int = 24,
    ) -> list[dict]:
        """全文检索告警 (进程名/IP/规则/消息)"""
        client = await self._get_client()
        body = {
            "query": {
                "bool": {
                    "must": [
                        {
                            "multi_match": {
                                "query": query,
                                "fields": [
                                    "event.action^2",
                                    "event.original.process_name^3",
                                    "event.original.cmdline^2",
                                    "source.ip",
                                    "destination.ip",
                                    "host.name",
                                    "rule.id",
                                ],
                            }
                        },
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": f"now-{time_range_hours}h",
                                    "lte": "now",
                                }
                            }
                        },
                    ]
                }
            },
            "sort": [{"@timestamp": {"order": "desc"}}],
            "size": size,
        }
        try:
            resp = await client.post("/secsiem-alerts-*/_search", json=body)
            resp.raise_for_status()
            hits = resp.json().get("hits", {}).get("hits", [])
            return [self._format_hit(h) for h in hits]
        except Exception as e:  # noqa: BLE001
            raise OpenSearchError(f"OpenSearch 搜索失败: {e}") from e

    def _format_hit(self, hit: dict) -> dict:
        src = hit.get("_source", {})
        return {
            "alert_id": src.get("event", {}).get("id"),
            "ts": src.get("@timestamp"),
            "severity": src.get("event", {}).get("severity"),
            "message": src.get("event", {}).get("action"),
            "src_ip": src.get("source", {}).get("ip"),
            "dst_ip": src.get("destination", {}).get("ip"),
            "hostname": src.get("host", {}).get("name"),
            "rule_id": src.get("rule", {}).get("id"),
            "mitre_tactics": src.get("threat", {}).get("tactic", {}).get("name", []),
            "mitre_techniques": src.get("threat", {}).get("technique", {}).get("id", []),
            "raw": src.get("event", {}).get("original", {}),
            "score": hit.get("_score"),
        }

    async def health(self) -> dict:
        """OpenSearch 集群健康"""
        client = await self._get_client()
        try:
            resp = await client.get("/_cluster/health")
            resp.raise_for_status()
            return resp.json()
        except Exception as e:  # noqa: BLE001
            return {"status": "unreachable", "error": str(e)}

    async def close(self) -> None:
        if self._client and not self._client.is_closed:
            await self._client.aclose()


# 单例工厂
_client: OpenSearchClient | None = None


def get_opensearch() -> OpenSearchClient:
    global _client
    if _client is None:
        _client = OpenSearchClient()
    return _client
