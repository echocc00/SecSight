"""OpenCTI 集成 — GraphQL 查询 IoC + APT 归因

OpenCTI 是本地 STIX 知识库,和 AbuseIPDB/OTX 的区别:
  - 云端源查的是"这个 IP 现在坏不坏"
  - OpenCTI 查的是"这个 IoC 在我们自己的情报库里关联到哪个威胁组织/战役"
    → 能给出 APT 归因和 ATT&CK 技术,这是云端免费源给不了的

License 隔离: OpenCTI AGPL-3.0,只走 HTTP GraphQL,不 import 其代码,
不 fork 其连接器 —— 见 AGENTS.md license 约束。
"""
from __future__ import annotations

from typing import Any

import httpx
import structlog

from app.models.schemas import IntelResult
from app.threat_intel.base import ThreatIntelError, ThreatIntelProvider

log = structlog.get_logger()

# STIX Cyber Observable 类型 (OpenCTI 用 STIX 命名,与我们的 indicator_type 不同)
_STIX_TYPE_MAP = {
    "ip": "IPv4-Addr",
    "domain": "Domain-Name",
    "file_hash": "StixFile",
    "url": "Url",
}

# 按 observable 值精确查,附带关联的 indicator/report/intrusion-set
_OBSERVABLE_QUERY = """
query SearchObservable($filters: FilterGroup) {
  stixCyberObservables(first: 5, filters: $filters) {
    edges {
      node {
        id
        entity_type
        observable_value
        x_opencti_score
        createdBy { name }
        objectLabel { value }
        indicators {
          edges {
            node {
              id
              name
              confidence
              valid_until
              revoked
              x_mitre_platforms
              killChainPhases { kill_chain_name phase_name }
            }
          }
        }
        reports(first: 5) {
          edges { node { id name published } }
        }
      }
    }
  }
}
"""

# IoC → 关联威胁组织 (APT 归因)。stixCoreRelationships 双向查,
# 因为归因关系可能是 observable→intrusion-set 也可能反向。
_ATTRIBUTION_QUERY = """
query Attribution($id: String!) {
  stixCoreObject(id: $id) {
    id
    ... on StixCyberObservable {
      stixCoreRelationships(first: 20) {
        edges {
          node {
            relationship_type
            confidence
            from {
              ... on IntrusionSet { id name aliases description }
              ... on Malware { id name malware_types }
              ... on Campaign { id name }
              ... on AttackPattern { id name x_mitre_id }
            }
            to {
              ... on IntrusionSet { id name aliases description }
              ... on Malware { id name malware_types }
              ... on Campaign { id name }
              ... on AttackPattern { id name x_mitre_id }
            }
          }
        }
      }
    }
  }
}
"""


class OpenCTIError(ThreatIntelError):
    """OpenCTI 查询失败 (触发降级到其他情报源)"""


class OpenCTIClient:
    """OpenCTI GraphQL 客户端 (仅读)"""

    def __init__(self, base_url: str, token: str, timeout: int = 15) -> None:
        if not token:
            raise OpenCTIError("OPENCTI_ADMIN_TOKEN 未配置")
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.timeout = timeout

    async def _graphql(self, query: str, variables: dict) -> dict:
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(
                    f"{self.base_url}/graphql",
                    json={"query": query, "variables": variables},
                    headers={
                        "Authorization": f"Bearer {self.token}",
                        "Content-Type": "application/json",
                    },
                )
                resp.raise_for_status()
                payload = resp.json()
        except Exception as e:  # noqa: BLE001
            raise OpenCTIError(f"OpenCTI GraphQL 请求失败: {e}") from e

        # GraphQL 200 也可能带 errors —— 不检查会把 None 当成"查无此 IoC"
        if payload.get("errors"):
            messages = "; ".join(
                str(err.get("message", err)) for err in payload["errors"]
            )
            raise OpenCTIError(f"OpenCTI GraphQL 返回错误: {messages}")
        return payload.get("data") or {}

    async def search_observable(self, indicator_type: str, value: str) -> dict | None:
        """按值精确查 observable,返回 None 表示情报库里没有"""
        stix_type = _STIX_TYPE_MAP.get(indicator_type)
        if not stix_type:
            raise OpenCTIError(f"不支持的 indicator_type: {indicator_type}")

        filters = {
            "mode": "and",
            "filters": [
                {"key": "entity_type", "values": [stix_type], "operator": "eq"},
                {"key": "value", "values": [value], "operator": "eq"},
            ],
            "filterGroups": [],
        }
        data = await self._graphql(_OBSERVABLE_QUERY, {"filters": filters})
        edges = ((data.get("stixCyberObservables") or {}).get("edges")) or []
        if not edges:
            return None
        return edges[0]["node"]

    async def get_attribution(self, observable_id: str) -> dict:
        """查 IoC 关联的威胁组织/恶意软件/战役/ATT&CK 技术"""
        data = await self._graphql(_ATTRIBUTION_QUERY, {"id": observable_id})
        obj = data.get("stixCoreObject") or {}
        edges = ((obj.get("stixCoreRelationships") or {}).get("edges")) or []

        intrusion_sets: list[dict] = []
        malwares: list[dict] = []
        campaigns: list[dict] = []
        techniques: list[str] = []

        for edge in edges:
            node = edge.get("node") or {}
            confidence = node.get("confidence")
            # 关系两端都要看: 归因方向不固定
            for side in ("from", "to"):
                entity = node.get(side) or {}
                name = entity.get("name")
                if not name:
                    continue
                if "aliases" in entity:
                    intrusion_sets.append(
                        {
                            "name": name,
                            "aliases": entity.get("aliases") or [],
                            "confidence": confidence,
                            "relationship": node.get("relationship_type"),
                        }
                    )
                elif "malware_types" in entity:
                    malwares.append(
                        {"name": name, "types": entity.get("malware_types") or []}
                    )
                elif "x_mitre_id" in entity:
                    mitre_id = entity.get("x_mitre_id")
                    if mitre_id:
                        techniques.append(mitre_id)
                else:
                    campaigns.append({"name": name})

        return {
            "intrusion_sets": _dedup_by_name(intrusion_sets),
            "malwares": _dedup_by_name(malwares),
            "campaigns": _dedup_by_name(campaigns),
            "mitre_techniques": sorted(set(techniques)),
        }


def _dedup_by_name(items: list[dict]) -> list[dict]:
    seen: set[str] = set()
    result: list[dict] = []
    for item in items:
        name = item.get("name", "")
        if name and name not in seen:
            seen.add(name)
            result.append(item)
    return result


class OpenCTIProvider(ThreatIntelProvider):
    """OpenCTI 作为 ThreatIntelService 的第 3 provider

    与云端源并行查询,由 ConfidenceSynthesizer 合成 —— OpenCTI 命中会带上
    APT 归因,这是它独有的价值。
    """

    name = "opencti"
    is_paid = False
    supports = ("ip", "domain", "file_hash", "url")

    def __init__(
        self,
        base_url: str,
        token: str,
        timeout: int = 15,
        malicious_score: int = 50,
    ) -> None:
        self.client = OpenCTIClient(base_url, token, timeout)
        self.malicious_score = malicious_score

    async def _query(self, indicator_type: str, value: str) -> IntelResult:
        node = await self.client.search_observable(indicator_type, value)
        if not node:
            # 库里没有 ≠ 安全,只是无情报。confidence=0 让合成器忽略这一票。
            return IntelResult(
                indicator=value,
                indicator_type=indicator_type,
                provider=self.name,
                confidence=0.0,
                malicious=False,
                tags=["opencti:not_found"],
            )

        score = node.get("x_opencti_score") or 0
        labels = [
            lbl.get("value")
            for lbl in (node.get("objectLabel") or [])
            if lbl.get("value")
        ]
        indicators = [
            e["node"] for e in ((node.get("indicators") or {}).get("edges") or [])
        ]
        # revoked 的 indicator 不能算命中 —— 情报已被撤回
        active = [i for i in indicators if not i.get("revoked")]

        attribution = await self.client.get_attribution(node["id"])
        techniques = list(attribution["mitre_techniques"])
        for indicator in active:
            for phase in indicator.get("killChainPhases") or []:
                phase_name = phase.get("phase_name")
                if phase_name:
                    labels.append(f"kill_chain:{phase_name}")

        tags = [f"opencti:score:{score}"] + labels
        for intrusion_set in attribution["intrusion_sets"]:
            tags.append(f"apt:{intrusion_set['name']}")
        for malware in attribution["malwares"]:
            tags.append(f"malware:{malware['name']}")

        malicious = score >= self.malicious_score or bool(active)
        # 有 APT 归因说明是本地已确认的定向威胁,置信度直接给高
        confidence = min(score / 100, 1.0)
        if attribution["intrusion_sets"]:
            confidence = max(confidence, 0.8)
        elif active:
            confidence = max(confidence, 0.6)

        return IntelResult(
            indicator=value,
            indicator_type=indicator_type,
            provider=self.name,
            confidence=confidence,
            malicious=malicious,
            tags=sorted(set(tags)),
            mitre_ttps=techniques,
            raw={
                "observable_id": node["id"],
                "entity_type": node.get("entity_type"),
                "x_opencti_score": score,
                "indicator_count": len(indicators),
                "active_indicator_count": len(active),
                "attribution": attribution,
            },
        )

    async def query_ip(self, ip: str) -> IntelResult:
        return await self._query("ip", ip)

    async def query_domain(self, domain: str) -> IntelResult:
        return await self._query("domain", domain)

    async def query_file_hash(self, hash: str) -> IntelResult:
        return await self._query("file_hash", hash)

    async def query_url(self, url: str) -> IntelResult:
        return await self._query("url", url)


async def health_check() -> dict[str, Any]:
    """OpenCTI 连通性 (供 /health 用)"""
    from app.core.config import settings

    if not settings.enable_opencti:
        return {"enabled": False, "status": "disabled"}
    if not settings.opencti_token:
        return {"enabled": True, "status": "misconfigured", "reason": "token 未配置"}

    try:
        client = OpenCTIClient(
            settings.opencti_base_url,
            settings.opencti_token,
            settings.opencti_timeout_seconds,
        )
        await client._graphql("query { about { version } }", {})
        return {"enabled": True, "status": "ok"}
    except Exception as e:  # noqa: BLE001
        return {"enabled": True, "status": "down", "reason": str(e)}
