"""Qdrant 真实检索实现

流程:
  1. embedding_provider.embed(query) → 向量
  2. qdrant_client.search() HNSW top_k
  3. 返回 chunks (含 score)

知识入库: ingest_knowledge() 把 ATT&CK/案例文本写入 Qdrant collection。
"""
from __future__ import annotations

import hashlib
import json
import uuid
from pathlib import Path
from typing import Any

import structlog
from qdrant_client import AsyncQdrantClient
from qdrant_client.http import models as qm

from app.retrieval.embedding import embedding_provider
from app.retrieval.mock import KnowledgeRetriever

log = structlog.get_logger()

COLLECTION = "secsight_knowledge"


class QdrantRetriever(KnowledgeRetriever):
    """真实 Qdrant 向量检索"""

    def __init__(self, url: str, api_key: str = "", dim: int = embedding_provider.dim) -> None:
        self.client = AsyncQdrantClient(url=url, api_key=api_key or None)
        self.dim = dim

    async def ensure_collection(self) -> None:
        """确保 collection 存在 (幂等)"""
        collections = await self.client.get_collections()
        names = {c.name for c in collections.collections}
        if COLLECTION not in names:
            await self.client.create_collection(
                collection_name=COLLECTION,
                vectors_config=qm.VectorParams(size=self.dim, distance=qm.Distance.COSINE),
            )
            log.info("qdrant.collection_created", collection=COLLECTION, dim=self.dim)

    async def search(self, query: str | list[dict], top_k: int = 5) -> list[dict]:
        """向量检索 top_k chunks"""
        query_text = (
            query
            if isinstance(query, str)
            else " ".join(str(m.get("content", "")) for m in query)
        )
        vector = embedding_provider.embed(query_text)

        try:
            await self.ensure_collection()
            # qdrant-client 新版用 query_points (search 已弃用)
            response = await self.client.query_points(
                collection_name=COLLECTION,
                query=vector,
                limit=top_k,
                with_payload=True,
            )
            results = response.points
        except Exception as e:  # noqa: BLE001
            log.warning("qdrant.search_failed", error=str(e))
            return []

        chunks: list[dict] = []
        for point in results:
            payload = point.payload or {}
            payload["score"] = point.score
            chunks.append(payload)
        log.info("qdrant.search", query_len=len(query_text), hits=len(chunks))
        return chunks

    async def ingest_knowledge(self, items: list[dict]) -> int:
        """批量写入知识 chunks

        items: [{"id":..., "name":..., "description":..., "type":..., ...}]
        """
        await self.ensure_collection()
        points: list[qm.PointStruct] = []
        for item in items:
            text = " ".join(str(v) for v in item.values() if isinstance(v, (str, list)))
            vec = embedding_provider.embed(text)
            point_id = item.get("id") or text[:32]
            # 用确定性 UUID5 (基于 id 字符串),避免 hash 碰撞导致重复
            pid = str(uuid.uuid5(uuid.NAMESPACE_URL, str(point_id)))
            points.append(qm.PointStruct(id=pid, vector=vec, payload=item))

        await self.client.upsert(collection_name=COLLECTION, points=points)
        log.info("qdrant.ingested", count=len(points))
        return len(points)


async def ingest_from_jsonl(file_path: str) -> int:
    """从 JSONL 文件批量导入知识到 Qdrant"""
    from app.core.config import settings

    retriever = QdrantRetriever(
        url=settings.qdrant_url, api_key=settings.qdrant_api_key
    )
    items: list[dict] = []
    path = Path(file_path)
    if not path.exists():
        log.warning("qdrant.ingest_file_not_found", path=file_path)
        return 0
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                items.append(json.loads(line))
    return await retriever.ingest_knowledge(items)
