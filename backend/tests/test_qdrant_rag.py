"""Qdrant RAG 测试 — embedding + 检索 + 入库 (mock Qdrant,无需真实容器)"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.retrieval.embedding import EmbeddingProvider, embedding_provider
from app.retrieval.mock import KnowledgeRetriever, MockRetriever, get_retriever


class TestEmbeddingProvider:
    def test_embed_returns_fixed_dim(self):
        vec = embedding_provider.embed("xmrig mining")
        assert len(vec) == EmbeddingProvider.dim

    def test_embed_normalizes_l2(self):
        vec = embedding_provider.embed("cryptominer stratum pool")
        norm = sum(v * v for v in vec) ** 0.5
        assert 0.99 <= norm <= 1.01  # L2 归一化

    def test_empty_text_returns_zero_vector(self):
        vec = embedding_provider.embed("")
        assert all(v == 0.0 for v in vec)

    def test_similar_texts_closer_than_dissimilar(self):
        import numpy as np

        v1 = np.array(embedding_provider.embed("xmrig cryptominer mining"))
        v2 = np.array(embedding_provider.embed("xmrig mining pool stratum"))
        v3 = np.array(embedding_provider.embed("ransomware encrypt files"))
        cos12 = float(v1 @ v2 / (np.linalg.norm(v1) * np.linalg.norm(v2) + 1e-9))
        cos13 = float(v1 @ v3 / (np.linalg.norm(v1) * np.linalg.norm(v3) + 1e-9))
        assert cos12 > cos13  # 相似文本余弦更高

    def test_embed_batch(self):
        vecs = embedding_provider.embed_batch(["a", "b"])
        assert len(vecs) == 2
        assert all(len(v) == EmbeddingProvider.dim for v in vecs)


class TestGetRetrieverFactory:
    def test_returns_mock_in_mock_mode(self):
        assert isinstance(get_retriever(), MockRetriever)

    def test_returns_qdrant_when_enabled(self, monkeypatch):
        from app.core import config as cfg

        monkeypatch.setattr(cfg.settings, "mock_mode", False)
        monkeypatch.setattr(cfg.settings, "enable_qdrant", True)
        from app.retrieval.mock import QdrantRetriever

        assert isinstance(get_retriever(), QdrantRetriever)


class TestQdrantRetriever:
    """用 mock Qdrant client 测试检索逻辑 (无需真实容器)"""

    @pytest.mark.asyncio
    async def test_search_returns_payloads_with_score(self):
        from app.retrieval.qdrant_retriever import QdrantRetriever

        retriever = QdrantRetriever(url="http://fake:6333")
        # mock client
        point = MagicMock()
        point.payload = {"id": "attck:T1496", "name": "Resource Hijacking"}
        point.score = 0.92
        response = MagicMock()
        response.points = [point]
        retriever.client.query_points = AsyncMock(return_value=response)
        retriever.ensure_collection = AsyncMock()

        results = await retriever.search("xmrig mining", top_k=1)
        assert len(results) == 1
        assert results[0]["id"] == "attck:T1496"
        assert results[0]["score"] == 0.92

    @pytest.mark.asyncio
    async def test_search_returns_empty_on_failure(self):
        from app.retrieval.qdrant_retriever import QdrantRetriever

        retriever = QdrantRetriever(url="http://fake:6333")
        retriever.ensure_collection = AsyncMock(side_effect=RuntimeError("down"))
        results = await retriever.search("x", top_k=3)
        assert results == []

    @pytest.mark.asyncio
    async def test_ingest_knowledge_upserts_points(self):
        from app.retrieval.qdrant_retriever import QdrantRetriever

        retriever = QdrantRetriever(url="http://fake:6333")
        retriever.ensure_collection = AsyncMock()
        retriever.client.upsert = AsyncMock()
        items = [{"id": "T1496", "name": "Resource Hijacking", "description": "挖矿"}]
        count = await retriever.ingest_knowledge(items)
        assert count == 1
        assert retriever.client.upsert.await_count == 1

    @pytest.mark.asyncio
    async def test_search_accepts_message_list(self):
        from app.retrieval.qdrant_retriever import QdrantRetriever

        retriever = QdrantRetriever(url="http://fake:6333")
        response = MagicMock()
        response.points = []
        retriever.client.query_points = AsyncMock(return_value=response)
        retriever.ensure_collection = AsyncMock()
        # 消息列表输入不应报错
        results = await retriever.search(
            [{"role": "user", "content": "xmrig detected"}], top_k=2
        )
        assert results == []


# ============ 真实 Qdrant 冒烟 (容器在跑才执行) ============


@pytest.mark.skipif(
    True,  # 默认跳过; 设 SECSIGHT_QDRANT_LIVE=1 启用
    reason="需 Qdrant 容器运行,设 SECSIGHT_QDRANT_LIVE=1 启用",
)
class TestLiveQdrant:
    @pytest.mark.asyncio
    async def test_live_ingest_and_search(self):
        from app.retrieval.qdrant_retriever import QdrantRetriever

        r = QdrantRetriever(url="http://localhost:6333")
        await r.ingest_knowledge([{"id": "test", "name": "xmrig test", "description": "mining"}])
        results = await r.search("xmrig mining", top_k=1)
        assert len(results) >= 1
