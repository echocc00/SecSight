"""Embedding provider 三实现 — 工厂选择 / 降级 / 维度隔离 / BGE 真实语义

BGE 相关测试需本地模型 (约 2GB),未装/未下载时自动跳过:
    pip install -r requirements-embedding.lock
    SECSIGHT_BGE_LIVE=1 pytest tests/test_embedding_providers.py
"""
from __future__ import annotations

import os

import numpy as np
import pytest

from app.retrieval.embedding import (
    APIEmbedding,
    BaseEmbedding,
    TFIDFEmbedding,
    build_provider,
    get_embedding_provider,
    reset_embedding_provider,
)


@pytest.fixture(autouse=True)
def _clean_singleton():
    reset_embedding_provider()
    yield
    reset_embedding_provider()


def _cos(a: list[float], b: list[float]) -> float:
    va, vb = np.array(a), np.array(b)
    return float(va @ vb / (np.linalg.norm(va) * np.linalg.norm(vb) + 1e-9))


class TestTFIDFEmbedding:
    def test_dim_is_256(self):
        assert TFIDFEmbedding().dim == 256

    def test_normalized(self):
        vec = TFIDFEmbedding().embed("xmrig mining pool")
        assert 0.99 <= sum(v * v for v in vec) ** 0.5 <= 1.01

    def test_same_language_similarity_works(self):
        p = TFIDFEmbedding()
        related = _cos(p.embed("xmrig mining pool"), p.embed("xmrig mining stratum"))
        unrelated = _cos(p.embed("xmrig mining pool"), p.embed("ransomware encryption"))
        assert related > unrelated

    def test_batch_matches_single(self):
        p = TFIDFEmbedding()
        assert p.embed_batch(["abc"])[0] == p.embed("abc")


class TestProviderFactory:
    def test_tfidf_by_default(self, monkeypatch):
        from app.core import config

        monkeypatch.setattr(config.settings, "embedding_provider", "tfidf")
        assert build_provider().name == "tfidf"

    def test_explicit_name_overrides_config(self, monkeypatch):
        from app.core import config

        monkeypatch.setattr(config.settings, "embedding_provider", "bge")
        assert build_provider("tfidf").name == "tfidf"

    def test_unknown_provider_falls_back(self, monkeypatch):
        from app.core import config

        monkeypatch.setattr(config.settings, "embedding_provider", "nonsense")
        monkeypatch.setattr(config.settings, "embedding_fallback_to_tfidf", True)
        assert build_provider().name == "tfidf"

    def test_unknown_provider_raises_when_fallback_disabled(self, monkeypatch):
        """生产必须能快速失败 —— 静默降级会让检索质量断崖下跌而无人察觉"""
        from app.core import config

        monkeypatch.setattr(config.settings, "embedding_provider", "nonsense")
        monkeypatch.setattr(config.settings, "embedding_fallback_to_tfidf", False)
        with pytest.raises(ValueError):
            build_provider()

    def test_api_without_base_url_raises_when_no_fallback(self, monkeypatch):
        from app.core import config

        monkeypatch.setattr(config.settings, "embedding_provider", "api")
        monkeypatch.setattr(config.settings, "embedding_api_base", "")
        monkeypatch.setattr(config.settings, "embedding_fallback_to_tfidf", False)
        with pytest.raises(ValueError):
            build_provider()

    def test_api_without_base_url_falls_back(self, monkeypatch):
        from app.core import config

        monkeypatch.setattr(config.settings, "embedding_provider", "api")
        monkeypatch.setattr(config.settings, "embedding_api_base", "")
        monkeypatch.setattr(config.settings, "embedding_fallback_to_tfidf", True)
        assert build_provider().name == "tfidf"

    def test_singleton_reused(self):
        assert get_embedding_provider() is get_embedding_provider()

    def test_reset_creates_new_instance(self):
        first = get_embedding_provider()
        reset_embedding_provider()
        assert get_embedding_provider() is not first


class TestEmbeddingStatus:
    def test_reports_not_loaded_before_first_use(self):
        from app.retrieval.embedding import embedding_status

        status = embedding_status()
        assert status["loaded"] is False
        assert status["active"] is None

    def test_reports_active_after_load(self, monkeypatch):
        from app.core import config
        from app.retrieval.embedding import embedding_status

        monkeypatch.setattr(config.settings, "embedding_provider", "tfidf")
        get_embedding_provider()
        status = embedding_status()
        assert status["loaded"] is True
        assert status["active"] == "tfidf"
        assert status["dim"] == 256
        assert status["degraded"] is False

    def test_flags_degradation(self, monkeypatch):
        """配置 bge 却跑成 tfidf 必须在 /health 暴露,否则没人发现检索变差了"""
        from app.core import config
        from app.retrieval.embedding import embedding_status

        monkeypatch.setattr(config.settings, "embedding_provider", "nonsense")
        monkeypatch.setattr(config.settings, "embedding_fallback_to_tfidf", True)
        get_embedding_provider()
        assert embedding_status()["degraded"] is True

    async def test_health_exposes_embedding(self, client):
        resp = await client.get("/health")
        assert "embedding" in resp.json()


class TestAPIEmbedding:
    def test_dim_probed_from_first_response(self, monkeypatch):
        """维度不能写死 —— 不同模型维度不同,写死会与 collection 不匹配"""
        import httpx

        class _Resp:
            def raise_for_status(self):
                pass

            def json(self):
                return {"data": [{"embedding": [0.1] * 768}]}

        monkeypatch.setattr(httpx, "post", lambda *a, **k: _Resp())
        provider = APIEmbedding("http://fake/v1", "key", "m3")
        assert provider.dim == 768

    def test_sends_bearer_token(self, monkeypatch):
        import httpx

        captured: dict = {}

        class _Resp:
            def raise_for_status(self):
                pass

            def json(self):
                return {"data": [{"embedding": [0.0] * 4}]}

        def _post(url, **kwargs):
            captured["url"] = url
            captured["headers"] = kwargs["headers"]
            return _Resp()

        monkeypatch.setattr(httpx, "post", _post)
        APIEmbedding("http://fake/v1/", "secret", "m3").embed("x")
        assert captured["url"] == "http://fake/v1/embeddings"
        assert captured["headers"]["Authorization"] == "Bearer secret"


class TestCollectionDimensionIsolation:
    def test_collection_name_includes_dim(self):
        from app.retrieval.qdrant_retriever import collection_name

        assert collection_name(256) != collection_name(1024)
        assert "256" in collection_name(256)

    def test_retriever_uses_provider_dim(self):
        from app.retrieval.qdrant_retriever import QdrantRetriever

        retriever = QdrantRetriever(url="http://fake:6333")
        assert retriever.dim == get_embedding_provider().dim
        assert str(retriever.dim) in retriever.collection

    def test_explicit_dim_overrides(self):
        from app.retrieval.qdrant_retriever import QdrantRetriever

        retriever = QdrantRetriever(url="http://fake:6333", dim=1024)
        assert retriever.collection.endswith("_1024")


_BGE_LIVE = os.environ.get("SECSIGHT_BGE_LIVE") == "1"


@pytest.mark.skipif(not _BGE_LIVE, reason="需本地 BGE 模型,设 SECSIGHT_BGE_LIVE=1 启用")
class TestBGEEmbeddingLive:
    """真实模型验证: 语义检索质量必须明显优于 TF-IDF"""

    @pytest.fixture(scope="class")
    def bge(self) -> BaseEmbedding:
        from app.retrieval.embedding import BGEEmbedding
        from app.core.config import settings

        return BGEEmbedding(settings.embedding_model, "cpu")

    def test_dim_is_1024_for_bge_m3(self, bge):
        assert bge.dim == 1024

    def test_vectors_normalized(self, bge):
        vec = bge.embed("xmrig 挖矿进程")
        assert 0.99 <= sum(v * v for v in vec) ** 0.5 <= 1.01

    def test_cross_lingual_semantics(self, bge):
        """中英同义句必须比中文无关句更近 —— TF-IDF 在这里判反"""
        cn = bge.embed("主机上发现 xmrig 挖矿进程,CPU 占用 98%")
        en = bge.embed("cryptomining malware detected, high CPU usage")
        unrelated = bge.embed("用户提交了报销申请单")
        assert _cos(cn, en) > _cos(cn, unrelated)

    def test_beats_tfidf_on_cross_lingual(self, bge):
        cn_text = "主机上发现 xmrig 挖矿进程,CPU 占用 98%"
        en_text = "cryptomining malware detected, high CPU usage"
        noise = "用户提交了报销申请单"

        tfidf = TFIDFEmbedding()
        tfidf_margin = _cos(tfidf.embed(cn_text), tfidf.embed(en_text)) - _cos(
            tfidf.embed(cn_text), tfidf.embed(noise)
        )
        bge_margin = _cos(bge.embed(cn_text), bge.embed(en_text)) - _cos(
            bge.embed(cn_text), bge.embed(noise)
        )
        assert bge_margin > tfidf_margin

    def test_paraphrase_without_shared_tokens(self, bge):
        """无字面重合的同义改写也要召回 —— TF-IDF 完全做不到"""
        a = bge.embed("勒索软件加密了所有文档并索要赎金")
        b = bge.embed("文件被恶意程序锁定,攻击者要求支付比特币")
        c = bge.embed("Nginx 配置文件语法错误导致启动失败")
        assert _cos(a, b) > _cos(a, c)

    def test_batch_matches_single(self, bge):
        single = bge.embed("xmrig mining")
        batched = bge.embed_batch(["xmrig mining", "other text"])[0]
        assert _cos(single, batched) > 0.999
