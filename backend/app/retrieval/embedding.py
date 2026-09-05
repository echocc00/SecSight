"""Embedding provider — 文本向量化

三种实现,按 EMBEDDING_PROVIDER 选择:
  - tfidf: numpy hashing trick,无外部依赖,256 维 (默认/兜底)
  - bge:   本地 sentence-transformers (BAAI/bge-m3, 1024 维),需装 [embedding] extra
  - api:   OpenAI 兼容 embedding 端点 (维度由模型决定)

维度必须与 Qdrant collection 一致 —— 换 provider 后要重建索引,
见 deploy/reindex_knowledge.py。
"""
from __future__ import annotations

import hashlib
import re
from abc import ABC, abstractmethod
from collections import Counter

import numpy as np
import structlog

log = structlog.get_logger()

# TF-IDF 固定维度 (hashing trick,无需预训练词表)
_TFIDF_DIM = 256


def _tokenize(text: str) -> list[str]:
    """简单分词: 中英文混合,按非字母数字切分"""
    text = text.lower()
    # 英文: 按非字母切;中文: 按字符
    return re.findall(r"[a-z0-9]+|[一-鿿]", text)


def _hash_token(token: str) -> int:
    """token → 维度索引 (hashing trick)"""
    h = hashlib.md5(token.encode()).hexdigest()
    return int(h[:8], 16) % _TFIDF_DIM


class BaseEmbedding(ABC):
    """embedding 抽象。dim 必须与 Qdrant collection 向量维度一致。"""

    name: str = "base"
    dim: int = 0

    @abstractmethod
    def embed(self, text: str) -> list[float]: ...

    def embed_batch(self, texts: list[str]) -> list[list[float]]:
        return [self.embed(t) for t in texts]


class TFIDFEmbedding(BaseEmbedding):
    """numpy hash-based bag-of-words — 无模型依赖的兜底实现

    检索质量明显弱于语义模型 (只能命中字面重合),仅用于 mock/离线环境。
    """

    name = "tfidf"
    dim = _TFIDF_DIM

    def embed(self, text: str) -> list[float]:
        tokens = _tokenize(text)
        if not tokens:
            return [0.0] * _TFIDF_DIM

        vec = np.zeros(_TFIDF_DIM, dtype=np.float32)
        for token, count in Counter(tokens).items():
            vec[_hash_token(token)] += count * (1.0 + len(token) / 10.0)

        norm = np.linalg.norm(vec)
        if norm > 0:
            vec = vec / norm
        return vec.tolist()


class BGEEmbedding(BaseEmbedding):
    """本地 sentence-transformers (BAAI/bge-m3 等)

    首次加载会下载模型 (bge-m3 约 2GB) 并常驻内存,所以模型只在
    进程内加载一次。中英文混合语料上明显优于 TF-IDF。
    """

    name = "bge"

    def __init__(self, model_name: str, device: str = "cpu") -> None:
        from sentence_transformers import SentenceTransformer

        self.model_name = model_name
        self.model = SentenceTransformer(model_name, device=device)
        # sentence-transformers 6.x 把 get_sentence_embedding_dimension 改名为
        # get_embedding_dimension,两个名字都要支持
        getter = getattr(
            self.model, "get_embedding_dimension", None
        ) or self.model.get_sentence_embedding_dimension
        self.dim = int(getter())
        log.info("embedding.bge_loaded", model=model_name, dim=self.dim, device=device)

    def embed(self, text: str) -> list[float]:
        vec = self.model.encode(text, normalize_embeddings=True)
        return [float(x) for x in vec]

    def embed_batch(self, texts: list[str]) -> list[list[float]]:
        # 批量编码远快于逐条 (一次前向传播处理整批)
        vectors = self.model.encode(texts, normalize_embeddings=True)
        return [[float(x) for x in v] for v in vectors]


class APIEmbedding(BaseEmbedding):
    """OpenAI 兼容 embedding 端点 (如智谱/通义/本地 vLLM)

    维度按首次调用的返回结果确定 —— 不同模型维度不同,写死会与
    collection 不匹配。
    """

    name = "api"

    def __init__(self, base_url: str, api_key: str, model: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.model = model
        self._dim = 0

    @property
    def dim(self) -> int:
        if not self._dim:
            self.embed("dimension probe")
        return self._dim

    @dim.setter
    def dim(self, value: int) -> None:
        self._dim = value

    def embed(self, text: str) -> list[float]:
        import httpx

        resp = httpx.post(
            f"{self.base_url}/embeddings",
            json={"model": self.model, "input": text},
            headers={"Authorization": f"Bearer {self.api_key}"},
            timeout=30,
        )
        resp.raise_for_status()
        vector = resp.json()["data"][0]["embedding"]
        self._dim = len(vector)
        return [float(x) for x in vector]


def build_provider(name: str | None = None) -> BaseEmbedding:
    """按配置构造 provider,失败按 embedding_fallback_to_tfidf 决定是否降级"""
    from app.core.config import settings

    name = (name or settings.embedding_provider).lower()

    if name == "tfidf":
        return TFIDFEmbedding()

    try:
        if name == "bge":
            return BGEEmbedding(settings.embedding_model, settings.embedding_device)
        if name == "api":
            if not settings.embedding_api_base:
                raise ValueError("EMBEDDING_PROVIDER=api 但 EMBEDDING_API_BASE 未配置")
            return APIEmbedding(
                settings.embedding_api_base,
                settings.embedding_api_key,
                settings.embedding_model,
            )
        raise ValueError(f"未知 EMBEDDING_PROVIDER: {name}")
    except Exception as e:  # noqa: BLE001
        if not settings.embedding_fallback_to_tfidf:
            raise
        log.error(
            "embedding.provider_failed_fallback_tfidf",
            provider=name,
            error=str(e),
            hint="检索质量将明显下降;生产设 EMBEDDING_FALLBACK_TO_TFIDF=false 以快速失败",
        )
        return TFIDFEmbedding()


_provider: BaseEmbedding | None = None


def get_embedding_provider() -> BaseEmbedding:
    """进程级单例 —— BGE 模型加载昂贵,不能每次检索都重建"""
    global _provider
    if _provider is None:
        _provider = build_provider()
    return _provider


def reset_embedding_provider() -> None:
    """清空单例 (改配置后重建,测试也用)"""
    global _provider
    _provider = None


def embedding_status() -> dict[str, object]:
    """embedding 实际生效情况 (供 /health 暴露)

    只报告已构造的 provider —— 不主动触发 BGE 模型加载,否则健康检查会
    在冷启动时阻塞几十秒。
    """
    from app.core.config import settings

    configured = settings.embedding_provider
    if _provider is None:
        return {
            "configured": configured,
            "active": None,
            "loaded": False,
            "collection_suffix": None,
            "degraded": False,
        }
    return {
        "configured": configured,
        "active": _provider.name,
        "loaded": True,
        "dim": _provider.dim,
        "collection_suffix": f"_{_provider.dim}",
        # 配置要真实模型却跑成 tfidf,说明模型加载失败降级了
        "degraded": _provider.name != configured,
    }


class _LazyProvider:
    """向后兼容的模块级句柄: embedding_provider.embed(...) 仍可用

    属性访问时才真正构造 provider,避免 import 期就加载 2GB 模型。
    """

    def __getattr__(self, item: str):
        return getattr(get_embedding_provider(), item)


embedding_provider = _LazyProvider()
