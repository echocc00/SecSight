"""Embedding provider — 文本向量化

轻量实现: numpy TF-IDF (无外部模型依赖,机制跑通)
可升级: sentence-transformers BGE-m3 / 云端 embedding API (替换此类即可)
"""
from __future__ import annotations

import hashlib
import re
from collections import Counter

import numpy as np

# 固定词表维度 (hashing trick,无需预训练词表)
_EMBED_DIM = 256


def _tokenize(text: str) -> list[str]:
    """简单分词: 中英文混合,按非字母数字切分"""
    text = text.lower()
    # 英文: 按非字母切;中文: 按字符
    tokens = re.findall(r"[a-z0-9]+|[一-鿿]", text)
    return tokens


def _hash_token(token: str) -> int:
    """token → 维度索引 (hashing trick)"""
    h = hashlib.md5(token.encode()).hexdigest()
    return int(h[:8], 16) % _EMBED_DIM


class EmbeddingProvider:
    """文本 embedding (numpy hash-based bag-of-words)

    升级路径: 替换 embed() 为 sentence-transformers 或云端 API。
    维度 _EMBED_DIM 需与 Qdrant collection 一致。
    """

    dim: int = _EMBED_DIM

    def embed(self, text: str) -> list[float]:
        """文本 → 向量 (L2 归一化)"""
        tokens = _tokenize(text)
        if not tokens:
            return [0.0] * _EMBED_DIM

        vec = np.zeros(_EMBED_DIM, dtype=np.float32)
        counts = Counter(tokens)
        for token, count in counts.items():
            idx = _hash_token(token)
            # TF-IDF 近似: TF * log(N/DF),这里用 TF * token 长度加权
            vec[idx] += count * (1.0 + len(token) / 10.0)

        # L2 归一化
        norm = np.linalg.norm(vec)
        if norm > 0:
            vec = vec / norm
        return vec.tolist()

    def embed_batch(self, texts: list[str]) -> list[list[float]]:
        return [self.embed(t) for t in texts]


embedding_provider = EmbeddingProvider()
