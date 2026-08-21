"""知识入库脚本 — 把 ATT&CK/案例知识灌入 Qdrant

用法 (Qdrant 已启动):
  PYTHONPATH=. python scripts/ingest_knowledge.py
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

# 确保 backend 在 path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.retrieval.mock import _MOCK_KNOWLEDGE  # noqa: E402
from app.retrieval.qdrant_retriever import QdrantRetriever  # noqa: E402
from app.core.config import settings  # noqa: E402


async def main() -> int:
    print(f"Qdrant: {settings.qdrant_url}")
    retriever = QdrantRetriever(url=settings.qdrant_url, api_key=settings.qdrant_api_key)
    count = await retriever.ingest_knowledge(_MOCK_KNOWLEDGE)
    print(f"已灌入 {count} 条知识 chunks → collection 'secsight_knowledge'")
    # 验证检索
    results = await retriever.search("xmrig mining stratum", top_k=3)
    print(f"\n验证检索 'xmrig mining stratum' → {len(results)} 条命中:")
    for r in results:
        print(f"  - {r.get('id')}: {r.get('name','')} (score={r.get('score',0):.3f})")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
