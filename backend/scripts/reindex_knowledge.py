#!/usr/bin/env python3
"""知识重建索引 — 换 embedding provider 后重新向量化入 Qdrant

换 provider 会改向量维度 (tfidf 256 / bge-m3 1024)。collection 名带维度后缀,
所以旧索引不会被污染,但新 collection 是空的 —— 必须重跑这个脚本,否则
RAG 检索一直返回 0 命中而不报错。

用法:
    cd backend
    EMBEDDING_PROVIDER=bge ENABLE_QDRANT=true python scripts/reindex_knowledge.py
    python scripts/reindex_knowledge.py --dry-run    # 只看会索引什么
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

import yaml

_BACKEND_ROOT = Path(__file__).resolve().parents[1]
_PROJECT_ROOT = _BACKEND_ROOT.parent
if str(_BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(_BACKEND_ROOT))

KNOWLEDGE_DIR = _PROJECT_ROOT / "knowledge"

# 常见容器键: 文件顶层是 dict 时,知识条目挂在这些 key 下
_CONTAINER_KEYS = ("skills", "rules", "techniques", "cases", "items")


def _load_yaml_knowledge() -> list[dict]:
    """扫 knowledge/ 下所有 YAML,拍平成 chunk 列表

    L1 战术层文件结构不统一 (有的顶层是 list,有的是 dict 带 skills/rules),
    统一按 "取出所有 dict 条目" 处理,给每条补 id/type/source_file。
    """
    chunks: list[dict] = []
    if not KNOWLEDGE_DIR.exists():
        return chunks

    for path in sorted(KNOWLEDGE_DIR.rglob("*.yaml")):
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
        except Exception as e:  # noqa: BLE001
            print(f"  [skip] {path.name}: YAML 解析失败 {e}")
            continue
        if not data:
            continue

        rel = str(path.relative_to(_PROJECT_ROOT)).replace("\\", "/")
        layer = path.relative_to(KNOWLEDGE_DIR).parts[0]

        items: list[dict] = []
        if isinstance(data, list):
            items = [d for d in data if isinstance(d, dict)]
        elif isinstance(data, dict):
            for key in _CONTAINER_KEYS:
                value = data.get(key)
                if isinstance(value, list):
                    items.extend(d for d in value if isinstance(d, dict))
            if not items:
                items = [data]

        for i, item in enumerate(items):
            chunk = dict(item)
            chunk.setdefault("id", f"{rel}#{i}")
            chunk.setdefault("type", "knowledge")
            chunk["layer"] = layer
            chunk["source_file"] = rel
            chunks.append(chunk)

    return chunks


def _load_jsonl_knowledge() -> list[dict]:
    chunks: list[dict] = []
    if not KNOWLEDGE_DIR.exists():
        return chunks
    for path in sorted(KNOWLEDGE_DIR.rglob("*.jsonl")):
        rel = str(path.relative_to(_PROJECT_ROOT)).replace("\\", "/")
        with open(path, encoding="utf-8") as f:
            for i, line in enumerate(f):
                line = line.strip()
                if not line:
                    continue
                try:
                    item = json.loads(line)
                except json.JSONDecodeError as e:
                    print(f"  [skip] {rel}:{i + 1} JSON 解析失败 {e}")
                    continue
                item.setdefault("id", f"{rel}#{i}")
                item["source_file"] = rel
                chunks.append(item)
    return chunks


def _builtin_knowledge() -> list[dict]:
    """内置 ATT&CK 预设知识 —— 知识库为空时也要有可检索内容"""
    from app.retrieval.mock import _MOCK_KNOWLEDGE

    return [dict(c) for c in _MOCK_KNOWLEDGE]


def collect_chunks(include_builtin: bool = True) -> list[dict]:
    chunks = _load_yaml_knowledge() + _load_jsonl_knowledge()
    if include_builtin:
        chunks += _builtin_knowledge()
    return chunks


async def reindex(dry_run: bool = False, include_builtin: bool = True) -> int:
    from app.core.config import settings
    from app.retrieval.embedding import get_embedding_provider
    from app.retrieval.qdrant_retriever import QdrantRetriever, collection_name

    provider = get_embedding_provider()
    print(f"embedding provider: {provider.name} (dim={provider.dim})")
    print(f"target collection : {collection_name(provider.dim)}")

    if provider.name == "tfidf" and settings.embedding_provider != "tfidf":
        print(
            f"[WARN] 配置要求 {settings.embedding_provider} 但实际降级到 tfidf —— "
            "模型未装或加载失败,索引质量会很差。检查日志后再重跑。"
        )

    chunks = collect_chunks(include_builtin)
    print(f"待索引 chunks: {len(chunks)}")
    if not chunks:
        print("知识库为空,无需索引")
        return 0

    if dry_run:
        for chunk in chunks[:10]:
            print(f"  - {chunk.get('id')} ({chunk.get('type')})")
        if len(chunks) > 10:
            print(f"  ... 还有 {len(chunks) - 10} 条")
        return 0

    if not settings.enable_qdrant:
        print("[FAIL] ENABLE_QDRANT=false,拒绝写入 (设为 true 后重跑)")
        return 1

    retriever = QdrantRetriever(url=settings.qdrant_url, api_key=settings.qdrant_api_key)
    count = await retriever.ingest_knowledge(chunks)
    print(f"[OK] 已写入 {count} 条到 {retriever.collection}")

    probe = await retriever.search("xmrig 挖矿 高 CPU", top_k=3)
    print(f"检索自检: 命中 {len(probe)} 条")
    for hit in probe:
        print(f"  score={hit.get('score'):.4f} id={hit.get('id')}")
    if not probe:
        print("[WARN] 写入成功但检索为空 —— 检查 Qdrant 索引状态")
        return 1
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="重建 Qdrant 知识索引")
    parser.add_argument("--dry-run", action="store_true", help="只列出待索引内容")
    parser.add_argument(
        "--no-builtin", action="store_true", help="不包含内置 ATT&CK 预设知识"
    )
    args = parser.parse_args()
    return asyncio.run(reindex(args.dry_run, include_builtin=not args.no_builtin))


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.exit(main())
