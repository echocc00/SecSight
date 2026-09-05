#!/usr/bin/env bash
# 数据库迁移 — 生产部署前执行 (不在应用启动时自动跑,避免多实例并发锁)
#
# 用法:
#   ./migrate.sh              # 升级到最新
#   ./migrate.sh downgrade -1 # 回退一个版本
#   ./migrate.sh current      # 查看当前版本
#   ./migrate.sh history      # 查看迁移历史
set -euo pipefail

cd "$(dirname "$0")"

if [ ! -f .env ]; then
  echo "❌ deploy/.env 不存在,先从 .env.example 复制"
  exit 1
fi

CMD="${1:-upgrade}"
ARG="${2:-head}"

echo "▶ 数据库迁移: alembic $CMD $ARG"
docker compose run --rm --no-deps \
  -e DATABASE_URL="postgresql+asyncpg://$(grep '^POSTGRES_USER=' .env | cut -d= -f2):$(grep '^POSTGRES_PASSWORD=' .env | cut -d= -f2-)@postgres:5432/$(grep '^POSTGRES_DB=' .env | cut -d= -f2)" \
  secsight-backend alembic "$CMD" "$ARG"

echo "✅ 迁移完成"
