"""迁移版本校验 — 生产启动前 fail-fast

生产环境不自动跑 migration (多实例并发会锁死),
改为启动时校验 DB 版本 == 代码期望的 head,不匹配则拒绝启动。
"""
from __future__ import annotations

from pathlib import Path

from sqlalchemy import text

from app.db.database import async_session

import structlog

log = structlog.get_logger()


class MigrationMismatchError(RuntimeError):
    """DB schema 版本与代码不匹配"""


def _expected_head() -> str | None:
    """从 alembic/versions/ 解析 head revision

    head = 没有被其他 migration 作为 down_revision 引用的那个。
    """
    versions_dir = Path(__file__).resolve().parents[2] / "alembic" / "versions"
    if not versions_dir.is_dir():
        return None

    revisions: set[str] = set()
    down_refs: set[str] = set()
    for f in versions_dir.glob("*.py"):
        text_content = f.read_text(encoding="utf-8")
        for line in text_content.splitlines():
            s = line.strip()
            if s.startswith("revision:") or s.startswith("revision ="):
                rev = s.split("=")[-1].strip().strip("'\"")
                if rev and rev != "None":
                    revisions.add(rev)
            elif s.startswith("down_revision:") or s.startswith("down_revision ="):
                dr = s.split("=")[-1].strip().strip("'\"")
                if dr and dr != "None":
                    down_refs.add(dr)

    heads = revisions - down_refs
    return next(iter(heads)) if len(heads) == 1 else None


async def _current_db_revision() -> str | None:
    async with async_session() as session:
        try:
            r = await session.execute(text("SELECT version_num FROM alembic_version"))
            return r.scalar()
        except Exception:  # noqa: BLE001 - 表不存在 = 未迁移
            return None


async def assert_head() -> None:
    """校验 DB 已迁移到最新,否则抛异常拒绝启动"""
    expected = _expected_head()
    if not expected:
        log.warning("migration.head_undetermined", note="跳过校验")
        return

    current = await _current_db_revision()
    if current is None:
        raise MigrationMismatchError(
            f"数据库未初始化 (无 alembic_version 表)。"
            f"请先执行: ./deploy/migrate.sh  (期望版本 {expected})"
        )
    if current != expected:
        raise MigrationMismatchError(
            f"数据库 schema 版本落后: DB={current}, 代码期望={expected}。"
            f"请执行: ./deploy/migrate.sh"
        )
    log.info("migration.verified", revision=current)
