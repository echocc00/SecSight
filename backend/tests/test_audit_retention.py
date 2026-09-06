"""审计日志 retention 清理 — purge_before 链重建 + 调度器集成

等保 2.0 三级: 审计日志保存不少于 retention_days,到期后清理。
清理会断链,所以保留段重建为新链 (首条作 genesis)。
"""
from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from app.db.repositories import AuditLogRepository


async def _seed_mixed(repo: AuditLogRepository) -> None:
    """3 条过期 (190 天前) + 2 条近期"""
    old = datetime.utcnow() - timedelta(days=190)
    for i in range(3):
        await repo.record(action=f"old_{i}", actor="tester")
    # 把前 3 条时间戳改老 (record 用 utcnow,手动回填)
    from app.db.models import AuditLogModel
    from sqlalchemy import select

    rows = (await repo.session.execute(select(AuditLogModel).order_by(AuditLogModel.seq))).scalars().all()
    for m in rows[:3]:
        m.ts = old
    await repo.session.commit()
    for i in range(2):
        await repo.record(action=f"recent_{i}", actor="tester")


class TestPurgeBefore:
    async def test_removes_expired_and_rebuilds_chain(self, db_session):
        repo = AuditLogRepository(db_session)
        await _seed_mixed(repo)

        cutoff = datetime.utcnow() - timedelta(days=180)
        deleted = await repo.purge_before(cutoff)

        assert deleted == 3
        result = await repo.verify_chain()
        assert result["valid"] is True, result
        assert result["verified_count"] == 2

        # 保留段重建为 1..2 (seq 重排),不是旧 seq 3..5
        logs = await repo.list_recent()
        seqs = sorted(log["seq"] for log in logs)
        assert seqs == [1, 2]

    async def test_chain_usable_after_purge(self, db_session):
        """清理后继续写审计,链不断"""
        repo = AuditLogRepository(db_session)
        await _seed_mixed(repo)
        await repo.purge_before(datetime.utcnow() - timedelta(days=180))

        await repo.record(action="post_purge", actor="tester")
        result = await repo.verify_chain()
        assert result["valid"] is True
        assert result["verified_count"] == 3

    async def test_all_expired_clears(self, db_session):
        repo = AuditLogRepository(db_session)
        for i in range(2):
            await repo.record(action=f"a{i}", actor="t")
        from app.db.models import AuditLogModel
        from sqlalchemy import select

        rows = (await repo.session.execute(select(AuditLogModel))).scalars().all()
        for m in rows:
            m.ts = datetime.utcnow() - timedelta(days=500)
        await repo.session.commit()

        deleted = await repo.purge_before(datetime.utcnow() - timedelta(days=180))
        assert deleted == 2
        result = await repo.verify_chain()
        assert result["valid"] is True
        assert result["verified_count"] == 0

    async def test_nothing_expired_no_change(self, db_session):
        repo = AuditLogRepository(db_session)
        await repo.record(action="fresh", actor="t")
        deleted = await repo.purge_before(datetime.utcnow() - timedelta(days=180))
        assert deleted == 0
        assert (await repo.verify_chain())["valid"] is True


class TestSchedulerPurgeIntegration:
    @pytest.mark.asyncio
    async def test_purge_job_cleans_and_audits(self, monkeypatch):
        from app.agents import scheduler
        from app.core import config
        from app.db.database import async_session
        from app.db.repositories import AuditLogRepository

        # 保留期压到 1 天,造 2 条过期记录
        monkeypatch.setattr(config.settings, "audit_log_retention_days", 1)
        monkeypatch.setattr(config.settings, "enable_audit_retention_purge", True)

        async with async_session() as session:
            repo = AuditLogRepository(session)
            await repo.record(action="stale1", actor="t")
            await repo.record(action="stale2", actor="t")
            from app.db.models import AuditLogModel
            from sqlalchemy import select

            rows = (await session.execute(select(AuditLogModel))).scalars().all()
            for m in rows:
                assert m is not None
            # record 用 utcnow → 手动回改过期
            m = rows[0]
            m.ts = datetime.utcnow() - timedelta(days=30)
            await session.commit()

        await scheduler._purge_audited_logs()

        async with async_session() as session:
            repo = AuditLogRepository(session)
            logs = await repo.list_recent()
            # 1 条 stale 被删;清理动作本身写进审计 (audit_retention_purged)
            actions = [l["action"] for l in logs]
            assert "audit_retention_purged" in actions
            assert not any("stale1" in l["action"] for l in logs)
            assert (await repo.verify_chain())["valid"] is True

    @pytest.mark.asyncio
    async def test_purge_job_skip_when_disabled(self, monkeypatch):
        from app.core import config

        monkeypatch.setattr(config.settings, "audit_log_retention_days", 0)
        from app.agents import scheduler

        # 不应抛错,直接返回
        await scheduler._purge_audited_logs()