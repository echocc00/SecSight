"""审计日志 hash chain — 链式计算 / 篡改检测 / API / 报告集成"""
from __future__ import annotations

import pytest
import pytest_asyncio

from app.db.repositories import AuditLogRepository


@pytest_asyncio.fixture
async def audit_repo(db_session):
    return AuditLogRepository(db_session)


async def _seed(repo: AuditLogRepository, count: int = 3) -> None:
    for i in range(count):
        await repo.record(
            action=f"action_{i}", actor="tester", case_id="case-1", detail={"i": i}
        )


class TestChainConstruction:
    async def test_first_entry_has_genesis_prev_hash(self, audit_repo):
        await audit_repo.record(action="init", actor="system")
        logs = await audit_repo.list_recent()
        assert logs[0]["seq"] == 1
        assert logs[0]["prev_hash"] == "0" * 64

    async def test_seq_increments(self, audit_repo):
        await _seed(audit_repo, 3)
        logs = sorted(await audit_repo.list_recent(), key=lambda x: x["seq"])
        assert [log["seq"] for log in logs] == [1, 2, 3]

    async def test_each_entry_links_to_previous(self, audit_repo):
        await _seed(audit_repo, 3)
        logs = sorted(await audit_repo.list_recent(), key=lambda x: x["seq"])
        for prev, cur in zip(logs, logs[1:]):
            assert cur["prev_hash"] == prev["entry_hash"]

    async def test_entry_hash_is_sha256_hex(self, audit_repo):
        await audit_repo.record(action="init", actor="system")
        logs = await audit_repo.list_recent()
        assert len(logs[0]["entry_hash"]) == 64
        int(logs[0]["entry_hash"], 16)  # 必须是合法十六进制

    async def test_identical_content_different_seq_yields_different_hash(self, audit_repo):
        """同内容不同位置必须不同哈希,否则可整段替换而不断链"""
        await audit_repo.record(action="same", actor="a", detail={"x": 1})
        await audit_repo.record(action="same", actor="a", detail={"x": 1})
        logs = sorted(await audit_repo.list_recent(), key=lambda x: x["seq"])
        assert logs[0]["entry_hash"] != logs[1]["entry_hash"]


class TestVerifyChain:
    async def test_empty_chain_valid(self, audit_repo):
        result = await audit_repo.verify_chain()
        assert result["valid"] is True
        assert result["verified_count"] == 0

    async def test_intact_chain_valid(self, audit_repo):
        await _seed(audit_repo, 5)
        result = await audit_repo.verify_chain()
        assert result["valid"] is True
        assert result["verified_count"] == 5
        assert len(result["chain_head"]) == 64

    async def test_detects_tampered_detail(self, db_session, audit_repo):
        """改内容不改 hash → entry_hash 重算不匹配"""
        from app.db.models import AuditLogModel

        await _seed(audit_repo, 3)
        target = await db_session.get(AuditLogModel, 2)
        target.detail = {"i": 999}
        await db_session.commit()

        result = await audit_repo.verify_chain()
        assert result["valid"] is False
        assert result["broken_at_seq"] == 2
        assert "entry_hash" in result["reason"]

    async def test_detects_tampered_actor(self, db_session, audit_repo):
        from app.db.models import AuditLogModel

        await _seed(audit_repo, 3)
        target = await db_session.get(AuditLogModel, 1)
        target.actor = "attacker"
        await db_session.commit()

        result = await audit_repo.verify_chain()
        assert result["valid"] is False
        assert result["broken_at_seq"] == 1

    async def test_detects_deleted_entry(self, db_session, audit_repo):
        """删记录 → seq 不连续"""
        from app.db.models import AuditLogModel

        await _seed(audit_repo, 4)
        target = await db_session.get(AuditLogModel, 2)
        await db_session.delete(target)
        await db_session.commit()

        result = await audit_repo.verify_chain()
        assert result["valid"] is False
        assert result["broken_at_seq"] == 3
        assert "seq" in result["reason"]

    async def test_detects_broken_prev_hash(self, db_session, audit_repo):
        from app.db.models import AuditLogModel

        await _seed(audit_repo, 3)
        target = await db_session.get(AuditLogModel, 3)
        target.prev_hash = "f" * 64
        await db_session.commit()

        result = await audit_repo.verify_chain()
        assert result["valid"] is False
        assert result["broken_at_seq"] == 3
        assert "prev_hash" in result["reason"]

    async def test_reports_verified_count_before_break(self, db_session, audit_repo):
        from app.db.models import AuditLogModel

        await _seed(audit_repo, 5)
        target = await db_session.get(AuditLogModel, 4)
        target.detail = {"tampered": True}
        await db_session.commit()

        result = await audit_repo.verify_chain()
        assert result["verified_count"] == 3


class TestAuditAPI:
    async def _token(self, client) -> str:
        from app.db.database import async_session
        from app.db.repositories import UserRepository

        async with async_session() as session:
            await UserRepository(session).seed_defaults()
        resp = await client.post(
            "/api/auth/login", json={"username": "admin", "password": "ChangeMe_123!"}
        )
        return resp.json()["access_token"]

    async def test_verify_requires_auth(self, client):
        resp = await client.get("/api/audit/verify")
        assert resp.status_code == 401

    async def test_verify_returns_valid_for_intact_chain(self, client):
        token = await self._token(client)
        resp = await client.get(
            "/api/audit/verify", headers={"Authorization": f"Bearer {token}"}
        )
        assert resp.status_code == 200
        assert resp.json()["data"]["valid"] is True

    async def test_verify_detects_tampering_through_api(self, client):
        from app.db.database import async_session
        from app.db.models import AuditLogModel

        token = await self._token(client)
        async with async_session() as session:
            repo = AuditLogRepository(session)
            await _seed(repo, 3)
            target = await session.get(AuditLogModel, 2)
            target.action = "forged"
            await session.commit()

        resp = await client.get(
            "/api/audit/verify", headers={"Authorization": f"Bearer {token}"}
        )
        data = resp.json()["data"]
        assert data["valid"] is False
        assert data["broken_at_seq"] == 2

    async def test_list_logs_includes_hash_fields(self, client):
        from app.db.database import async_session

        token = await self._token(client)
        async with async_session() as session:
            await _seed(AuditLogRepository(session), 2)

        resp = await client.get(
            "/api/audit", headers={"Authorization": f"Bearer {token}"}
        )
        logs = resp.json()["data"]
        assert logs
        assert "entry_hash" in logs[0]
        assert "prev_hash" in logs[0]
        assert "seq" in logs[0]

    async def test_list_logs_filtered_by_case(self, client):
        from app.db.database import async_session

        token = await self._token(client)
        async with async_session() as session:
            repo = AuditLogRepository(session)
            await repo.record(action="a", actor="t", case_id="case-A")
            await repo.record(action="b", actor="t", case_id="case-B")

        resp = await client.get(
            "/api/audit",
            params={"case_id": "case-A"},
            headers={"Authorization": f"Bearer {token}"},
        )
        logs = resp.json()["data"]
        assert all(log["case_id"] == "case-A" for log in logs)


class TestComplianceReportChain:
    async def test_report_embeds_chain_verification(self, client):
        """合规报告必须自证留痕未被篡改"""
        inject = await client.post(
            "/api/alerts/inject",
            json={"alert_type": "xmrig_process", "hostname": "audit-h1"},
        )
        case_id = inject.json()["data"]["case_id"]

        resp = await client.get(f"/api/compliance/{case_id}/report")
        assert resp.status_code == 200
        assert "审计链完整性校验" in resp.text
        assert "hash chain 校验通过" in resp.text

    async def test_markdown_report_embeds_chain(self, client):
        inject = await client.post(
            "/api/alerts/inject",
            json={"alert_type": "xmrig_process", "hostname": "audit-h2"},
        )
        case_id = inject.json()["data"]["case_id"]

        resp = await client.get(f"/api/compliance/{case_id}/report.md")
        assert "审计链完整性校验" in resp.text

    async def test_report_flags_tampering(self, client):
        from app.db.database import async_session
        from app.db.models import AuditLogModel

        inject = await client.post(
            "/api/alerts/inject",
            json={"alert_type": "xmrig_process", "hostname": "audit-h3"},
        )
        case_id = inject.json()["data"]["case_id"]

        async with async_session() as session:
            target = await session.get(AuditLogModel, 1)
            assert target is not None, "编排应已写入审计记录"
            target.actor = "attacker"
            await session.commit()

        resp = await client.get(f"/api/compliance/{case_id}/report")
        assert "审计链校验失败" in resp.text
