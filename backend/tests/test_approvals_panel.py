"""跨 Case 审批汇总 API — /api/approvals/pending"""
from __future__ import annotations

import pytest


async def _inject(client, alert_type: str = "data_exfiltration", hostname: str = "h1") -> str:
    resp = await client.post(
        "/api/alerts/inject", json={"alert_type": alert_type, "hostname": hostname}
    )
    assert resp.status_code == 200, resp.text
    return resp.json()["data"]["case_id"]


class TestPendingAggregation:
    async def test_empty_when_no_cases(self, client):
        resp = await client.get("/api/approvals/pending")
        assert resp.status_code == 200
        assert resp.json()["data"] == {"count": 0, "items": []}

    async def test_lists_l2_actions_across_cases(self, client):
        await _inject(client, hostname="agg-a")
        await _inject(client, hostname="agg-b")

        data = (await client.get("/api/approvals/pending")).json()["data"]
        assert data["count"] > 0
        case_ids = {item["case_id"] for item in data["items"]}
        assert len(case_ids) >= 2

    async def test_item_carries_case_context(self, client):
        """审批人要在列表里就能判断该不该批,不能只有 action_id"""
        case_id = await _inject(client, hostname="agg-ctx")
        items = (await client.get("/api/approvals/pending")).json()["data"]["items"]
        item = next(i for i in items if i["case_id"] == case_id)

        assert item["severity"]
        assert item["incident_summary"]
        assert item["action_type"]
        assert item["created_at"]
        assert item["required_roles"]
        assert item["missing_roles"]

    async def test_excludes_non_l2_actions(self, client):
        case_id = await _inject(client, hostname="agg-l2")
        case = (await client.get(f"/api/cases/{case_id}")).json()["data"]
        l2_ids = {
            a["action_id"] for a in case["proposed_actions"] if a["approval_required"]
        }
        non_l2 = {
            a["action_id"] for a in case["proposed_actions"] if not a["approval_required"]
        }

        items = (await client.get("/api/approvals/pending")).json()["data"]["items"]
        listed = {i["action_id"] for i in items if i["case_id"] == case_id}
        assert listed == l2_ids
        assert not (listed & non_l2)

    async def test_fully_approved_action_drops_off(self, client):
        case_id = await _inject(client, hostname="agg-done")
        items = (await client.get("/api/approvals/pending")).json()["data"]["items"]
        target = next(i for i in items if i["case_id"] == case_id)

        for role in target["required_roles"]:
            resp = await client.post(
                f"/api/approvals/{case_id}/actions/{target['action_id']}/approve",
                json={
                    "approver_role": role,
                    "approver_user": f"{role}-user",
                    "decision": "approved",
                },
            )
            assert resp.status_code == 200, resp.text

        after = (await client.get("/api/approvals/pending")).json()["data"]["items"]
        remaining = {
            i["action_id"] for i in after if i["case_id"] == case_id
        }
        assert target["action_id"] not in remaining

    async def test_partial_signature_still_listed_with_progress(self, client):
        case_id = await _inject(client, hostname="agg-partial")
        items = (await client.get("/api/approvals/pending")).json()["data"]["items"]
        target = next(i for i in items if i["case_id"] == case_id)
        first_role = target["required_roles"][0]

        await client.post(
            f"/api/approvals/{case_id}/actions/{target['action_id']}/approve",
            json={
                "approver_role": first_role,
                "approver_user": "u1",
                "decision": "approved",
            },
        )

        after = (await client.get("/api/approvals/pending")).json()["data"]["items"]
        updated = next(
            i
            for i in after
            if i["case_id"] == case_id and i["action_id"] == target["action_id"]
        )
        assert first_role in updated["approved_roles"]
        assert first_role not in updated["missing_roles"]

    async def test_rejected_action_stays_visible(self, client):
        """被拒的动作不能消失 —— 需要有人复核或改方案"""
        case_id = await _inject(client, hostname="agg-reject")
        items = (await client.get("/api/approvals/pending")).json()["data"]["items"]
        target = next(i for i in items if i["case_id"] == case_id)

        await client.post(
            f"/api/approvals/{case_id}/actions/{target['action_id']}/approve",
            json={
                "approver_role": target["required_roles"][0],
                "approver_user": "u1",
                "decision": "rejected",
                "comment": "误报",
            },
        )

        after = (await client.get("/api/approvals/pending")).json()["data"]["items"]
        updated = next(
            i
            for i in after
            if i["case_id"] == case_id and i["action_id"] == target["action_id"]
        )
        assert updated["rejected"] is True

    async def test_resolved_case_excluded(self, client):
        from app.db.database import async_session
        from app.db.repositories import CaseRepository

        case_id = await _inject(client, hostname="agg-resolved")
        async with async_session() as session:
            await CaseRepository(session).close(case_id, tttr_seconds=60)

        items = (await client.get("/api/approvals/pending")).json()["data"]["items"]
        assert all(i["case_id"] != case_id for i in items)

    async def test_critical_action_requires_three_roles(self, client):
        """高危动作 (isolate_host 等) 必须三签,列表要如实反映"""
        case_id = await _inject(client, hostname="agg-triple")
        items = (await client.get("/api/approvals/pending")).json()["data"]["items"]
        case_items = [i for i in items if i["case_id"] == case_id]

        from app.approvals.service import CRITICAL_ACTIONS

        critical = [i for i in case_items if i["action_type"] in CRITICAL_ACTIONS]
        assert critical, "该告警应生成至少一个高危动作"
        assert all(len(i["required_roles"]) == 3 for i in critical)

    async def test_case_specific_endpoint_still_works(self, client):
        """新增聚合路由不能把 /{case_id}/pending 抢掉"""
        case_id = await _inject(client, hostname="agg-route")
        resp = await client.get(f"/api/approvals/{case_id}/pending")
        assert resp.status_code == 200
        assert isinstance(resp.json()["data"], list)
