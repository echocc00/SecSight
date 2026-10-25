"""跨 Case 审批汇总 API — /api/approvals/pending

P0 鉴权修复后: 查询端点需 JWT (auth_client);签署身份来自 JWT / IM 回调
(conftest.sign_approval),请求体只含 {decision, comment}。
语义变更: 任一角色 rejected → Case 直接 resolved 并从待办列表消失
(终态案件不再吸收签名,防止已闭环案件被"复活")。
"""
from __future__ import annotations


from tests.conftest import approve_action_with_all_roles, sign_approval


async def _inject(client, alert_type: str = "data_exfiltration", hostname: str = "h1") -> str:
    resp = await client.post(
        "/api/alerts/inject", json={"alert_type": alert_type, "hostname": hostname}
    )
    assert resp.status_code == 200, resp.text
    return resp.json()["data"]["case_id"]


class TestPendingAggregation:
    async def test_empty_when_no_cases(self, auth_client):
        resp = await auth_client.get("/api/approvals/pending")
        assert resp.status_code == 200
        assert resp.json()["data"] == {"count": 0, "items": []}

    async def test_lists_l2_actions_across_cases(self, auth_client):
        await _inject(auth_client, hostname="agg-a")
        await _inject(auth_client, hostname="agg-b")

        data = (await auth_client.get("/api/approvals/pending")).json()["data"]
        assert data["count"] > 0
        case_ids = {item["case_id"] for item in data["items"]}
        assert len(case_ids) >= 2

    async def test_item_carries_case_context(self, auth_client):
        """审批人要在列表里就能判断该不该批,不能只有 action_id"""
        case_id = await _inject(auth_client, hostname="agg-ctx")
        items = (await auth_client.get("/api/approvals/pending")).json()["data"]["items"]
        item = next(i for i in items if i["case_id"] == case_id)

        assert item["severity"]
        assert item["incident_summary"]
        assert item["action_type"]
        assert item["created_at"]
        assert item["required_roles"]
        assert item["missing_roles"]

    async def test_excludes_non_l2_actions(self, auth_client):
        case_id = await _inject(auth_client, hostname="agg-l2")
        case = (await auth_client.get(f"/api/cases/{case_id}")).json()["data"]
        l2_ids = {
            a["action_id"] for a in case["proposed_actions"] if a["approval_required"]
        }
        non_l2 = {
            a["action_id"] for a in case["proposed_actions"] if not a["approval_required"]
        }

        items = (await auth_client.get("/api/approvals/pending")).json()["data"]["items"]
        listed = {i["action_id"] for i in items if i["case_id"] == case_id}
        assert listed == l2_ids
        assert not (listed & non_l2)

    async def test_fully_approved_action_drops_off(self, auth_client):
        case_id = await _inject(auth_client, hostname="agg-done")
        items = (await auth_client.get("/api/approvals/pending")).json()["data"]["items"]
        target = next(i for i in items if i["case_id"] == case_id)

        # 每个审批角色按其映射的签署路径签署 (身份来自 JWT / IM 回调)
        await approve_action_with_all_roles(
            auth_client, case_id, target["action_id"], target["required_roles"]
        )

        after = (await auth_client.get("/api/approvals/pending")).json()["data"]["items"]
        remaining = {
            i["action_id"] for i in after if i["case_id"] == case_id
        }
        assert target["action_id"] not in remaining

    async def test_partial_signature_still_listed_with_progress(self, auth_client):
        case_id = await _inject(auth_client, hostname="agg-partial")
        items = (await auth_client.get("/api/approvals/pending")).json()["data"]["items"]
        target = next(i for i in items if i["case_id"] == case_id)
        first_role = target["required_roles"][0]

        resp = await sign_approval(auth_client, case_id, target["action_id"], first_role)
        assert resp.status_code == 200, resp.text

        after = (await auth_client.get("/api/approvals/pending")).json()["data"]["items"]
        updated = next(
            i
            for i in after
            if i["case_id"] == case_id and i["action_id"] == target["action_id"]
        )
        assert first_role in updated["approved_roles"]
        assert first_role not in updated["missing_roles"]

    async def test_rejected_action_closes_case_and_drops_off(self, auth_client):
        """新语义 (P0): 任一角色 rejected → Case 直接 resolved (拒绝即终态)

        原断言"被拒动作留在待办列表"不再成立: 终态案件被待办聚合排除,
        防止已闭环案件被补签复活。拒绝结果改由审批记录与 Case 状态体现。
        """
        case_id = await _inject(auth_client, hostname="agg-reject")
        items = (await auth_client.get("/api/approvals/pending")).json()["data"]["items"]
        target = next(i for i in items if i["case_id"] == case_id)

        resp = await sign_approval(
            auth_client,
            case_id,
            target["action_id"],
            target["required_roles"][0],
            decision="rejected",
            comment="误报",
        )
        assert resp.status_code == 200, resp.text
        assert resp.json()["success"] is True

        # Case 进入 resolved 终态
        case = (await auth_client.get(f"/api/cases/{case_id}")).json()["data"]
        assert case["status"] == "resolved"

        # 待办列表不再展示 (终态案件排除),拒绝结果在审批记录中可追溯
        after = (await auth_client.get("/api/approvals/pending")).json()["data"]["items"]
        assert all(i["case_id"] != case_id for i in after)
        records = (await auth_client.get(f"/api/approvals/{case_id}/records")).json()["data"]
        assert any(r["decision"] == "rejected" for r in records)

    async def test_resolved_case_excluded(self, auth_client):
        from app.db.database import async_session
        from app.db.repositories import CaseRepository

        case_id = await _inject(auth_client, hostname="agg-resolved")
        async with async_session() as session:
            await CaseRepository(session).close(case_id, tttr_seconds=60)

        items = (await auth_client.get("/api/approvals/pending")).json()["data"]["items"]
        assert all(i["case_id"] != case_id for i in items)

    async def test_critical_action_requires_three_roles(self, auth_client):
        """高危动作 (isolate_host 等) 必须三签,列表要如实反映"""
        case_id = await _inject(auth_client, hostname="agg-triple")
        items = (await auth_client.get("/api/approvals/pending")).json()["data"]["items"]
        case_items = [i for i in items if i["case_id"] == case_id]

        from app.approvals.service import CRITICAL_ACTIONS

        critical = [i for i in case_items if i["action_type"] in CRITICAL_ACTIONS]
        assert critical, "该告警应生成至少一个高危动作"
        assert all(len(i["required_roles"]) == 3 for i in critical)

    async def test_case_specific_endpoint_still_works(self, auth_client):
        """新增聚合路由不能把 /{case_id}/pending 抢掉"""
        case_id = await _inject(auth_client, hostname="agg-route")
        resp = await auth_client.get(f"/api/approvals/{case_id}/pending")
        assert resp.status_code == 200
        assert isinstance(resp.json()["data"], list)
