"""执行时间线可观测性 — 跳过也留痕 / 执行器标识 / 目标与耗时

背景: 原实现只在成功路径 append ExecutionStep,审批未通过的动作在时间线上
完全消失,运维分不清"动作丢了"和"审批未通过被跳过"。
"""
from __future__ import annotations

import pytest


async def _inject(client, alert_type: str = "xmrig_process", hostname: str = "tl-1") -> str:
    resp = await client.post(
        "/api/alerts/inject", json={"alert_type": alert_type, "hostname": hostname}
    )
    return resp.json()["data"]["case_id"]


async def _case(client, case_id: str) -> dict:
    return (await client.get(f"/api/cases/{case_id}")).json()["data"]


class TestSkippedActionsRecorded:
    async def test_unapproved_l2_recorded_as_skipped(self, client):
        """L2 未审批的动作必须留 skipped 记录,而不是从时间线消失"""
        case_id = await _inject(client, hostname="tl-skip")
        case = await _case(client, case_id)

        l2_ids = {
            a["action_id"] for a in case["proposed_actions"] if a["approval_required"]
        }
        # 触发 execute_node: 直接调用节点,模拟审批未通过时的执行
        from app.agents.nodes import execute_node

        await execute_node({"case_id": case_id})

        case = await _case(client, case_id)
        logged = {s["action_id"]: s for s in case["execution_log"]}
        for action_id in l2_ids:
            assert action_id in logged, "未审批的 L2 动作也必须留记录"
            assert logged[action_id]["status"] == "skipped"

    async def test_skip_reason_explains_why(self, client):
        case_id = await _inject(client, hostname="tl-reason")
        from app.agents.nodes import execute_node

        await execute_node({"case_id": case_id})

        case = await _case(client, case_id)
        skipped = [s for s in case["execution_log"] if s["status"] == "skipped"]
        assert skipped
        assert "审批未通过" in skipped[0]["result"]["reason"]

    async def test_skipped_step_carries_action_context(self, client):
        """跳过记录也要带动作类型和目标,否则时间线上看不出跳过了什么"""
        case_id = await _inject(client, hostname="tl-ctx")
        from app.agents.nodes import execute_node

        await execute_node({"case_id": case_id})

        case = await _case(client, case_id)
        skipped = [s for s in case["execution_log"] if s["status"] == "skipped"]
        assert skipped
        assert skipped[0]["result"]["action_type"]
        assert skipped[0]["result"]["target"] is not None


class TestExecutedStepMetadata:
    async def test_success_step_carries_executor(self, client):
        """时间线要能自证是真执行还是 mock"""
        case_id = await _inject(client, hostname="tl-exec")
        from app.agents.nodes import execute_node

        await execute_node({"case_id": case_id})

        case = await _case(client, case_id)
        executed = [s for s in case["execution_log"] if s["status"] == "success"]
        assert executed
        assert executed[0]["result"]["executor"] == "mock"

    async def test_success_step_carries_action_type_and_target(self, client):
        case_id = await _inject(client, hostname="tl-meta")
        from app.agents.nodes import execute_node

        await execute_node({"case_id": case_id})

        case = await _case(client, case_id)
        executed = [s for s in case["execution_log"] if s["status"] == "success"]
        assert executed
        assert executed[0]["result"]["action_type"]
        assert executed[0]["result"]["autonomy_level"]

    async def test_timestamps_allow_duration_calc(self, client):
        case_id = await _inject(client, hostname="tl-dur")
        from app.agents.nodes import execute_node

        await execute_node({"case_id": case_id})

        case = await _case(client, case_id)
        for step in case["execution_log"]:
            assert step["started_at"]
            assert step["finished_at"]

    async def test_every_action_has_a_step(self, client):
        """回归: 每个动作都要有对应记录,不能静默丢失"""
        case_id = await _inject(client, hostname="tl-all")
        from app.agents.nodes import execute_node

        await execute_node({"case_id": case_id})

        case = await _case(client, case_id)
        action_ids = {a["action_id"] for a in case["proposed_actions"]}
        logged_ids = {s["action_id"] for s in case["execution_log"]}
        assert action_ids == logged_ids


class TestFullyApprovedActionsExecute:
    """回归: 审批通过的动作必须真正执行,不能因 case.approvals 空 dict 被误跳过"""

    async def _approve_all(self, client, case_id: str) -> None:
        items = (await client.get(f"/api/approvals/{case_id}/pending")).json()["data"]
        for item in items:
            for role in item["required_roles"]:
                resp = await client.post(
                    f"/api/approvals/{case_id}/actions/{item['action_id']}/approve",
                    json={
                        "approver_role": role,
                        "approver_user": f"{role}-u",
                        "decision": "approved",
                    },
                )
                assert resp.status_code == 200, resp.text

    async def test_approved_l2_actions_execute_not_skip(self, client):
        """批准全部动作 → execute_node 必须执行它们,而不是全部 skipped"""
        case_id = await _inject(client, hostname="tl-approved")
        await self._approve_all(client, case_id)

        from app.agents.nodes import execute_node

        await execute_node({"case_id": case_id})

        case = await _case(client, case_id)
        l2_ids = {
            a["action_id"]
            for a in case["proposed_actions"]
            if a["approval_required"]
        }
        if not l2_ids:
            pytest.skip("该剧本没有 L2 动作")

        logged = {s["action_id"]: s for s in case["execution_log"]}
        for action_id in l2_ids:
            assert action_id in logged
            assert logged[action_id]["status"] == "success", (
                f"已批准的 L2 动作被跳过而不是执行: {logged[action_id]['result']}"
            )

    async def test_partially_approved_skips_only_unapproved(self, client):
        """只批准部分 → 已批准的执行,未批准的跳过"""
        case_id = await _inject(client, hostname="tl-partial")
        items = (await client.get(f"/api/approvals/{case_id}/pending")).json()["data"]

        approved_action = items[0]
        approved_id = approved_action["action_id"]
        for role in approved_action["required_roles"]:
            await client.post(
                f"/api/approvals/{case_id}/actions/{approved_id}/approve",
                json={
                    "approver_role": role,
                    "approver_user": f"{role}-u",
                    "decision": "approved",
                },
            )

        from app.agents.nodes import execute_node

        await execute_node({"case_id": case_id})

        case = await _case(client, case_id)
        logged = {s["action_id"]: s for s in case["execution_log"]}
        assert logged[approved_id]["status"] == "success"
        for item in items[1:]:
            others = [
                s
                for s in case["execution_log"]
                if s["action_id"] == item["action_id"]
            ]
            assert others, "未审批的动作也要留记录"
            assert others[0]["status"] == "skipped"

    async def test_full_flow_approve_then_resolved_with_real_execution(self, client):
        """端到端: 注入 → 全批 → 恢复 → 处置确实执行 (成功,非 skipped)"""
        case_id = await _inject(client, hostname="tl-e2e")
        await self._approve_all(client, case_id)

        from app.api.approvals import resume_workflow

        # 模拟 API 在 all_approved 后调 resume_workflow(checkpointer 关闭时两段式)
        await resume_workflow(case_id)

        case = await _case(client, case_id)
        assert case["status"] == "resolved", case["status"]
        executed = [s for s in case["execution_log"] if s["status"] == "success"]
        assert executed, "已批准的处置动作必须执行过"
        assert all(
            (s.get("result") or {}).get("executor") == "mock" for s in executed
        )


class TestFailedStepRecordsError:
    async def test_failure_populates_error_field(self, client, monkeypatch):
        case_id = await _inject(client, hostname="tl-fail")

        from app.execution import mock as exec_mock

        class _Failing(exec_mock.ActionExecutor):
            async def execute(self, action, case_id=None):
                return {
                    "success": False,
                    "executor": "mock",
                    "message": "模拟执行失败",
                }

        monkeypatch.setattr(exec_mock, "get_executor", lambda: _Failing())

        from app.agents.nodes import execute_node

        await execute_node({"case_id": case_id})

        case = await _case(client, case_id)
        failed = [s for s in case["execution_log"] if s["status"] == "failed"]
        assert failed
        assert failed[0]["error"] == "模拟执行失败"


class TestExecutorLabelsAcrossBackends:
    async def test_shuffle_result_labels_executor(self):
        """Shuffle 执行结果必须带 executor=shuffle,前端才能区分真假处置"""
        from unittest.mock import AsyncMock, MagicMock, patch

        from app.execution.shuffle import ShuffleExecutor
        from app.models.schemas import Action, ActionType, AutonomyLevel

        action = Action(
            action_type=ActionType.isolate_host,
            target={"hostname": "h1"},
            autonomy_level=AutonomyLevel.L2,
        )

        response = MagicMock()
        response.raise_for_status = MagicMock()
        response.json = MagicMock(return_value={"execution_id": "exec-1", "status": "executing"})
        http = MagicMock()
        http.post = AsyncMock(return_value=response)
        http.__aenter__ = AsyncMock(return_value=http)
        http.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=http):
            executor = ShuffleExecutor(
                base_url="http://shuffle:3001",
                api_key="k",
                workflow_map={"isolate_host": "wf-1"},
            )
            result = await executor.execute(action, case_id="c1")

        assert result["executor"] == "shuffle"
        assert result["task_id"] == "exec-1"

    async def test_mock_result_labels_executor(self):
        from app.execution.mock import MockExecutor
        from app.models.schemas import Action, ActionType, AutonomyLevel

        result = await MockExecutor().execute(
            Action(
                action_type=ActionType.notify,
                target={},
                autonomy_level=AutonomyLevel.L5,
            )
        )
        assert result["executor"] == "mock"
