"""Shuffle 异步执行闭环 — 轮询判定 / executing 不假成功 / 终态回写

真实 Shuffle execute 是异步: 返回 executing/queued 表示已触发仍在跑。
测试核心保证: 时间线如实反映 executing→success/failed,而不是把"已触发"
当"已成功"。
"""
from __future__ import annotations

from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.execution.shuffle import ShuffleExecutor


def _shuffle_response(status: str) -> MagicMock:
    resp = MagicMock()
    resp.raise_for_status = MagicMock()
    resp.json = MagicMock(return_value={"status": status, "id": "exec-1"})
    http = MagicMock()
    http.post = AsyncMock(return_value=resp)
    http.__aenter__ = AsyncMock(return_value=http)
    http.__aexit__ = AsyncMock(return_value=False)
    return http


async def _executor_with_status(*statuses: str) -> ShuffleExecutor:
    """模拟 Shuffle get_execution_status 逐个返回状态"""
    calls = 0

    async def _get(url, **kwargs):
        nonlocal calls
        idx = min(calls, len(statuses) - 1)
        calls += 1
        return _status_resp(statuses[idx])

    http = MagicMock()
    http.get = _get
    http.__aenter__ = AsyncMock(return_value=http)
    http.__aexit__ = AsyncMock(return_value=False)
    with patch("httpx.AsyncClient", return_value=http):
        executor = ShuffleExecutor(base_url="http://shuffle:3001", api_key="k", workflow_map={})
        executor.get_execution_status = None  # 直接用 client mock 走 poll_to_terminal 内部
        # poll_to_terminal 内部调用 self.get_execution_status,手动替换
        executor.get_execution_status = AsyncMock(side_effect=[_s(s) for s in statuses])
    return executor


def _s(status: str) -> dict:
    return {"status": status, "execution_id": "exec-1"}


@pytest.mark.asyncio
class TestPollToTerminal:
    async def test_success_terminals(self):
        ex = ShuffleExecutor(base_url="http://x", api_key="k")
        ex.get_execution_status = AsyncMock(return_value={"status": "success"})
        out = await ex.poll_to_terminal("e1", attempts=2, interval_seconds=0)
        assert out["status"] == "success"
        assert out["success"] is True

    async def test_failed_terminals(self):
        ex = ShuffleExecutor(base_url="http://x", api_key="k")
        ex.get_execution_status = AsyncMock(return_value={"status": "failure"})
        out = await ex.poll_to_terminal("e1", attempts=2, interval_seconds=0)
        assert out["status"] == "failed"
        assert out["success"] is False

    async def test_error_terminals(self):
        ex = ShuffleExecutor(base_url="http://x", api_key="k")
        ex.get_execution_status = AsyncMock(return_value={"status": "error"})
        out = await ex.poll_to_terminal("e1", attempts=2, interval_seconds=0)
        assert out["status"] == "failed"

    async def test_transient_then_success(self):
        ex = ShuffleExecutor(base_url="http://x", api_key="k")
        ex.get_execution_status = AsyncMock(
            side_effect=[{"status": "queued"}, {"status": "success"}]
        )
        out = await ex.poll_to_terminal("e1", attempts=3, interval_seconds=0)
        assert out["status"] == "success"

    async def test_timeout_keeps_executing(self):
        """轮询耗尽仍无终态 → 保持 executing,绝不假 success"""
        ex = ShuffleExecutor(base_url="http://x", api_key="k")
        ex.get_execution_status = AsyncMock(return_value={"status": "executing"})
        out = await ex.poll_to_terminal("e1", attempts=2, interval_seconds=0)
        assert out["status"] == "executing"
        assert out["success"] is None

    async def test_query_failure_then_success(self):
        ex = ShuffleExecutor(base_url="http://x", api_key="k")
        from app.execution.shuffle import ShuffleError

        ex.get_execution_status = AsyncMock(
            side_effect=[ShuffleError("down"), {"status": "success"}]
        )
        out = await ex.poll_to_terminal("e1", attempts=3, interval_seconds=0)
        assert out["status"] == "success"


class TestExecuteNodeShuffle:
    @pytest.mark.asyncio
    async def test_executing_not_marked_success(self, client, monkeypatch):
        """异步 Shuffle 触发后 step 应标 executing,不是成功"""
        from app.agents import nodes
        from app.execution import mock as exec_mock
        from app.models.schemas import Action, ActionType, AutonomyLevel

        class _AsyncShuffle(exec_mock.ActionExecutor):
            async def execute(self, action, case_id=None):
                return {
                    "success": True,
                    "executor": "shuffle",
                    "task_id": "exec-1",
                    "message": "Shuffle workflow wf-1 triggered",
                    "shuffle_response": {"status": "executing", "id": "exec-1"},
                    "shuffle_execution_id": "exec-1",
                }

        # 轮询后台任务替换为 no-op,避免测试里真连 Shuffle
        async def _noop(case_id, action_id, execution_id):
            pass

        monkeypatch.setattr(exec_mock, "get_executor", lambda: _AsyncShuffle())
        monkeypatch.setattr(nodes, "_poll_shuffle_to_terminal", _noop)

        resp = await client.post(
            "/api/alerts/inject",
            json={"alert_type": "xmrig_process", "hostname": "sh-exec", "src_ip": "45.33.32.156"},
        )
        case_id = resp.json()["data"]["case_id"]
        pending = (await client.get(f"/api/approvals/{case_id}/pending")).json()["data"]
        for item in pending:
            for role in item["required_roles"]:
                await client.post(
                    f"/api/approvals/{case_id}/actions/{item['action_id']}/approve",
                    json={"approver_role": role, "approver_user": f"{role}-u", "decision": "approved"},
                )

        from app.agents.nodes import execute_node

        await execute_node({"case_id": case_id})

        case = (await client.get(f"/api/cases/{case_id}")).json()["data"]
        executed = [
            s
            for s in case["execution_log"]
            if (s.get("result") or {}).get("executor") == "shuffle"
        ]
        assert executed, "应有 shuffle 执行记录"
        # 异步触发 → 不假成成功
        assert all(s["status"] == "executing" for s in executed), [
            (s["status"], s.get("result")) for s in executed
        ]

    @pytest.mark.asyncio
    async def test_terminal_triggered_marked_success(self, client, monkeypatch):
        """Shuffle 返回 status=success (同步判断终态) → 直接 success"""
        from app.execution import mock as exec_mock

        class _DoneShuffle(exec_mock.ActionExecutor):
            async def execute(self, action, case_id=None):
                return {
                    "success": True,
                    "executor": "shuffle",
                    "task_id": "exec-2",
                    "message": "done",
                    "shuffle_response": {"status": "success", "id": "exec-2"},
                }

        monkeypatch.setattr(exec_mock, "get_executor", lambda: _DoneShuffle())
        from app.agents import nodes
        from app.agents.nodes import execute_node

        async def _noop(*a):
            pass

        monkeypatch.setattr(nodes, "_poll_shuffle_to_terminal", _noop)

        resp = await client.post(
            "/api/alerts/inject",
            json={"alert_type": "xmrig_process", "hostname": "sh-done", "src_ip": "45.33.32.156"},
        )
        case_id = resp.json()["data"]["case_id"]
        pending = (await client.get(f"/api/approvals/{case_id}/pending")).json()["data"]
        for item in pending:
            for role in item["required_roles"]:
                await client.post(
                    f"/api/approvals/{case_id}/actions/{item['action_id']}/approve",
                    json={"approver_role": role, "approver_user": f"{role}-u", "decision": "approved"},
                )

        await execute_node({"case_id": case_id})
        case = (await client.get(f"/api/cases/{case_id}")).json()["data"]
        shuffle_steps = [
            s for s in case["execution_log"] if (s.get("result") or {}).get("executor") == "shuffle"
        ]
        assert any(s["status"] == "success" for s in shuffle_steps)


class TestUpdateExecutionStatus:
    @pytest.mark.asyncio
    async def test_writes_terminal_status_back(self, client):
        """后台轮询终态回写: 原 executing step 更新为 success + 保留执行信息"""
        resp = await client.post(
            "/api/alerts/inject",
            json={"alert_type": "xmrig_process", "hostname": "sh-repo", "src_ip": "45.33.32.156"},
        )
        case_id = resp.json()["data"]["case_id"]

        from app.db.database import async_session
        from app.db.repositories import CaseRepository
        from app.models.schemas import Action, ExecutionStep

        # 构造一条"已触发,Shuffle 执行中"的 step,模拟异步执行完成后回写
        async with async_session() as session:
            repo = CaseRepository(session)
            case = await repo.get(case_id)
            action_id = case.proposed_actions[0].action_id
            await repo.append_execution(
                case_id,
                ExecutionStep(
                    action_id=action_id,
                    status="executing",
                    started_at=datetime.utcnow(),
                    result={
                        "executor": "shuffle",
                        "task_id": "exec-repo",
                        "action_type": case.proposed_actions[0].action_type.value,
                        "target": case.proposed_actions[0].target,
                    },
                ),
            )

            await repo.update_execution_status(
                case_id,
                action_id,
                "success",
                {"executor": "shuffle", "task_id": "exec-repo", "execute_status": "success"},
            )

            case = await repo.get(case_id)
            updated = next(s for s in case.execution_log if s.action_id == action_id and s.result.get("executor") == "shuffle")
            assert updated.status == "success"
            assert updated.finished_at is not None
            assert updated.result.get("execute_status") == "success"
            assert updated.result.get("action_type")  # 保留原动作信息
            assert updated.result.get("target")