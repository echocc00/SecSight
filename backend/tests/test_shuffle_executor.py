"""Shuffle executor 测试 — REST 调用 + 降级 + 工厂"""
from __future__ import annotations

import json
from unittest.mock import patch

import httpx
import pytest

from app.execution.mock import MockExecutor, get_executor
from app.execution.shuffle import ShuffleError, ShuffleExecutor
from app.models.schemas import Action, ActionType, AutonomyLevel, Severity


def _action(action_type: ActionType = ActionType.isolate_host) -> Action:
    return Action(
        action_type=action_type,
        target={"ip": "10.0.1.15"},
        autonomy_level=AutonomyLevel.L2,
        risk=Severity.high,
    )


def _patch_transport(handler) -> patch:
    """patch httpx.AsyncClient 注入 MockTransport"""
    real = httpx.AsyncClient

    def factory(**kw):
        return real(transport=httpx.MockTransport(handler), **kw)

    return patch("app.execution.shuffle.httpx.AsyncClient", factory)


class TestShuffleExecutorInit:
    def test_raises_without_base_url(self):
        with pytest.raises(ShuffleError, match="base_url"):
            ShuffleExecutor(base_url="", api_key="")

    def test_default_workflow_map(self):
        ex = ShuffleExecutor(base_url="http://s:3001", api_key="k")
        assert "isolate_host" in ex.workflow_map


class TestShuffleExecute:
    @pytest.mark.asyncio
    async def test_raises_when_workflow_id_not_configured(self):
        ex = ShuffleExecutor(base_url="http://s:3001", api_key="k")
        with pytest.raises(ShuffleError, match="未配置"):
            await ex.execute(_action())

    @pytest.mark.asyncio
    async def test_successful_execution_returns_task_id(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200, json={"execution_id": "exec-123", "status": "executing"}
            )

        ex = ShuffleExecutor(
            base_url="http://s:3001",
            api_key="k",
            workflow_map={"isolate_host": "wf-abc"},
        )
        with _patch_transport(handler):
            result = await ex.execute(_action())
        assert result["success"] is True
        assert result["task_id"] == "exec-123"
        assert "wf-abc" in result["message"]

    @pytest.mark.asyncio
    async def test_http_error_raises_shuffle_error(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(500, text="internal error")

        ex = ShuffleExecutor(
            base_url="http://s:3001", api_key="k", workflow_map={"isolate_host": "wf"}
        )
        with _patch_transport(handler):
            with pytest.raises(ShuffleError, match="调用失败"):
                await ex.execute(_action())

    @pytest.mark.asyncio
    async def test_connection_error_raises_shuffle_error(self):
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("connection refused")

        ex = ShuffleExecutor(
            base_url="http://s:3001", api_key="k", workflow_map={"isolate_host": "wf"}
        )
        with _patch_transport(handler):
            with pytest.raises(ShuffleError, match="调用失败"):
                await ex.execute(_action())

    @pytest.mark.asyncio
    async def test_sends_authorization_header(self):
        captured: dict = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["auth"] = request.headers.get("authorization")
            return httpx.Response(200, json={"execution_id": "x", "status": "success"})

        ex = ShuffleExecutor(
            base_url="http://s:3001",
            api_key="secret-key",
            workflow_map={"isolate_host": "wf"},
        )
        with _patch_transport(handler):
            await ex.execute(_action())
        assert captured["auth"] == "Bearer secret-key"

    @pytest.mark.asyncio
    async def test_execution_argument_contains_action_details(self):
        captured: dict = {}

        def handler(request: httpx.Request) -> httpx.Response:
            body = json.loads(request.content)
            arg = json.loads(body["execution_argument"])
            captured["action_type"] = arg["action_type"]
            captured["target"] = arg["target"]
            return httpx.Response(200, json={"execution_id": "x"})

        ex = ShuffleExecutor(
            base_url="http://s:3001", api_key="k", workflow_map={"isolate_host": "wf"}
        )
        with _patch_transport(handler):
            await ex.execute(_action(ActionType.isolate_host))
        assert captured["action_type"] == "isolate_host"
        assert captured["target"] == {"ip": "10.0.1.15"}


class TestGetExecutorFactory:
    def test_returns_mock_in_mock_mode(self):
        assert isinstance(get_executor(), MockExecutor)

    def test_returns_shuffle_when_enabled(self, monkeypatch):
        from app.core import config as cfg

        monkeypatch.setattr(cfg.settings, "mock_mode", False)
        monkeypatch.setattr(cfg.settings, "enable_shuffle", True)
        from app.execution.mock import ShuffleExecutor

        assert isinstance(get_executor(), ShuffleExecutor)
