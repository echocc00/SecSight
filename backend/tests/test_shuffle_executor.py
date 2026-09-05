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

    def test_workflow_map_empty_when_unconfigured(self):
        """未配置任何环境变量时 map 为空 (execute 抛错触发降级)"""
        ex = ShuffleExecutor(base_url="http://s:3001", api_key="k")
        assert ex.workflow_map == {}

    def test_workflow_map_from_env_var(self, monkeypatch):
        """SHUFFLE_WORKFLOW_<ACTION> 环境变量加载"""
        monkeypatch.setenv("SHUFFLE_WORKFLOW_ISOLATE_HOST", "wf-abc-123")
        monkeypatch.setenv("SHUFFLE_WORKFLOW_BLOCK_IP", "wf-def-456")
        ex = ShuffleExecutor(base_url="http://s:3001", api_key="k")
        assert ex.workflow_map["isolate_host"] == "wf-abc-123"
        assert ex.workflow_map["block_ip"] == "wf-def-456"
        assert "kill_process" not in ex.workflow_map

    def test_workflow_map_from_json_setting(self, monkeypatch):
        """SHUFFLE_WORKFLOW_MAP JSON 批量配置"""
        from app.core.config import settings

        monkeypatch.setattr(
            settings,
            "shuffle_workflow_map",
            '{"kill_process": "wf-kill-1", "notify": "wf-notify-1"}',
        )
        ex = ShuffleExecutor(base_url="http://s:3001", api_key="k")
        assert ex.workflow_map["kill_process"] == "wf-kill-1"
        assert ex.workflow_map["notify"] == "wf-notify-1"

    def test_env_var_overrides_json(self, monkeypatch):
        """单动作环境变量优先于 JSON 映射"""
        from app.core.config import settings

        monkeypatch.setattr(
            settings, "shuffle_workflow_map", '{"block_ip": "from-json"}'
        )
        monkeypatch.setenv("SHUFFLE_WORKFLOW_BLOCK_IP", "from-env")
        ex = ShuffleExecutor(base_url="http://s:3001", api_key="k")
        assert ex.workflow_map["block_ip"] == "from-env"

    def test_invalid_json_map_does_not_crash(self, monkeypatch):
        from app.core.config import settings

        monkeypatch.setattr(settings, "shuffle_workflow_map", "{not valid json")
        ex = ShuffleExecutor(base_url="http://s:3001", api_key="k")
        assert ex.workflow_map == {}


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


class TestShuffleWrapperFallback:
    """包装层 (mock.py ShuffleExecutor) 故障降级到 mock"""

    @pytest.mark.asyncio
    async def test_falls_back_to_mock_when_no_workflow_mapped(self):
        from app.execution.mock import ShuffleExecutor
        from app.models.schemas import Action, ActionType, AutonomyLevel, Severity

        action = Action(
            action_type=ActionType.isolate_host,
            target={"ip": "10.0.1.15"},
            autonomy_level=AutonomyLevel.L2,
            risk=Severity.high,
        )
        executor = ShuffleExecutor()
        result = await executor.execute(action)
        # 无 workflow 映射 → 降级 mock
        assert result["success"] is True
        assert "fallback_reason" in result

    @pytest.mark.asyncio
    async def test_env_var_provides_workflow_mapping(self, monkeypatch):
        """SHUFFLE_WORKFLOW_<TYPE> 环境变量映射"""
        from app.execution.mock import ShuffleExecutor
        from app.models.schemas import Action, ActionType, AutonomyLevel, Severity

        monkeypatch.setenv("SHUFFLE_WORKFLOW_NOTIFY", "wf-notify-789")
        action = Action(
            action_type=ActionType.notify,
            target={"message": "test"},
            autonomy_level=AutonomyLevel.L4,
            risk=Severity.low,
        )
        executor = ShuffleExecutor()
        # 配置了 workflow 但 Shuffle 不可达 → 降级
        result = await executor.execute(action)
        assert result["success"] is True
