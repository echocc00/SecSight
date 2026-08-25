"""workflow.py 纯逻辑测试: route_after_plan + route_approval + checkpointer 开关"""
from __future__ import annotations

from unittest.mock import patch

import pytest


class TestRouteAfterPlan:
    def test_routes_to_human_approve_when_l2_present(self):
        from app.agents.workflow import route_after_plan

        state = {"proposed_actions": [{"autonomy_level": "L2"}]}
        assert route_after_plan(state) == "human_approve"

    def test_routes_to_execute_when_no_l2(self):
        from app.agents.workflow import route_after_plan

        state = {"proposed_actions": [{"autonomy_level": "L3"}]}
        assert route_after_plan(state) == "execute"

    def test_routes_to_execute_when_empty_actions(self):
        from app.agents.workflow import route_after_plan

        state = {"proposed_actions": []}
        assert route_after_plan(state) == "execute"


class TestRouteApproval:
    def test_routes_to_execute_when_all_approved(self):
        from app.agents.workflow import route_approval

        state = {"approval_status": {"a1": "approved", "a2": "approved"}}
        assert route_approval(state) == "execute"

    def test_routes_to_escalate_when_rejected(self):
        from app.agents.workflow import route_approval

        state = {"approval_status": {"a1": "approved", "a2": "rejected"}}
        assert route_approval(state) == "escalate"

    def test_routes_to_escalate_when_pending(self):
        from app.agents.workflow import route_approval

        state = {"approval_status": {"a1": "approved", "a2": "pending"}}
        assert route_approval(state) == "escalate"

    def test_routes_to_execute_when_empty_approvals(self):
        from app.agents.workflow import route_approval

        state = {"approval_status": {}}
        assert route_approval(state) == "execute"


class TestCheckpointerToggle:
    def test_checkpointer_disabled_on_sqlite(self):
        from app.agents.workflow import _is_checkpointer_enabled

        with patch("app.core.config.settings") as s:
            s.enable_checkpointer = False
            s.database_url = "sqlite+aiosqlite:///test.db"
            assert _is_checkpointer_enabled() is False

    def test_checkpointer_enabled_on_postgres(self):
        from app.agents.workflow import _is_checkpointer_enabled

        with patch("app.core.config.settings") as s:
            s.enable_checkpointer = True
            s.database_url = "postgresql+asyncpg://u:p@host/db"
            assert _is_checkpointer_enabled() is True

    def test_checkpointer_disabled_even_on_postgres_if_flag_off(self):
        from app.agents.workflow import _is_checkpointer_enabled

        with patch("app.core.config.settings") as s:
            s.enable_checkpointer = False
            s.database_url = "postgresql+asyncpg://u:p@host/db"
            assert _is_checkpointer_enabled() is False
