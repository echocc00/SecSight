"""动作构建 + workflow 路由测试"""
from __future__ import annotations

import pytest

from app.agents.nodes import _infer_action_type, build_action_from_config
from app.agents.workflow import route_after_plan
from app.models.schemas import ActionType, AutonomyLevel
from app.playbooks.models import ContainmentActionConfig


class TestInferActionType:
    def test_explicit_action_type_wins(self):
        assert _infer_action_type("A1_anything", "isolate_host") == ActionType.isolate_host

    def test_infers_from_id_when_no_explicit(self):
        assert _infer_action_type("A2_kill_process") == ActionType.kill_process

    def test_infers_block_domain(self):
        assert _infer_action_type("A6_block_mining_pools", "block_domain") == ActionType.block_domain

    def test_falls_back_to_notify_for_unknown(self):
        assert _infer_action_type("A9_mystery_action") == ActionType.notify

    def test_invalid_explicit_falls_back_to_inference(self):
        assert _infer_action_type("A1_isolate_host", "not_a_real_type") == ActionType.isolate_host


class TestBuildActionFromConfig:
    def test_l2_action_requires_approval(self):
        cfg = ContainmentActionConfig(
            id="A1_isolate_host",
            name="隔离",
            action_type="isolate_host",
            autonomy="L2",
            approval="double",
        )
        action = build_action_from_config(cfg, "pb_test")
        assert action.autonomy_level == AutonomyLevel.L2
        assert action.approval_required is True
        assert action.requires_double_sign is True

    def test_l4_action_does_not_require_approval(self):
        cfg = ContainmentActionConfig(
            id="A5_lateral_scan",
            name="横向扫描",
            action_type="query_asset",
            autonomy="L4",
            approval="sampling",
        )
        action = build_action_from_config(cfg, "pb_test")
        assert action.autonomy_level == AutonomyLevel.L4
        assert action.approval_required is False

    def test_action_carries_playbook_id(self):
        cfg = ContainmentActionConfig(id="A1_isolate_host", name="x", action_type="isolate_host", autonomy="L2")
        action = build_action_from_config(cfg, "pb_cryptominer_v1")
        assert action.playbook_id == "pb_cryptominer_v1"


class TestRouteAfterPlan:
    def test_routes_to_human_approve_when_l2_present(self):
        state = {"proposed_actions": [{"autonomy_level": "L2"}, {"autonomy_level": "L4"}]}
        assert route_after_plan(state) == "human_approve"

    def test_routes_to_execute_when_no_l2(self):
        state = {"proposed_actions": [{"autonomy_level": "L3"}, {"autonomy_level": "L4"}, {"autonomy_level": "L5"}]}
        assert route_after_plan(state) == "execute"

    def test_routes_to_execute_when_no_actions(self):
        state = {"proposed_actions": []}
        assert route_after_plan(state) == "execute"
