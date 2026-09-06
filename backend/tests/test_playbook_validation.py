"""L2 动作双签保证 — 缺字段不静默退化 + 启动校验

背景: approval_required 由 autonomy==L2 派生(审批不会漏);但
requires_double_sign 依赖 YAML 显式 approval: double,漏写会退化成单签。
修复: critical 高危动作无论 YAML 都强制三签;启动 validate_playbooks 列出隐患。
"""
from __future__ import annotations

import pytest

from app.agents.nodes import build_action_from_config
from app.models.schemas import ActionType, AutonomyLevel
from app.playbooks.loader import validate_playbooks
from app.playbooks.models import ContainmentActionConfig, Playbook


def _cfg(
    action_id: str,
    action_type: str,
    autonomy: str = "L2",
    approval: str | None = None,
) -> ContainmentActionConfig:
    kwargs = {"autonomy": autonomy}
    if approval is not None:
        kwargs["approval"] = approval
    return ContainmentActionConfig(
        id=action_id, name=action_id, action_type=action_type, **kwargs
    )


class TestCriticalActionTripleSignEnforced:
    """高危 L2 动作必须三签,即使 YAML 漏写 approval: double"""

    def test_isolate_host_missing_approval_still_double_sign(self):
        action = build_action_from_config(
            _cfg("A1_isolate_host", "isolate_host"), "pb_test"
        )
        assert action.approval_required is True
        assert action.requires_double_sign is True

    def test_block_ip_missing_approval_still_double_sign(self):
        action = build_action_from_config(
            _cfg("A1_block_ip", "block_ip"), "pb_test"
        )
        assert action.requires_double_sign is True

    def test_block_domain_missing_approval_still_double_sign(self):
        action = build_action_from_config(
            _cfg("A2_block_domain", "block_domain"), "pb_test"
        )
        assert action.requires_double_sign is True

    def test_freeze_account_missing_approval_still_double_sign(self):
        action = build_action_from_config(
            _cfg("A_X_freeze_account", "freeze_account"), "pb_test"
        )
        assert action.requires_double_sign is True

    def test_explicit_none_still_forced_double(self):
        """就算 YAML 明写 approval: none,critical 也不能落后门"""
        action = build_action_from_config(
            _cfg("A1_isolate_host", "isolate_host", approval="none"), "pb_test"
        )
        assert action.requires_double_sign is True

    def test_explicit_single_becomes_double(self):
        action = build_action_from_config(
            _cfg("A1_isolate_host", "isolate_host", approval="single"), "pb_test"
        )
        assert action.requires_double_sign is True


class TestNonCriticalL2:
    def test_l2_without_approval_is_single_sign(self):
        """非高危 L2 (kill_process/quarantine) 缺审批声明 = 单签,但启动会警告"""
        action = build_action_from_config(
            _cfg("A_kill_process_pid", "kill_process"), "pb_test"
        )
        assert action.approval_required is True
        assert action.requires_double_sign is False

    def test_l2_with_double_stays_double(self):
        action = build_action_from_config(
            _cfg("A_kill_process_pid", "kill_process", approval="double"), "pb_test"
        )
        assert action.requires_double_sign is True

    def test_l3_never_requires_approval(self):
        action = build_action_from_config(
            _cfg("I1", "notify", autonomy="L5", approval=None), "pb_test"
        )
        assert action.approval_required is False


def _pb(pb_id: str, actions: list[ContainmentActionConfig]) -> Playbook:
    return Playbook(
        id=pb_id,
        name=pb_id,
        category="test",
        containment_actions=actions,
    )


class TestValidatePlaybooks:
    def test_flags_l2_without_approval(self):
        warnings = validate_playbooks(
            [_pb("pb_a", [_cfg("A1_isolate_host", "isolate_host")])]
        )
        assert any("未声明 approval" in w for w in warnings)

    def test_flags_critical_with_single_approval(self):
        warnings = validate_playbooks(
            [_pb("pb_b", [_cfg("A1_isolate_host", "isolate_host", approval="single")])]
        )
        assert any("应显式 double" in w for w in warnings)

    def test_clean_when_double_declared(self):
        warnings = validate_playbooks(
            [
                _pb(
                    "pb_c",
                    [
                        _cfg("A1_isolate_host", "isolate_host", approval="double"),
                        _cfg("A2_kill", "kill_process", approval="double"),
                    ],
                )
            ]
        )
        assert warnings == []

    def test_l1_no_warning(self):
        """非 L2 动作不参与校验"""
        warnings = validate_playbooks(
            [_pb("pb_d", [_cfg("I1", "notify", autonomy="L4")])]
        )
        assert warnings == []


class TestRealPlaybooksCompliance:
    def test_all_shipped_playbooks_l2_critical_are_double(self):
        """真实交付的 12 个剧本: 高危 L2 动作源 YAML 已显式 double (无遗漏)"""
        from app.playbooks.loader import load_all

        import os

        playbooks = load_all(os.environ.get("PLAYBOOKS_DIR", "./playbooks"))
        assert playbooks, "测试环境必须加载到剧本"

        warnings = validate_playbooks(playbooks)
        critical_missing = [w for w in warnings if "应显式 double" in w]
        unannotated_l2 = [w for w in warnings if "未声明 approval" in w]

        # 交付剧本已规范: 不存在 critical 高危漏标 double
        assert critical_missing == [], critical_missing
        # 允许非 critical 的 L2 单签,但也要逐个声明 —— 只接受已声明的
        assert unannotated_l2 == [], unannotated_l2

    def test_built_actions_from_real_playbooks_all_critical_triple(self):
        """构建产物层面: 所有真实剧本的高危 L2 动作都三签"""
        from app.playbooks.loader import load_all
        from app.approvals.service import CRITICAL_ACTIONS

        import os

        playbooks = load_all(os.environ.get("PLAYBOOKS_DIR", "./playbooks"))
        for pb in playbooks:
            for cfg in pb.containment_actions:
                if cfg.action_type not in CRITICAL_ACTIONS or cfg.autonomy != "L2":
                    continue
                action = build_action_from_config(cfg, pb.id)
                assert action.requires_double_sign is True, (
                    f"{pb.id}:{cfg.id} 高危 L2 未强制三签"
                )