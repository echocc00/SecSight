"""数据模型测试 — Pydantic 校验 + 领域方法"""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.models.schemas import (
    Action,
    ActionType,
    Alert,
    AutonomyLevel,
    Case,
    JudgmentReport,
    Severity,
)

# 满足 min_length=20 的有效推理依据
VALID_RATIONALE = "挖矿进程连接矿池，三重证据确认，建议立即隔离主机并清除持久化机制"


class TestJudgmentReportValidation:
    def test_valid_report_passes(self):
        r = JudgmentReport(
            incident_summary="测试摘要",
            severity=Severity.high,
            ttps=["T1496"],
            confidence=0.88,
            rationale=VALID_RATIONALE,
        )
        assert r.confidence == 0.88

    def test_confidence_out_of_range_rejected(self):
        with pytest.raises(ValidationError):
            JudgmentReport(
                incident_summary="x",
                severity=Severity.high,
                confidence=1.5,
                rationale=VALID_RATIONALE,
            )

    def test_summary_too_long_rejected(self):
        with pytest.raises(ValidationError):
            JudgmentReport(
                incident_summary="x" * 300,
                severity=Severity.high,
                confidence=0.5,
                rationale=VALID_RATIONALE,
            )

    def test_rationale_too_short_rejected(self):
        with pytest.raises(ValidationError):
            JudgmentReport(
                incident_summary="x",
                severity=Severity.high,
                confidence=0.5,
                rationale="太短",
            )


class TestCaseNeedsApproval:
    def _action(self, autonomy: AutonomyLevel) -> Action:
        return Action(
            action_type=ActionType.isolate_host,
            target={},
            autonomy_level=autonomy,
            approval_required=autonomy == AutonomyLevel.L2,
        )

    def test_returns_only_l2_actions(self):
        case = Case(
            proposed_actions=[
                self._action(AutonomyLevel.L2),
                self._action(AutonomyLevel.L4),
                self._action(AutonomyLevel.L2),
            ]
        )
        needs = case.needs_approval()
        assert len(needs) == 2
        assert all(a.autonomy_level == AutonomyLevel.L2 for a in needs)

    def test_returns_empty_when_no_l2(self):
        case = Case(proposed_actions=[self._action(AutonomyLevel.L3)])
        assert case.needs_approval() == []


class TestAlertDefaults:
    def test_alert_generates_id_and_timestamp(self):
        a = Alert(source="wazuh", rule_id="550", severity=Severity.low)
        assert a.alert_id
        assert a.ts is not None
        assert a.mitre_tactics == []
