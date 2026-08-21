"""剧本匹配引擎测试 — 评分匹配正确性"""
from __future__ import annotations

import pytest

from app.mock.alerts import (
    critical_service_crash_alert,
    log_collection_stopped_alert,
    mining_pool_connection_alert,
    ssh_bruteforce_alert,
    suspicious_crontab_alert,
    xmrig_process_alert,
)
from app.models.schemas import Alert, AssetRef, Severity
from app.playbooks.engine import PlaybookEngine, engine


class TestPlaybookLoading:
    def test_loads_all_phase1_and_phase2_playbooks(self):
        # Phase1: 6 P0 + Phase2: 6 P1 = 12
        assert len(engine.playbooks) == 12

    def test_get_by_id_returns_matching_playbook(self):
        pb = engine.get_by_id("pb_cryptominer_v1")
        assert pb is not None
        assert pb.name == "挖矿病毒应急响应"

    def test_get_by_id_returns_none_for_unknown(self):
        assert engine.get_by_id("nonexistent") is None


class TestPlaybookMatching:
    """每个 mock 告警应匹配到对应剧本"""

    def test_xmrig_process_matches_cryptominer(self):
        assert engine.match(xmrig_process_alert()).id == "pb_cryptominer_v1"

    def test_mining_pool_connection_matches_cryptominer(self):
        assert engine.match(mining_pool_connection_alert()).id == "pb_cryptominer_v1"

    def test_suspicious_crontab_matches_persistence_not_cryptominer(self):
        # 回归: 泛化 rule_id 550 曾导致误匹配 cryptominer
        assert engine.match(suspicious_crontab_alert()).id == "pb_persistence_v1"

    def test_ssh_bruteforce_matches_bruteforce(self):
        assert engine.match(ssh_bruteforce_alert()).id == "pb_bruteforce_v1"

    def test_log_collection_stopped_matches_log_compliance(self):
        assert engine.match(log_collection_stopped_alert()).id == "pb_log_compliance_v1"

    def test_critical_service_crash_matches_service_crash(self):
        assert engine.match(critical_service_crash_alert()).id == "pb_service_crash_v1"


class TestPhase2PlaybookMatching:
    """Phase2 P1 剧本匹配"""

    def test_web_attack_matches(self):
        from app.mock.alerts import web_sql_injection_alert

        assert engine.match(web_sql_injection_alert()).id == "pb_web_attack_v1"

    def test_data_exfiltration_matches(self):
        from app.mock.alerts import data_exfiltration_alert

        assert engine.match(data_exfiltration_alert()).id == "pb_data_exfiltration_v1"

    def test_lateral_movement_matches(self):
        from app.mock.alerts import lateral_movement_alert

        assert engine.match(lateral_movement_alert()).id == "pb_lateral_movement_v1"

    def test_privilege_escalation_matches(self):
        from app.mock.alerts import privilege_escalation_alert

        assert engine.match(privilege_escalation_alert()).id == "pb_privilege_escalation_v1"

    def test_c2_communication_matches(self):
        from app.mock.alerts import c2_communication_alert

        assert engine.match(c2_communication_alert()).id == "pb_c2_communication_v1"

    def test_phishing_email_matches(self):
        from app.mock.alerts import phishing_email_alert

        assert engine.match(phishing_email_alert()).id == "pb_phishing_v1"


class TestScoringPrecedence:
    """评分权重: sigma_id(10) > 进程模式(8) > wazuh rule(2)"""

    def test_sigma_id_beats_generic_wazuh_rule(self):
        # crontab 告警: sigma_id=suspicious_crontab_modification (persistence +10)
        # 同时 rule_id=550 也在 cryptominer 的 wazuh_rules (+2)
        # persistence 应以 10 > 2 胜出
        alert = suspicious_crontab_alert()
        pb = engine.match(alert)
        assert pb.id == "pb_persistence_v1"

    def test_no_match_returns_none_for_unrelated_alert(self):
        alert = Alert(
            source="custom",
            rule_id="9999",
            severity=Severity.low,
            asset=AssetRef(hostname="x"),
            raw={"nothing": "relevant"},
            message="completely unrelated event",
        )
        assert engine.match(alert) is None

    def test_higher_score_wins_over_priority_when_both_match(self):
        # 构造一个同时命中 persistence(sigma) 和 cryptominer(wazuh 550) 的告警
        # sigma 精确匹配应压过 wazuh rule
        score_persistence = engine._score(
            suspicious_crontab_alert(), engine.get_by_id("pb_persistence_v1")
        )
        score_cryptominer = engine._score(
            suspicious_crontab_alert(), engine.get_by_id("pb_cryptominer_v1")
        )
        assert score_persistence > score_cryptominer
