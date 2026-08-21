"""mock LLM 场景检测测试 — 技术 ID 优先判定"""
from __future__ import annotations

import pytest

from app.llm_gateway.mock import (
    MockLLMGateway,
    PRESET_REPORTS,
    _detect_scenario,
)
from app.models.schemas import JudgmentReport


def _msg(content: str) -> list[dict]:
    return [{"role": "user", "content": content}]


class TestScenarioDetection:
    """按 MITRE 技术 ID 优先判定,不受召回知识污染"""

    def test_detects_cryptominer_by_t1496(self):
        assert _detect_scenario(_msg("告警 MITRE技术: T1496 Resource Hijacking")) == "cryptominer"

    def test_detects_ransomware_by_t1486(self):
        assert _detect_scenario(_msg("techniques T1486")) == "ransomware"

    def test_detects_bruteforce_by_t1110(self):
        assert _detect_scenario(_msg("MITRE T1110 Brute Force")) == "bruteforce"

    def test_detects_persistence_by_t1053(self):
        assert _detect_scenario(_msg("T1053.003 Cron")) == "persistence"

    def test_detects_log_compliance_by_t1562(self):
        assert _detect_scenario(_msg("T1562 Impair Defenses")) == "log_compliance"

    def test_detects_service_crash_by_t1489(self):
        assert _detect_scenario(_msg("T1489 Service Stop")) == "service_crash"

    def test_technique_id_takes_precedence_over_keyword(self):
        # 即使文本含 xmrig 字样,只要有 T1053 就判 persistence
        text = "召回知识提到 xmrig 挖矿案例, 但告警技术是 T1053.003"
        assert _detect_scenario(_msg(text)) == "persistence"

    def test_keyword_fallback_xmrig(self):
        assert _detect_scenario(_msg("发现 xmrig 进程")) == "cryptominer"

    def test_keyword_fallback_crontab(self):
        assert _detect_scenario(_msg("crontab 被修改")) == "persistence"

    def test_defaults_to_cryptominer_when_unknown(self):
        assert _detect_scenario(_msg("完全无关的内容")) == "cryptominer"


class TestMockLLMGateway:
    @pytest.mark.asyncio
    async def test_tier2_structured_returns_judgment_report(self):
        llm = MockLLMGateway()
        report = await llm.tier2_structured(_msg("T1496 xmrig"), JudgmentReport)
        assert isinstance(report, JudgmentReport)
        assert report.severity.value == "high"
        assert "T1496" in report.ttps

    @pytest.mark.asyncio
    async def test_preset_reports_cover_all_six_scenarios(self):
        expected = {"cryptominer", "ransomware", "bruteforce", "persistence", "log_compliance", "service_crash"}
        assert expected.issubset(set(PRESET_REPORTS.keys()))

    @pytest.mark.asyncio
    async def test_tier1_complete_returns_summary_string(self):
        llm = MockLLMGateway()
        result = await llm.tier1_complete(_msg("T1110 brute"))
        assert "bruteforce" in result
