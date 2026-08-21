"""真实 LLM 集成测试 — provider JSON 解析 + 弹性降级 + 工厂路由"""
from __future__ import annotations

import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.llm_gateway.mock import MockLLMGateway, get_llm
from app.llm_gateway.provider import (
    LLMProviderError,
    RealLLMProvider,
    _extract_json,
)
from app.llm_gateway.resilient import ResilientLLMGateway
from app.models.schemas import JudgmentReport


class TestExtractJson:
    def test_extracts_from_code_fence(self):
        text = '```json\n{"a": 1}\n```'
        assert _extract_json(text) == '{"a": 1}'

    def test_extracts_embedded_json(self):
        text = '前置说明 {"a": 1} 后置说明'
        assert _extract_json(text) == '{"a": 1}'

    def test_returns_plain_json(self):
        assert _extract_json('{"a": 1}') == '{"a": 1}'


class TestCoerceConfidence:
    def test_numeric_passthrough(self):
        from app.llm_gateway.provider import _coerce_confidence

        assert _coerce_confidence(0.88) == 0.88

    def test_clamps_above_one(self):
        from app.llm_gateway.provider import _coerce_confidence

        assert _coerce_confidence(1.5) == 1.0

    def test_percent_string(self):
        from app.llm_gateway.provider import _coerce_confidence

        assert _coerce_confidence("85") == 0.85

    def test_word_high(self):
        from app.llm_gateway.provider import _coerce_confidence

        assert _coerce_confidence("High") == 0.8

    def test_bool_true(self):
        from app.llm_gateway.provider import _coerce_confidence

        assert _coerce_confidence(True) == 0.8

    def test_unknown_defaults_half(self):
        from app.llm_gateway.provider import _coerce_confidence

        assert _coerce_confidence("garbage") == 0.5


class TestJudgmentNormalizer:
    """真实 LLM 常见 schema 偏差的归一化"""

    def _normalize(self, d: dict) -> dict:
        from app.llm_gateway.provider import _PREPROCESSORS
        from app.models.schemas import JudgmentReport

        return _PREPROCESSORS[JudgmentReport](d)

    def test_normalizes_capitalized_severity(self):
        out = self._normalize({"severity": "High", "rationale": "x" * 25})
        assert out["severity"] == "high"

    def test_invalid_severity_defaults_medium(self):
        out = self._normalize({"severity": "Extreme", "rationale": "x" * 25})
        assert out["severity"] == "medium"

    def test_bool_true_positive_coerced_to_yes(self):
        out = self._normalize({"true_positive": True, "rationale": "x" * 25})
        assert out["true_positive"] == "yes"

    def test_bool_false_true_positive_coerced_to_no(self):
        out = self._normalize({"true_positive": False, "rationale": "x" * 25})
        assert out["true_positive"] == "no"

    def test_filters_invalid_recommended_actions(self):
        out = self._normalize(
            {"recommended_actions": ["isolate_host", "隔离主机", "block_ip"], "rationale": "x" * 25}
        )
        assert out["recommended_actions"] == ["isolate_host", "block_ip"]

    def test_pads_short_rationale(self):
        out = self._normalize({"rationale": "太短"})
        assert len(out["rationale"]) >= 20

    def test_kill_chain_phase_list_joined_to_string(self):
        out = self._normalize({"kill_chain_phase": ["TA0040 Impact"], "rationale": "x" * 25})
        assert out["kill_chain_phase"] == "TA0040 Impact"

    def test_kill_chain_phase_non_string_cleared(self):
        out = self._normalize({"kill_chain_phase": 123, "rationale": "x" * 25})
        assert out["kill_chain_phase"] == ""

    def test_incident_summary_list_joined(self):
        out = self._normalize({"incident_summary": ["part1", "part2"], "rationale": "x" * 25})
        assert out["incident_summary"] == "part1 part2"


class TestBuildConstraints:
    def test_includes_severity_enum_values(self):
        from app.llm_gateway.provider import _build_constraints
        from app.models.schemas import JudgmentReport

        constraints = _build_constraints(JudgmentReport)
        assert "severity" in constraints
        assert "low" in constraints and "critical" in constraints

    def test_includes_recommended_actions_enum(self):
        from app.llm_gateway.provider import _build_constraints
        from app.models.schemas import JudgmentReport

        constraints = _build_constraints(JudgmentReport)
        assert "recommended_actions" in constraints
        assert "isolate_host" in constraints


class TestRealLLMProvider:
    def _provider(self) -> RealLLMProvider:
        with patch("app.llm_gateway.provider.AsyncOpenAI"):
            return RealLLMProvider(
                base_url="http://x/v1", api_key="k", model="m", timeout=5
            )

    def test_raises_without_api_key(self):
        with pytest.raises(LLMProviderError, match="api_key 未配置"):
            RealLLMProvider(base_url="http://x", api_key="", model="m")

    @pytest.mark.asyncio
    async def test_complete_wraps_error_as_provider_error(self):
        provider = self._provider()
        provider.client.chat.completions.create = AsyncMock(side_effect=RuntimeError("boom"))
        with pytest.raises(LLMProviderError, match="LLM 调用失败"):
            await provider.complete([{"role": "user", "content": "x"}])

    @pytest.mark.asyncio
    async def test_complete_structured_parses_valid_json(self):
        payload = (
            '{"incident_summary":"s","severity":"high","ttps":["T1496"],'
            '"confidence":0.9,"rationale":"足够长的推理依据内容用于测试结构化解析通过"}'
        )
        provider = self._provider()
        msg = MagicMock()
        msg.content = payload
        choice = MagicMock()
        choice.message = msg
        resp = MagicMock()
        resp.choices = [choice]
        provider.client.chat.completions.create = AsyncMock(return_value=resp)

        report = await provider.complete_structured(
            [{"role": "user", "content": "x"}], JudgmentReport
        )
        assert report.severity.value == "high"
        assert report.confidence == 0.9

    @pytest.mark.asyncio
    async def test_complete_structured_raises_on_invalid_json(self):
        provider = self._provider()
        msg = MagicMock()
        msg.content = "这不是 JSON"
        choice = MagicMock()
        choice.message = msg
        resp = MagicMock()
        resp.choices = [choice]
        provider.client.chat.completions.create = AsyncMock(return_value=resp)

        with pytest.raises(LLMProviderError, match="非合法 JSON"):
            await provider.complete_structured(
                [{"role": "user", "content": "x"}], JudgmentReport
            )


def _failing_provider() -> RealLLMProvider:
    """构造一个调用即失败的 real provider"""
    with patch("app.llm_gateway.provider.AsyncOpenAI"):
        provider = RealLLMProvider(base_url="http://x", api_key="k", model="m")
    provider.client.chat.completions.create = AsyncMock(side_effect=RuntimeError("down"))
    return provider


class TestResilientFallback:
    """真 LLM 故障 → 降级 mock"""

    @pytest.mark.asyncio
    async def test_tier2_structured_falls_back_to_mock(self):
        gw = ResilientLLMGateway(_failing_provider(), MockLLMGateway(), fallback_enabled=True)
        report = await gw.tier2_structured(
            [{"role": "user", "content": "xmrig T1496"}], JudgmentReport
        )
        assert isinstance(report, JudgmentReport)
        assert gw.last_used == "fallback"

    @pytest.mark.asyncio
    async def test_tier1_complete_falls_back_to_mock(self):
        gw = ResilientLLMGateway(_failing_provider(), MockLLMGateway(), fallback_enabled=True)
        result = await gw.tier1_complete([{"role": "user", "content": "T1110"}])
        assert "MOCK" in result
        assert gw.last_used == "fallback"

    @pytest.mark.asyncio
    async def test_raises_when_fallback_disabled(self):
        gw = ResilientLLMGateway(_failing_provider(), MockLLMGateway(), fallback_enabled=False)
        with pytest.raises(LLMProviderError):
            await gw.tier2_structured(
                [{"role": "user", "content": "x"}], JudgmentReport
            )

    @pytest.mark.asyncio
    async def test_uses_real_when_success(self):
        payload = (
            '{"incident_summary":"real","severity":"high","ttps":["T1496"],'
            '"confidence":0.95,"rationale":"真实 LLM 返回的研判依据内容，足够长度以通过最小长度校验测试"}'
        )
        with patch("app.llm_gateway.provider.AsyncOpenAI"):
            provider = RealLLMProvider(base_url="http://x", api_key="k", model="m")
        msg = MagicMock()
        msg.content = payload
        choice = MagicMock()
        choice.message = msg
        resp = MagicMock()
        resp.choices = [choice]
        provider.client.chat.completions.create = AsyncMock(return_value=resp)

        gw = ResilientLLMGateway(provider, MockLLMGateway(), fallback_enabled=True)
        report = await gw.tier2_structured(
            [{"role": "user", "content": "x"}], JudgmentReport
        )
        assert report.incident_summary == "real"
        assert gw.last_used == "real"

    @pytest.mark.asyncio
    async def test_audit_complete_blocked_by_domestic_guardrail(self):
        gw = ResilientLLMGateway(_failing_provider(), MockLLMGateway())
        with pytest.raises(PermissionError, match="境内 LLM"):
            await gw.audit_complete([{"role": "user", "content": "x"}])


class TestGetLLMFactoryRealMode:
    """mock_mode=False 时按 llm_provider 构建弹性网关"""

    def test_returns_resilient_gateway_for_minimax(self, monkeypatch):
        from app.core import config as cfg

        monkeypatch.setattr(cfg.settings, "mock_mode", False)
        monkeypatch.setattr(cfg.settings, "llm_provider", "minimax")
        monkeypatch.setattr(cfg.settings, "minimax_api_key", "test-key")
        with patch("app.llm_gateway.provider.AsyncOpenAI"):
            llm = get_llm()
        assert isinstance(llm, ResilientLLMGateway)

    def test_returns_resilient_gateway_for_litellm(self, monkeypatch):
        from app.core import config as cfg

        monkeypatch.setattr(cfg.settings, "mock_mode", False)
        monkeypatch.setattr(cfg.settings, "llm_provider", "litellm")
        monkeypatch.setattr(cfg.settings, "litellm_master_key", "test-key")
        with patch("app.llm_gateway.provider.AsyncOpenAI"):
            llm = get_llm()
        assert isinstance(llm, ResilientLLMGateway)


# ============ 真 LLM 冒烟测试 (仅当 MINIMAX_API_KEY 存在时运行) ============
_HAS_MINIMAX_KEY = bool(os.environ.get("MINIMAX_API_KEY"))


@pytest.mark.skipif(not _HAS_MINIMAX_KEY, reason="未设置 MINIMAX_API_KEY,跳过真 LLM 冒烟")
class TestLiveMiniMaxSmoke:
    @pytest.mark.asyncio
    async def test_live_minimax_structured_judgment(self):
        """真实调用 MiniMax 生成结构化研判 (需要真实 key)"""
        from app.core import config as cfg

        provider = RealLLMProvider(
            base_url=cfg.settings.minimax_base_url,
            api_key=os.environ["MINIMAX_API_KEY"],
            model=cfg.settings.minimax_model,
            timeout=cfg.settings.llm_timeout_seconds,
        )
        messages = [
            {"role": "system", "content": "你是安全研判助手。"},
            {
                "role": "user",
                "content": (
                    "告警: 主机 web-prod-01 检测到 xmrig 进程, 命令行含 stratum+tcp://pool.supportxmr.com:3333。"
                    "检索知识: T1496 Resource Hijacking (挖矿)。"
                    "请输出研判。"
                ),
            },
        ]
        report = await provider.complete_structured(messages, JudgmentReport)
        assert isinstance(report, JudgmentReport)
        assert report.incident_summary
        assert 0 <= report.confidence <= 1
