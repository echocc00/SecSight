"""LLM 网关测试 — 工厂路由 + 合规护栏 (生产强制境内 LLM)"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.llm_gateway.client import LLMGateway
from app.llm_gateway.mock import MockLLMGateway, get_llm


class TestGetLLMFactory:
    def test_returns_mock_gateway_in_mock_mode(self):
        # mock_mode=True (conftest 设置) → 返回 MockLLMGateway
        assert isinstance(get_llm(), MockLLMGateway)


class TestComplianceGuardrail:
    """生产强制境内 LLM: 境外模型 (Claude/GPT) 禁用"""

    @pytest.mark.asyncio
    async def test_audit_complete_raises_when_domestic_required(self):
        gateway = LLMGateway()
        # settings.require_domestic_llm 默认 True
        with pytest.raises(PermissionError, match="境内 LLM"):
            await gateway.audit_complete([{"role": "user", "content": "x"}])


class TestLLMGatewayCompletion:
    def _mock_response(self, content: str):
        msg = MagicMock()
        msg.content = content
        choice = MagicMock()
        choice.message = msg
        resp = MagicMock()
        resp.choices = [choice]
        return resp

    @pytest.mark.asyncio
    async def test_tier1_complete_returns_content(self):
        with patch("app.llm_gateway.client.AsyncOpenAI") as MockClient:
            instance = MockClient.return_value
            instance.chat.completions.create = AsyncMock(
                return_value=self._mock_response("ok")
            )
            gateway = LLMGateway()
            result = await gateway.tier1_complete([{"role": "user", "content": "hi"}])
            assert result == "ok"

    @pytest.mark.asyncio
    async def test_tier2_structured_validates_schema(self):
        from app.models.schemas import JudgmentReport

        payload = (
            '{"incident_summary":"s","severity":"high","ttps":["T1496"],'
            '"confidence":0.9,"rationale":"足够长的推理依据内容用于测试结构化输出校验通过"}'
        )
        with patch("app.llm_gateway.client.AsyncOpenAI") as MockClient:
            instance = MockClient.return_value
            instance.chat.completions.create = AsyncMock(
                return_value=self._mock_response(payload)
            )
            gateway = LLMGateway()
            report = await gateway.tier2_structured(
                [{"role": "user", "content": "x"}], JudgmentReport
            )
            assert report.severity.value == "high"
            assert report.confidence == 0.9


class TestResilientFallback:
    """ResilientLLMGateway: 真 LLM 故障时降级到 mock"""

    def _make_gateway(self, real_fails: bool = True, fallback_enabled: bool = True):
        from app.llm_gateway.resilient import ResilientLLMGateway
        from app.llm_gateway.provider import LLMProviderError

        real = MagicMock()
        if real_fails:
            real.complete = AsyncMock(side_effect=LLMProviderError("real down"))
            real.complete_structured = AsyncMock(side_effect=LLMProviderError("real down"))
        else:
            real.complete = AsyncMock(return_value="real-response")
        fallback = MockLLMGateway()
        return ResilientLLMGateway(real=real, fallback=fallback, fallback_enabled=fallback_enabled)

    @pytest.mark.asyncio
    async def test_tier1_falls_back_on_real_failure(self):
        gw = self._make_gateway(real_fails=True)
        result = await gw.tier1_complete([{"role": "user", "content": "x"}])
        assert gw.last_used == "fallback"
        assert isinstance(result, str)

    @pytest.mark.asyncio
    async def test_tier2_falls_back_on_real_failure(self):
        gw = self._make_gateway(real_fails=True)
        result = await gw.tier2_complete([{"role": "user", "content": "x"}])
        assert gw.last_used == "fallback"

    @pytest.mark.asyncio
    async def test_tier3_falls_back_on_real_failure(self):
        gw = self._make_gateway(real_fails=True)
        result = await gw.tier3_complete([{"role": "user", "content": "x"}])
        assert gw.last_used == "fallback"

    @pytest.mark.asyncio
    async def test_tier2_structured_falls_back_on_real_failure(self):
        from app.models.schemas import JudgmentReport

        gw = self._make_gateway(real_fails=True)
        report = await gw.tier2_structured([{"role": "user", "content": "x"}], JudgmentReport)
        assert gw.last_used == "fallback"
        assert isinstance(report, JudgmentReport)

    @pytest.mark.asyncio
    async def test_fallback_disabled_raises(self):
        from app.llm_gateway.provider import LLMProviderError

        gw = self._make_gateway(real_fails=True, fallback_enabled=False)
        with pytest.raises(LLMProviderError, match="real down"):
            await gw.tier1_complete([{"role": "user", "content": "x"}])

    @pytest.mark.asyncio
    async def test_real_success_no_fallback(self):
        gw = self._make_gateway(real_fails=False)
        result = await gw.tier1_complete([{"role": "user", "content": "x"}])
        assert gw.last_used == "real"
        assert result == "real-response"

    @pytest.mark.asyncio
    async def test_audit_complete_raises_when_domestic_required(self):
        gw = self._make_gateway(real_fails=False)
        with pytest.raises(PermissionError, match="境内 LLM"):
            await gw.audit_complete([{"role": "user", "content": "x"}])
