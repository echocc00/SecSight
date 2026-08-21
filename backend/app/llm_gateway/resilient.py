"""弹性 LLM 网关 — 真 LLM 主 + 故障降级 mock

策略: 研判优先走真实 LLM (MiniMax);若调用失败/超时/解析失败,
且 llm_fallback_to_mock=True,则降级回 MockLLMGateway 预设报告,
保证 Case 闭环不中断。
"""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel

from app.llm_gateway.mock import MockLLMGateway
from app.llm_gateway.provider import LLMProviderError, RealLLMProvider

import structlog

log = structlog.get_logger()


class ResilientLLMGateway:
    """真实 LLM 为主,故障自动降级 mock"""

    def __init__(
        self,
        real: RealLLMProvider,
        fallback: MockLLMGateway,
        fallback_enabled: bool = True,
    ) -> None:
        self.real = real
        self.fallback = fallback
        self.fallback_enabled = fallback_enabled
        self.last_used = "none"  # real | fallback (供观测/审计)

    def _maybe_raise(self, error: LLMProviderError) -> None:
        if not self.fallback_enabled:
            raise error

    async def tier1_complete(self, messages: list[dict], **kw: Any) -> str:
        try:
            result = await self.real.complete(messages, **kw)
            self.last_used = "real"
            return result
        except LLMProviderError as e:
            log.warning("llm.tier1_fallback", error=str(e))
            self._maybe_raise(e)
            self.last_used = "fallback"
            return await self.fallback.tier1_complete(messages, **kw)

    async def tier2_complete(self, messages: list[dict], **kw: Any) -> str:
        try:
            result = await self.real.complete(messages, **kw)
            self.last_used = "real"
            return result
        except LLMProviderError as e:
            log.warning("llm.tier2_fallback", error=str(e))
            self._maybe_raise(e)
            self.last_used = "fallback"
            return await self.fallback.tier2_complete(messages, **kw)

    async def tier3_complete(self, messages: list[dict], **kw: Any) -> str:
        try:
            result = await self.real.complete(messages, **kw)
            self.last_used = "real"
            return result
        except LLMProviderError as e:
            log.warning("llm.tier3_fallback", error=str(e))
            self._maybe_raise(e)
            self.last_used = "fallback"
            return await self.fallback.tier3_complete(messages, **kw)

    async def tier2_structured(
        self, messages: list[dict], schema: type[BaseModel], **kw: Any
    ) -> BaseModel:
        """研判结构化输出 — 核心降级点"""
        try:
            result = await self.real.complete_structured(messages, schema)
            self.last_used = "real"
            return result
        except LLMProviderError as e:
            log.warning("llm.tier2_structured_fallback", error=str(e))
            self._maybe_raise(e)
            self.last_used = "fallback"
            return await self.fallback.tier2_structured(messages, schema, **kw)

    async def audit_complete(self, messages: list[dict], **kw: Any) -> str:
        """高风险审计 — 合规约束同 LLMGateway (境外模型禁用)"""
        from app.core.config import settings

        if settings.require_domestic_llm:
            raise PermissionError(
                "生产环境强制境内 LLM,境外模型 (Claude/GPT) 禁用。"
            )
        return await self.tier2_complete(messages, **kw)
