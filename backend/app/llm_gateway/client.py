"""LLM 网关客户端 (经 LiteLLM,OpenAI 兼容)

不直接调厂商 SDK,统一走 LiteLLM 路由。
合规: 生产强制境内模型 (tier1/tier2/tier3),境外 (tier4_audit) 仅脱敏后备选。
"""
from __future__ import annotations

import json
from typing import Any

from openai import AsyncOpenAI
from pydantic import BaseModel

from app.core.config import settings


class LLMGateway:
    """LiteLLM 网关客户端"""

    def __init__(self) -> None:
        self.client = AsyncOpenAI(
            base_url=settings.litellm_base_url,
            api_key=settings.litellm_master_key or "sk-internal",
        )

    async def tier1_complete(self, messages: list[dict], **kw: Any) -> str:
        """Tier1 简单分诊 (MiniMax)"""
        return await self._complete(settings.model_tier1, messages, **kw)

    async def tier2_complete(self, messages: list[dict], **kw: Any) -> str:
        """Tier2 复杂调查推理 (DeepSeek-V3)"""
        return await self._complete(settings.model_tier2, messages, **kw)

    async def tier3_complete(self, messages: list[dict], **kw: Any) -> str:
        """Tier3 代码/剧本生成 (DeepSeek-Coder)"""
        return await self._complete(settings.model_tier3, messages, **kw)

    async def tier2_structured(
        self, messages: list[dict], schema: type[BaseModel], **kw: Any
    ) -> BaseModel:
        """Tier2 结构化输出 (Pydantic 强制校验,防幻觉)"""
        response = await self.client.chat.completions.create(
            model=settings.model_tier2,
            messages=messages,
            temperature=0.1,
            response_format={"type": "json_object"},
            **kw,
        )
        content = response.choices[0].message.content or "{}"
        return schema.model_validate_json(content)

    async def audit_complete(self, messages: list[dict], **kw: Any) -> str:
        """Tier4 高风险审计 (Claude,仅脱敏后备选)

        合规约束: require_domestic_llm=True 时禁止调用境外模型。
        """
        if settings.require_domestic_llm:
            raise PermissionError(
                "生产环境强制境内 LLM,境外模型 (Claude/GPT) 禁用。"
                "如需脱敏后备选,设 REQUIRE_DOMESTIC_LLM=false。"
            )
        return await self._complete("tier4_audit", messages, **kw)

    async def _complete(self, model: str, messages: list[dict], **kw: Any) -> str:
        response = await self.client.chat.completions.create(
            model=model,
            messages=messages,
            temperature=kw.pop("temperature", 0.1),
            **kw,
        )
        return response.choices[0].message.content or ""


llm = LLMGateway()
