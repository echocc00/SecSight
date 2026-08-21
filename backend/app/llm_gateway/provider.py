"""真实 LLM provider — OpenAI 兼容端点 (MiniMax 直连 / LiteLLM)

不绑定具体厂商 SDK,统一走 OpenAI 兼容 API。
MiniMax: base_url=https://api.minimax.chat/v1, model=abab6.5s-chat
LiteLLM: base_url=http://litellm:4000/v1, model=tier2

健壮性: 真实 LLM 输出常偏离 schema (大小写/类型/枚举),
通过 ① schema 驱动的枚举约束提示 ② 归一化器 两步保障解析成功。
"""
from __future__ import annotations

import json
import re
import types
import typing
from enum import Enum
from typing import Any, Callable

from openai import AsyncOpenAI
from pydantic import BaseModel

import structlog

log = structlog.get_logger()


class LLMProviderError(Exception):
    """LLM 调用/解析失败 (触发上层降级)"""
    pass


# ============ JSON 提取 ============


def _extract_json(text: str) -> str:
    """从 LLM 输出提取 JSON (容忍 markdown 代码围栏/前后缀)"""
    text = text.strip()
    fence = re.search(r"```(?:json)?\s*(.*?)```", text, re.DOTALL)
    if fence:
        text = fence.group(1).strip()
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if match:
        return match.group(0)
    return text


# ============ Schema 驱动的枚举约束提示 ============


def _enum_values(ann: Any) -> list | None:
    """从类型注解提取枚举值 (支持 Enum / list[Enum] / Optional[Enum] / X|None)"""
    origin = typing.get_origin(ann)
    if origin is list:
        args = typing.get_args(ann)
        return _enum_values(args[0]) if args else None
    if origin in (typing.Union, types.UnionType):
        args = [a for a in typing.get_args(ann) if a is not type(None)]
        return _enum_values(args[0]) if args else None
    if isinstance(ann, type) and issubclass(ann, Enum):
        return [m.value for m in ann]
    return None


def _build_constraints(schema: type[BaseModel]) -> str:
    """构造枚举字段约束说明,注入 prompt 让 LLM 输出合法值"""
    parts = []
    for name, field in schema.model_fields.items():
        vals = _enum_values(field.annotation)
        if vals:
            parts.append(f'字段 "{name}" 的值必须严格从 {vals} 中选')
    return "; ".join(parts)


# ============ 归一化器注册 ============

_PREPROCESSORS: dict[type, Callable[[dict], dict]] = {}


def register_preprocessor(schema: type) -> Callable:
    def deco(fn: Callable[[dict], dict]) -> Callable:
        _PREPROCESSORS[schema] = fn
        return fn

    return deco


def _clamp_or_percent(f: float) -> float:
    """>10 视为百分数 (85→0.85),否则 clamp 到 [0,1] (1.5→1.0)"""
    if f > 10:
        f = f / 100
    return max(0.0, min(1.0, f))


def _coerce_confidence(v: Any) -> float:
    """置信度强制为 [0,1] 浮点 (容忍单词/百分数/越界)"""
    if isinstance(v, bool):
        return 0.8 if v else 0.2
    if isinstance(v, (int, float)):
        return _clamp_or_percent(float(v))
    if isinstance(v, str):
        s = v.strip().lower()
        word_map = {
            "high": 0.8, "medium": 0.5, "low": 0.3, "critical": 0.9,
            "very high": 0.9, "高": 0.8, "中": 0.5, "低": 0.3,
        }
        if s in word_map:
            return word_map[s]
        try:
            return _clamp_or_percent(float(s))
        except ValueError:
            return 0.5
    return 0.5


def _register_judgment_normalizer() -> None:
    """注册 JudgmentReport 归一化器 (延迟 import 避免环)"""
    from app.models.schemas import ActionType, JudgmentReport

    valid_severities = {"low", "medium", "high", "critical"}
    valid_tp = {"yes", "no", "uncertain"}
    valid_actions = {a.value for a in ActionType}

    def normalize(d: dict) -> dict:
        d = dict(d)
        # severity → 小写合法枚举
        sev = d.get("severity")
        if isinstance(sev, str):
            sev = sev.strip().lower()
            d["severity"] = sev if sev in valid_severities else "medium"
        else:
            d["severity"] = "medium"
        # true_positive → str
        tp = d.get("true_positive")
        if isinstance(tp, bool):
            d["true_positive"] = "yes" if tp else "no"
        elif tp in valid_tp:
            d["true_positive"] = tp
        else:
            d["true_positive"] = "uncertain"
        # confidence → float [0,1]
        d["confidence"] = _coerce_confidence(d.get("confidence"))
        # recommended_actions → 过滤为合法 ActionType
        ra = d.get("recommended_actions", [])
        d["recommended_actions"] = (
            [a for a in ra if a in valid_actions] if isinstance(ra, list) else []
        )
        # kill_chain_phase → str (真实 LLM 可能返回 list)
        kcp = d.get("kill_chain_phase")
        if isinstance(kcp, list):
            d["kill_chain_phase"] = ", ".join(str(x) for x in kcp)
        elif not isinstance(kcp, str):
            d["kill_chain_phase"] = ""
        # incident_summary → str (真实 LLM 可能返回 list)
        summ = d.get("incident_summary")
        if isinstance(summ, list):
            d["incident_summary"] = " ".join(str(x) for x in summ)
        elif not isinstance(summ, str):
            d["incident_summary"] = ""
        # rationale 最小长度兜底 (真实 LLM 可能输出过短)
        rat = d.get("rationale", "")
        if isinstance(rat, str) and len(rat) < 20:
            d["rationale"] = (rat + "（LLM 输出过短,自动补全以满足最小长度要求）")[:500]
        return d

    register_preprocessor(JudgmentReport)(normalize)


_register_judgment_normalizer()


# ============ Provider ============


class RealLLMProvider:
    """调用 OpenAI 兼容端点的真实 LLM"""

    def __init__(
        self,
        base_url: str,
        api_key: str,
        model: str,
        timeout: int = 60,
    ) -> None:
        if not api_key:
            raise LLMProviderError("LLM api_key 未配置")
        self.model = model
        self.client = AsyncOpenAI(
            base_url=base_url,
            api_key=api_key,
            timeout=timeout,
        )

    async def complete(
        self,
        messages: list[dict],
        temperature: float = 0.1,
        max_tokens: int = 2000,
        **kw: Any,
    ) -> str:
        """普通文本补全 (max_tokens 足够大,避免 JSON 被截断)"""
        try:
            resp = await self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                temperature=temperature,
                max_tokens=max_tokens,
                **kw,
            )
            return resp.choices[0].message.content or ""
        except Exception as e:  # noqa: BLE001 - 统一转 LLMProviderError 触发降级
            raise LLMProviderError(f"LLM 调用失败: {e}") from e

    async def complete_structured(
        self, messages: list[dict], schema: type[BaseModel], temperature: float = 0.1
    ) -> BaseModel:
        """结构化输出: prompt 指示 JSON + 提取 + 归一化 + Pydantic 校验"""
        constraints = _build_constraints(schema)
        schema_fields = ", ".join(schema.model_fields.keys())
        json_instruction = {
            "role": "system",
            "content": (
                "你必须仅输出一个合法 JSON 对象,不要任何额外文字或代码围栏。"
                "保持各字段简洁: incident_summary 不超过 80 字,rationale 不超过 150 字。"
                f"JSON 顶层字段为: {schema_fields}。"
                f"{constraints}。"
                "severity 必须小写;confidence 必须是 0 到 1 的数字;"
                "true_positive 必须是字符串 yes/no/uncertain;kill_chain_phase 必须是字符串。"
                "所有 TTP 必须从【检索知识】中已有的 ATT&CK 技术选择,禁止编造。"
            ),
        }
        raw = await self.complete(
            [json_instruction] + messages, temperature, max_tokens=2000
        )
        json_str = _extract_json(raw)
        try:
            data = json.loads(json_str)
        except Exception as e:  # noqa: BLE001
            log.warning("llm.json_parse_failed", error=str(e), raw_preview=raw[:200])
            raise LLMProviderError(f"LLM 输出非合法 JSON: {e}") from e

        preprocessor = _PREPROCESSORS.get(schema)
        if preprocessor:
            data = preprocessor(data)

        try:
            return schema.model_validate(data)
        except Exception as e:  # noqa: BLE001
            log.warning("llm.schema_validate_failed", error=str(e), raw_preview=raw[:200])
            raise LLMProviderError(f"LLM 输出无法校验为 {schema.__name__}: {e}") from e
