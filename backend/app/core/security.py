"""安全加固 — 速率限制 / CORS / PII 脱敏 / 密钥校验"""
from __future__ import annotations

import re
from functools import lru_cache

from fastapi import HTTPException, Request, status
from slowapi import Limiter
from slowapi.util import get_remote_address

from app.core.config import settings

# ============ 速率限制 ============

# 按客户端 IP 限流
limiter = Limiter(key_func=get_remote_address, default_limits=["1000/minute"])

# 敏感端点专用限流 (登录/注入/审批)
LOGIN_LIMIT = "10/minute"
INJECT_LIMIT = "60/minute"
APPROVAL_LIMIT = "30/minute"


# ============ PII 脱敏 ============

# 常见 PII 模式
_PATTERNS: list[tuple[str, str]] = [
    # 手机号 (11 位,1 开头)
    (re.compile(r"\b1[3-9]\d{9}\b"), "[PHONE]"),
    # 邮箱
    (re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b"), "[EMAIL]"),
    # 身份证 (18 位,最后一位 X)
    (re.compile(r"\b\d{17}[\dXx]\b"), "[IDCARD]"),
    # 银行卡 (16-19 位数字)
    (re.compile(r"\b\d{16,19}\b"), "[CARD]"),
    # IP (保留前两段)
    # 注: IP 在告警里是关键信息,不脱敏
]


def redact_pii(text: str) -> str:
    """脱敏文本中的 PII (手机/邮箱/身份证/银行卡)"""
    if not text or not settings.pii_redaction_enabled:
        return text
    for pattern, replacement in _PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def redact_dict(data: dict) -> dict:
    """递归脱敏 dict 中的字符串值"""
    if not settings.pii_redaction_enabled:
        return data
    result: dict = {}
    for k, v in data.items():
        if isinstance(v, str):
            result[k] = redact_pii(v)
        elif isinstance(v, dict):
            result[k] = redact_dict(v)
        elif isinstance(v, list):
            result[k] = [
                redact_pii(x) if isinstance(x, str)
                else redact_dict(x) if isinstance(x, dict)
                else x
                for x in v
            ]
        else:
            result[k] = v
    return result


# ============ CORS 白名单 ============

# 生产环境收紧: 仅允许配置的前端域名
@lru_cache
def get_cors_origins() -> list[str]:
    if settings.env == "development":
        return ["*"]  # 开发期放开
    # 生产: 从环境变量 CORS_ORIGINS 读取,逗号分隔
    import os

    origins = os.environ.get("CORS_ORIGINS", "http://localhost:8080")
    return [o.strip() for o in origins.split(",") if o.strip()]


# ============ 密钥校验 ============


def validate_secrets() -> list[str]:
    """启动时校验必需密钥,返回警告列表 (不阻塞启动)"""
    warnings: list[str] = []

    if settings.secret_key in ("dev-secret-change-me", "ChangeMe_SecSight_Secret"):
        if settings.env == "production":
            warnings.append("⚠️ SECSIGHT_SECRET_KEY 使用默认值,生产必须修改")
        elif settings.env != "test":
            warnings.append("⚠️ SECSIGHT_SECRET_KEY 使用默认值,建议修改")

    if not settings.mock_mode:
        # 真实模式必须配置 LLM key
        if settings.llm_provider == "minimax" and not settings.minimax_api_key:
            warnings.append("⚠️ mock_mode=false 但 MINIMAX_API_KEY 未配置")
        if settings.llm_provider == "litellm" and not settings.litellm_master_key:
            warnings.append("⚠️ mock_mode=false 但 LITELLM_MASTER_KEY 未配置")

    if settings.enable_threat_intel:
        if not settings.abuseipdb_api_key and not settings.otx_api_key:
            warnings.append("⚠️ ENABLE_THREAT_INTEL=true 但未配置任何情报 API key")

    return warnings
