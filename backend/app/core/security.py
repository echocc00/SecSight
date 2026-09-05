"""安全加固 — 速率限制 / CORS / PII 脱敏 / 密钥校验"""
from __future__ import annotations

import re
import time
from functools import lru_cache

from fastapi import HTTPException, Request, status
from fastapi.responses import JSONResponse, Response
from slowapi import Limiter
from slowapi.util import get_remote_address

from app.core.config import settings

# ============ 速率限制 ============

# 按客户端 IP 限流。storage_uri 默认内存,多副本部署必须设 RATE_LIMIT_STORAGE_URI=redis://...
# swallow_errors: Redis 故障时放行请求而非 500 (可用性优先于限流精度)
# headers_enabled 保持关闭: 开启会要求每个被限端点显式声明 Response 参数,
# 而 429 的 Retry-After 由 _rate_limit_exceeded_handler 负责,不依赖该开关。
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=[settings.rate_limit_default],
    storage_uri=settings.rate_limit_storage_uri,
    enabled=settings.rate_limit_enabled,
    swallow_errors=True,
)

# 敏感端点专用限流 (登录/注入/webhook/检索/审批)
LOGIN_LIMIT = settings.rate_limit_login
INJECT_LIMIT = settings.rate_limit_inject
WEBHOOK_LIMIT = settings.rate_limit_webhook
SEARCH_LIMIT = settings.rate_limit_search
APPROVAL_LIMIT = settings.rate_limit_approval


def rate_limit_config() -> dict[str, object]:
    """当前限流配置 (供 /health 暴露,便于运维核对)"""
    return {
        "enabled": limiter.enabled,
        "storage": settings.rate_limit_storage_uri.split("://")[0],
        "distributed": not settings.rate_limit_storage_uri.startswith("memory"),
        "limits": {
            "default": settings.rate_limit_default,
            "login": LOGIN_LIMIT,
            "inject": INJECT_LIMIT,
            "webhook": WEBHOOK_LIMIT,
            "search": SEARCH_LIMIT,
            "approval": APPROVAL_LIMIT,
        },
    }


def rate_limit_exceeded_handler(request: Request, exc: Exception) -> Response:
    """429 响应: 统一 ApiResponse 形状 + Retry-After

    slowapi 自带 handler 只在 headers_enabled=True 时给 Retry-After,而开启该选项
    会要求每个被限端点显式声明 Response 参数。这里自己算窗口剩余秒数。
    """
    retry_after = 60
    current_limit = getattr(request.state, "view_rate_limit", None)
    if current_limit is not None:
        try:
            reset_at, _remaining = limiter.limiter.get_window_stats(
                current_limit[0], *current_limit[1]
            )
            retry_after = max(1, int(reset_at - time.time()))
        except Exception:  # noqa: BLE001 — 拿不到窗口就用兜底值,不能让 429 变 500
            pass

    return JSONResponse(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        content={"success": False, "error": f"请求过于频繁,已触发限流: {exc}"},
        headers={"Retry-After": str(retry_after)},
    )


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


def validate_execution_config() -> list[str]:
    """校验处置执行链路真实能力,显式告知哪些动作会走 mock

    问题背景: 未配置 workflow_id 时 Shuffle 必抛错 → 静默降级 mock,
    用户以为在跑真实处置。启动时必须显式警告。
    """
    warnings: list[str] = []

    if settings.mock_mode:
        warnings.append(
            "ℹ️ SECSIGHT_MOCK_MODE=true — LLM/情报/检索/执行全部走 mock。"
            "真实链路设 SECSIGHT_MOCK_MODE=false + 各 ENABLE_* 开关"
        )
        return warnings

    from app.models.schemas import ActionType

    if settings.enable_shuffle:
        from app.execution.shuffle import load_workflow_map

        wf_map = load_workflow_map()
        missing = [a.value for a in ActionType if not wf_map.get(a.value)]
        if missing:
            warnings.append(
                f"⚠️ ENABLE_SHUFFLE=true 但以下动作无 workflow_id 配置,将降级 MockExecutor: "
                f"{', '.join(missing)}。配置方式: SHUFFLE_WORKFLOW_<ACTION>=<workflow_id> "
                f"(见 deploy/shuffle-workflows/README.md)"
            )
        configured = [a for a in wf_map if wf_map[a]]
        if configured:
            warnings.append(f"✅ Shuffle 真实执行已配置: {', '.join(configured)}")
    else:
        warnings.append(
            "⚠️ mock_mode=false 但 ENABLE_SHUFFLE=false — 所有处置动作走 MockExecutor "
            "(仅打日志+审计,不会真实隔离主机/封 IP)"
        )

    if not settings.enable_opensearch:
        warnings.append(
            "ℹ️ ENABLE_OPENSEARCH=false — 告警检索降级扫 Postgres JSON (小数据量可用)"
        )
    if not settings.enable_qdrant:
        warnings.append(
            "ℹ️ ENABLE_QDRANT=false — RAG 走 mock 检索器 (返回预设 ATT&CK 知识)"
        )

    return warnings
