"""Prometheus 指标 — 核心业务指标暴露

/metrics 端点供 Prometheus 抓取。
"""
from __future__ import annotations

from prometheus_client import Counter, Gauge, Histogram, generate_latest

# ============ 指标定义 ============

# Case 计数 (按状态)
CASES_TOTAL = Counter(
    "secsight_cases_total",
    "Total cases created",
    ["status", "playbook_id"],
)

# TTTR 响应耗时分布
TTTR_SECONDS = Histogram(
    "secsight_tttr_seconds",
    "Time to remediate (seconds)",
    buckets=(30, 60, 120, 300, 600, 1800, 3600),
)

# 当前待处理 Case 数
PENDING_CASES = Gauge(
    "secsight_pending_cases",
    "Currently pending cases (by status)",
    ["status"],
)

# LLM 调用与降级
LLM_CALLS_TOTAL = Counter(
    "secsight_llm_calls_total",
    "Total LLM calls",
    ["tier", "result"],  # result: success | fallback
)

LLM_FALLBACK_TOTAL = Counter(
    "secsight_llm_fallback_total",
    "Total LLM fallback to mock",
    ["tier"],
)

# 情报查询
THREAT_INTEL_QUERIES = Counter(
    "secsight_threat_intel_queries_total",
    "Total threat intel queries",
    ["provider", "result"],
)

# 执行结果
EXECUTION_TOTAL = Counter(
    "secsight_execution_total",
    "Total action executions",
    ["action_type", "status"],
)

EXECUTION_SUCCESS_RATE = Gauge(
    "secsight_execution_success_rate",
    "Action execution success rate (rolling)",
)

# 审批
APPROVALS_TOTAL = Counter(
    "secsight_approvals_total",
    "Total approvals submitted",
    ["decision"],
)


# ============ 便捷记录函数 ============


def record_case_created(status: str, playbook_id: str) -> None:
    CASES_TOTAL.labels(status=status, playbook_id=playbook_id or "none").inc()


def record_tttr(seconds: int) -> None:
    TTTR_SECONDS.observe(seconds)


def record_llm_call(tier: str, success: bool) -> None:
    result = "success" if success else "fallback"
    LLM_CALLS_TOTAL.labels(tier=tier, result=result).inc()
    if not success:
        LLM_FALLBACK_TOTAL.labels(tier=tier).inc()


def record_threat_intel(provider: str, success: bool) -> None:
    THREAT_INTEL_QUERIES.labels(
        provider=provider, result="success" if success else "failed"
    ).inc()


def record_execution(action_type: str, success: bool) -> None:
    EXECUTION_TOTAL.labels(
        action_type=action_type, status="success" if success else "failed"
    ).inc()


def record_approval(decision: str) -> None:
    APPROVALS_TOTAL.labels(decision=decision).inc()


def update_pending(status: str, count: int) -> None:
    PENDING_CASES.labels(status=status).set(count)


def metrics_response() -> bytes:
    """生成 /metrics 响应"""
    return generate_latest()
