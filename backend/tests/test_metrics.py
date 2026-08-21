"""指标测试 — Prometheus 指标记录"""
from __future__ import annotations

from app.core.metrics import (
    metrics_response,
    record_approval,
    record_case_created,
    record_execution,
    record_llm_call,
    record_threat_intel,
    record_tttr,
)


class TestMetricsRecording:
    def test_record_case_created(self):
        # Counter 应该不报错
        record_case_created("resolved", "pb_cryptominer_v1")

    def test_record_tttr(self):
        record_tttr(120)

    def test_record_llm_call_success(self):
        record_llm_call("tier2", success=True)

    def test_record_llm_call_fallback(self):
        record_llm_call("tier2", success=False)

    def test_record_threat_intel(self):
        record_threat_intel("abuseipdb", success=True)

    def test_record_execution(self):
        record_execution("isolate_host", success=True)

    def test_record_approval(self):
        record_approval("approved")

    def test_metrics_response_returns_bytes(self):
        data = metrics_response()
        assert isinstance(data, bytes)
        assert b"secsight" in data
