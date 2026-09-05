"""速率限制落地验证 — 429 触发 / 端点独立配额 / 配置暴露"""
from __future__ import annotations

import pytest

from app.core.security import (
    APPROVAL_LIMIT,
    INJECT_LIMIT,
    LOGIN_LIMIT,
    SEARCH_LIMIT,
    WEBHOOK_LIMIT,
    rate_limit_config,
)


def _quota(limit: str) -> int:
    return int(limit.split("/")[0])


class TestLimitConstants:
    def test_login_is_strictest(self):
        assert _quota(LOGIN_LIMIT) < _quota(INJECT_LIMIT)

    def test_webhook_is_loosest(self):
        """webhook 是机器推送,配额必须远高于人工端点"""
        assert _quota(WEBHOOK_LIMIT) > _quota(SEARCH_LIMIT)
        assert _quota(WEBHOOK_LIMIT) > _quota(APPROVAL_LIMIT)

    def test_all_limits_per_minute(self):
        for limit in (LOGIN_LIMIT, INJECT_LIMIT, WEBHOOK_LIMIT, SEARCH_LIMIT, APPROVAL_LIMIT):
            assert limit.endswith("/minute")


class TestRateLimitConfigReport:
    def test_reports_limits(self):
        cfg = rate_limit_config()
        assert cfg["limits"]["login"] == LOGIN_LIMIT
        assert cfg["limits"]["webhook"] == WEBHOOK_LIMIT

    def test_memory_storage_marked_not_distributed(self):
        cfg = rate_limit_config()
        assert cfg["storage"] == "memory"
        assert cfg["distributed"] is False

    async def test_health_exposes_rate_limit(self, client):
        resp = await client.get("/health")
        assert resp.status_code == 200
        assert "rate_limit" in resp.json()


class TestLoginRateLimit:
    async def test_429_after_quota_exhausted(self, client, rate_limiter):
        quota = _quota(LOGIN_LIMIT)
        payload = {"username": "nobody", "password": "wrong"}

        for _ in range(quota):
            resp = await client.post("/api/auth/login", json=payload)
            assert resp.status_code == 401, "配额内应正常返回 401 而非 429"

        blocked = await client.post("/api/auth/login", json=payload)
        assert blocked.status_code == 429
        assert "Retry-After" in blocked.headers or "retry-after" in blocked.headers
        body = blocked.json()
        assert body["success"] is False
        assert "限流" in body["error"]

    async def test_disabled_limiter_never_blocks(self, client):
        """RATE_LIMIT_ENABLED=false 时不应拦截 (limiter.enabled 默认 False)"""
        payload = {"username": "nobody", "password": "wrong"}
        for _ in range(_quota(LOGIN_LIMIT) + 3):
            resp = await client.post("/api/auth/login", json=payload)
            assert resp.status_code == 401


class TestSearchRateLimit:
    async def test_search_has_own_quota(self, client, rate_limiter):
        """检索配额独立于登录配额: 打满登录不影响检索"""
        for _ in range(_quota(LOGIN_LIMIT) + 1):
            await client.post(
                "/api/auth/login", json={"username": "x", "password": "y"}
            )
        resp = await client.get("/api/alerts/search", params={"q": "xmrig"})
        assert resp.status_code == 200

    async def test_429_after_search_quota(self, client, rate_limiter):
        quota = _quota(SEARCH_LIMIT)
        for _ in range(quota):
            resp = await client.get("/api/alerts/search", params={"q": "xmrig"})
            assert resp.status_code == 200
        blocked = await client.get("/api/alerts/search", params={"q": "xmrig"})
        assert blocked.status_code == 429


class TestWebhookRateLimit:
    async def test_webhook_quota_not_hit_by_normal_burst(self, client, rate_limiter):
        """webhook 600/min: 连打 20 次不应被限 (真实告警风暴场景)"""
        payload = {
            "timestamp": "2026-01-01T00:00:00Z",
            "rule": {"id": "100001", "level": 10, "description": "test", "groups": []},
            "agent": {"name": "host-1", "id": "001"},
            "data": {"srcip": "1.2.3.4"},
            "full_log": "test",
        }
        for _ in range(20):
            resp = await client.post("/api/alerts/wazuh-webhook", json=payload)
            assert resp.status_code != 429
