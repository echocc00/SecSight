"""安全加固测试 — PII 脱敏 + CORS + 密钥校验"""
from __future__ import annotations

import pytest

from app.core.security import (
    get_cors_origins,
    redact_dict,
    redact_pii,
    validate_secrets,
)


class TestPIIRedaction:
    def test_redacts_phone(self):
        assert "[PHONE]" in redact_pii("call 13800138000 now")

    def test_redacts_email(self):
        assert "[EMAIL]" in redact_pii("contact admin@example.com")

    def test_redacts_idcard(self):
        assert "[IDCARD]" in redact_pii("id 110101199001011234")

    def test_keeps_ip(self):
        # IP 是告警关键信息,不脱敏
        text = "attack from 45.10.0.1"
        assert "45.10.0.1" in redact_pii(text)

    def test_redacts_multiple(self):
        text = "user 13912345678 admin@evil.com from 45.10.0.1"
        redacted = redact_pii(text)
        assert "[PHONE]" in redacted
        assert "[EMAIL]" in redacted
        assert "45.10.0.1" in redacted  # IP 保留

    def test_redact_dict_recursive(self):
        data = {"msg": "call 13800138000", "nested": {"email": "a@b.com"}}
        out = redact_dict(data)
        assert "[PHONE]" in out["msg"]
        assert "[EMAIL]" in out["nested"]["email"]

    def test_redact_dict_list(self):
        data = {"items": ["phone 13800138000", "normal"]}
        out = redact_dict(data)
        assert "[PHONE]" in out["items"][0]
        assert out["items"][1] == "normal"


class TestCorsOrigins:
    def test_dev_returns_wildcard(self, monkeypatch):
        from app.core import config as cfg

        monkeypatch.setattr(cfg.settings, "env", "development")
        # 清 lru_cache
        get_cors_origins.cache_clear()
        assert "*" in get_cors_origins()

    def test_prod_restricts_origins(self, monkeypatch):
        import os

        from app.core import config as cfg

        monkeypatch.setattr(cfg.settings, "env", "production")
        monkeypatch.setenv("CORS_ORIGINS", "https://soc.company.com,https://soc2.company.com")
        get_cors_origins.cache_clear()
        origins = get_cors_origins()
        assert "https://soc.company.com" in origins
        assert "*" not in origins
        # 恢复
        monkeypatch.setattr(cfg.settings, "env", "development")
        get_cors_origins.cache_clear()


class TestSecretValidation:
    def test_warns_on_default_secret_in_production(self, monkeypatch):
        from app.core import config as cfg

        monkeypatch.setattr(cfg.settings, "env", "production")
        monkeypatch.setattr(cfg.settings, "secret_key", "ChangeMe_SecSight_Secret")
        warnings = validate_secrets()
        assert any("SECRET_KEY" in w for w in warnings)

    def test_warns_when_mock_false_but_no_llm_key(self, monkeypatch):
        from app.core import config as cfg

        monkeypatch.setattr(cfg.settings, "mock_mode", False)
        monkeypatch.setattr(cfg.settings, "llm_provider", "minimax")
        monkeypatch.setattr(cfg.settings, "minimax_api_key", "")
        warnings = validate_secrets()
        assert any("MINIMAX_API_KEY" in w for w in warnings)

    def test_no_warnings_when_properly_configured(self, monkeypatch):
        from app.core import config as cfg

        monkeypatch.setattr(cfg.settings, "env", "development")
        monkeypatch.setattr(cfg.settings, "secret_key", "proper-secret-xxx")
        monkeypatch.setattr(cfg.settings, "mock_mode", True)
        warnings = validate_secrets()
        assert len(warnings) == 0
