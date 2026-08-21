# SecSight 配置 (环境变量驱动)
from __future__ import annotations

from functools import lru_cache
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="SECSIGHT_",
        extra="ignore",
    )

    # 基础
    env: str = "development"
    log_level: str = "INFO"
    secret_key: str = Field(default="dev-secret-change-me")
    backend_host: str = "0.0.0.0"
    backend_port: int = 8000
    mock_mode: bool = True  # 全 mock 开关,真实环境切 false

    # 数据库 (垂直切片默认 SQLite,生产切 Postgres)
    database_url: str = Field(
        default="sqlite+aiosqlite:///./secsight.db",
        alias="DATABASE_URL",
    )
    postgres_dsn: str = Field(
        default="postgresql+asyncpg://secsight:ChangeMe@postgres:5432/secsight",
        alias="POSTGRES_DSN",
    )

    # 向量库
    qdrant_url: str = Field(default="http://qdrant:6333", alias="QDRANT_URL")
    qdrant_api_key: str = Field(default="", alias="QDRANT_API_KEY")

    # LLM 网关 (LiteLLM)
    litellm_base_url: str = Field(
        default="http://litellm:4000/v1", alias="LITELLM_BASE_URL"
    )
    litellm_master_key: str = Field(default="", alias="LITELLM_MASTER_KEY")
    model_tier1: str = Field(default="tier1", alias="LITELLM_MODEL_TIER1")
    model_tier2: str = Field(default="tier2", alias="LITELLM_MODEL_TIER2")
    model_tier3: str = Field(default="tier3", alias="LITELLM_MODEL_TIER3")

    # 合规: 强制境内 LLM
    require_domestic_llm: bool = Field(default=True, alias="REQUIRE_DOMESTIC_LLM")
    pii_redaction_enabled: bool = Field(default=True, alias="PII_REDACTION_ENABLED")

    # OpenSearch
    opensearch_url: str = Field(
        default="http://opensearch:9200", alias="OPENSEARCH_URL"
    )
    opensearch_user: str = Field(default="admin", alias="OPENSEARCH_USER")
    opensearch_password: str = Field(default="", alias="OPENSEARCH_PASSWORD")

    # 隔离组件 (AGPL/GPL,仅 HTTP 调用)
    shuffle_base_url: str = Field(
        default="http://shuffle:3001", alias="SHUFFLE_BASE_URL"
    )
    shuffle_api_key: str = Field(default="", alias="SHUFFLE_API_KEY")
    opencti_base_url: str = Field(
        default="http://opencti:8080", alias="OPENCTI_BASE_URL"
    )
    opencti_token: str = Field(default="", alias="OPENCTI_ADMIN_TOKEN")
    iris_base_url: str = Field(default="http://dfir-iris:8000", alias="IRIS_BASE_URL")

    # 威胁情报 (免费源)
    abuseipdb_api_key: str = Field(default="", alias="ABUSEIPDB_API_KEY")
    otx_api_key: str = Field(default="", alias="OTX_API_KEY")

    # 审计
    audit_log_retention_days: int = Field(
        default=180, alias="AUDIT_LOG_RETENTION_DAYS"
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
