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

    # Embedding provider: tfidf (无依赖兜底) | bge (本地 sentence-transformers) | api (OpenAI 兼容)
    # 换 provider 会改向量维度 → 必须重建 Qdrant collection (deploy/reindex.py)
    embedding_provider: str = Field(default="tfidf", alias="EMBEDDING_PROVIDER")
    embedding_model: str = Field(default="BAAI/bge-m3", alias="EMBEDDING_MODEL")
    embedding_device: str = Field(default="cpu", alias="EMBEDDING_DEVICE")
    embedding_api_base: str = Field(default="", alias="EMBEDDING_API_BASE")
    embedding_api_key: str = Field(default="", alias="EMBEDDING_API_KEY")
    # 真实 embedding 失败是否降级 tfidf。生产建议 false —— 静默降级会让
    # 检索质量断崖下跌却无人察觉,且维度不匹配时写入的向量是垃圾。
    embedding_fallback_to_tfidf: bool = Field(
        default=True, alias="EMBEDDING_FALLBACK_TO_TFIDF"
    )

    # LLM 网关 (LiteLLM)
    litellm_base_url: str = Field(
        default="http://litellm:4000/v1", alias="LITELLM_BASE_URL"
    )
    litellm_master_key: str = Field(default="", alias="LITELLM_MASTER_KEY")
    model_tier1: str = Field(default="tier1", alias="LITELLM_MODEL_TIER1")
    model_tier2: str = Field(default="tier2", alias="LITELLM_MODEL_TIER2")
    model_tier3: str = Field(default="tier3", alias="LITELLM_MODEL_TIER3")

    # 真实 LLM provider 选择 (mock_mode=False 时生效)
    # minimax = MiniMax 直连 (OpenAI 兼容); litellm = 经 LiteLLM 网关
    llm_provider: str = Field(default="minimax", alias="LLM_PROVIDER")
    minimax_api_key: str = Field(default="", alias="MINIMAX_API_KEY")
    minimax_base_url: str = Field(
        default="https://api.minimax.chat/v1", alias="MINIMAX_BASE_URL"
    )
    minimax_model: str = Field(default="abab6.5s-chat", alias="MINIMAX_MODEL")
    llm_timeout_seconds: int = Field(default=60, alias="LLM_TIMEOUT_SECONDS")
    # 真 LLM 故障/超时 → 降级回 mock 预设报告 (保证闭环不断)
    llm_fallback_to_mock: bool = Field(default=True, alias="LLM_FALLBACK_TO_MOCK")

    # 合规: 强制境内 LLM
    require_domestic_llm: bool = Field(default=True, alias="REQUIRE_DOMESTIC_LLM")
    pii_redaction_enabled: bool = Field(default=True, alias="PII_REDACTION_ENABLED")

    # 各组件真实后端启用开关 (独立于 mock_mode,后端就绪才开)
    # mock_mode=False 时,LLM 走真实;retriever/executor 仍需各自 enable 才用真实
    enable_qdrant: bool = Field(default=False, alias="ENABLE_QDRANT")
    enable_shuffle: bool = Field(default=False, alias="ENABLE_SHUFFLE")
    enable_opensearch: bool = Field(default=False, alias="ENABLE_OPENSEARCH")
    enable_checkpointer: bool = Field(default=False, alias="ENABLE_CHECKPOINTER")
    # 知识沉淀飞轮 (L3→L1): Case resolved 后自动提取知识 + 入 Qdrant + 写 L1 YAML
    enable_knowledge_sediment: bool = Field(
        default=True, alias="ENABLE_KNOWLEDGE_SEDIMENT"
    )
    # Proactive Agent 定时调度 (威胁狩猎/漏扫/检测工程/资产加固)
    enable_proactive_scheduler: bool = Field(
        default=False, alias="ENABLE_PROACTIVE_SCHEDULER"
    )
    # 告警时间窗聚合 (同 IoC 窗口内并入现有 Case,防告警风暴)
    enable_alert_dedup: bool = Field(default=True, alias="ENABLE_ALERT_DEDUP")
    alert_dedup_window_minutes: int = Field(
        default=5, alias="ALERT_DEDUP_WINDOW_MINUTES"
    )

    # 速率限制 (多副本部署必须用 Redis,否则每副本独立计数)
    rate_limit_enabled: bool = Field(default=True, alias="RATE_LIMIT_ENABLED")
    rate_limit_storage_uri: str = Field(
        default="memory://", alias="RATE_LIMIT_STORAGE_URI"
    )
    rate_limit_login: str = Field(default="5/minute", alias="RATE_LIMIT_LOGIN")
    rate_limit_inject: str = Field(default="30/minute", alias="RATE_LIMIT_INJECT")
    rate_limit_webhook: str = Field(default="600/minute", alias="RATE_LIMIT_WEBHOOK")
    rate_limit_search: str = Field(default="60/minute", alias="RATE_LIMIT_SEARCH")
    rate_limit_approval: str = Field(default="120/minute", alias="RATE_LIMIT_APPROVAL")
    rate_limit_default: str = Field(default="1000/minute", alias="RATE_LIMIT_DEFAULT")
    # 情报源: mock_mode=False 且 enable_threat_intel=True 时用真实 AbuseIPDB+OTX
    enable_threat_intel: bool = Field(default=False, alias="ENABLE_THREAT_INTEL")
    abuseipdb_api_key: str = Field(default="", alias="ABUSEIPDB_API_KEY")
    otx_api_key: str = Field(default="", alias="OTX_API_KEY")
    threat_intel_timeout_seconds: int = Field(default=10, alias="THREAT_INTEL_TIMEOUT_SECONDS")
    # 真实情报失败 → 降级 mock (保证闭环)
    threat_intel_fallback_to_mock: bool = Field(default=True, alias="THREAT_INTEL_FALLBACK_TO_MOCK")

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
    shuffle_workflow_map: str = Field(
        default="{}", alias="SHUFFLE_WORKFLOW_MAP"
    )  # JSON: {"isolate_host":"wf_id",...}

    # Wazuh 告警源 (GPL 隔离,API/文件读取)
    wazuh_api_url: str = Field(default="http://wazuh-manager:55000", alias="WAZUH_API_URL")
    wazuh_api_user: str = Field(default="wazuh-wui", alias="WAZUH_API_USER")
    wazuh_api_password: str = Field(default="", alias="WAZUH_API_PASSWORD")
    wazuh_alerts_json: str = Field(
        default="", alias="WAZUH_ALERTS_JSON"
    )  # 文件模式: alerts.json 路径
    opencti_base_url: str = Field(
        default="http://opencti:8080", alias="OPENCTI_BASE_URL"
    )
    opencti_token: str = Field(default="", alias="OPENCTI_ADMIN_TOKEN")
    # OpenCTI 作为第 3 情报源 (本地 STIX 知识库 + APT 归因)
    enable_opencti: bool = Field(default=False, alias="ENABLE_OPENCTI")
    opencti_timeout_seconds: int = Field(default=15, alias="OPENCTI_TIMEOUT_SECONDS")
    # x_opencti_score 阈值: >= 判恶意。OpenCTI 默认 50,情报质量高的库可调低
    opencti_malicious_score: int = Field(default=50, alias="OPENCTI_MALICIOUS_SCORE")
    iris_base_url: str = Field(default="http://dfir-iris:8000", alias="IRIS_BASE_URL")

    # 威胁情报 (免费源)
    abuseipdb_api_key: str = Field(default="", alias="ABUSEIPDB_API_KEY")
    otx_api_key: str = Field(default="", alias="OTX_API_KEY")

    # 审计
    audit_log_retention_days: int = Field(
        default=180, alias="AUDIT_LOG_RETENTION_DAYS"
    )

    # 认证令牌
    # access 短时效 + refresh 长时效: access 泄露的窗口从 8h 收到 30min,
    # refresh 存 hash 且可吊销,登出即失效。
    access_token_expire_minutes: int = Field(
        default=30, alias="ACCESS_TOKEN_EXPIRE_MINUTES"
    )
    refresh_token_expire_days: int = Field(
        default=7, alias="REFRESH_TOKEN_EXPIRE_DAYS"
    )
    # 种子用户初始密码。生产留空 → 启动时生成随机密码并打印一次,
    # 避免所有部署共用 ChangeMe_123!
    seed_user_password: str = Field(default="", alias="SEED_USER_PASSWORD")


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
