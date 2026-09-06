"""SecSight FastAPI 入口"""
from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import datetime

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api import router as api_router
from app.core.config import settings
from app.core.security import get_cors_origins, validate_secrets
from app.db.database import init_db

import structlog

structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.add_log_level,
        structlog.processors.JSONRenderer(),
    ]
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    _log = structlog.get_logger()

    # 启动: dev 用 create_all 快速迭代,生产校验 alembic 版本
    if settings.env in ("development", "test"):
        await init_db()
        # 种子默认用户
        try:
            from app.db.database import async_session
            from app.db.repositories import UserRepository

            async with async_session() as session:
                repo = UserRepository(session)
                n = await repo.seed_defaults()
                if n:
                    _log.info(f"users.seeded count={n}")
        except Exception as e:
            _log.warning(f"users.seed_failed error={e}")
    else:
        # 生产: 不自动 migrate (多实例并发会锁),仅校验版本
        from app.db.migration_check import assert_head

        await assert_head()

    # 密钥校验 (警告不阻塞启动)
    for w in validate_secrets():
        _log.warning(w)
    # 剧本配置校验 (L2 双签不静默漏签)
    import os

    from app.playbooks.loader import load_all, validate_playbooks

    for w in validate_playbooks(
        load_all(os.environ.get("PLAYBOOKS_DIR", "./playbooks"))
    ):
        _log.warning(w)
    # 执行链路能力声明 (让用户知道哪些动作会走 mock)
    from app.core.security import validate_execution_config

    for w in validate_execution_config():
        _log.warning(w)

    # Proactive Agent 定时调度
    from app.agents.scheduler import shutdown_scheduler, start_scheduler

    start_scheduler()
    yield
    await shutdown_scheduler()


def create_app() -> FastAPI:
    app = FastAPI(
        title="SecSight",
        description="AI 驱动的安全运维平台 — API",
        version="0.2.0",
        docs_url="/docs",
        redoc_url="/redoc",
        lifespan=lifespan,
    )

    # CORS 收紧 (生产仅配置域名)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=get_cors_origins(),
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # 速率限制
    from slowapi.errors import RateLimitExceeded

    from app.core.security import limiter, rate_limit_exceeded_handler

    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, rate_limit_exceeded_handler)

    @app.get("/health")
    async def health() -> dict:
        from app.core.metrics import update_pending

        # 扩展健康检查: 含各组件连通性
        components: dict[str, str] = {}
        try:
            async with async_session() as session:
                from sqlalchemy import text

                await session.execute(text("SELECT 1"))
            components["postgres"] = "ok"
        except Exception:
            components["postgres"] = "down"

        # Qdrant
        try:
            import httpx

            async with httpx.AsyncClient(timeout=3) as c:
                await c.get(f"{settings.qdrant_url}/healthz")
            components["qdrant"] = "ok"
        except Exception:
            components["qdrant"] = "down (mock mode 可忽略)"

        # LiteLLM
        try:
            import httpx

            async with httpx.AsyncClient(timeout=3) as c:
                await c.get(f"{settings.litellm_base_url}/health/liveliness")
            components["litellm"] = "ok"
        except Exception:
            components["litellm"] = "down (mock mode 可忽略)"

        # OpenCTI (第 3 情报源,AGPL 隔离组件,仅 HTTP)
        if settings.enable_opencti:
            from app.integrations.opencti import health_check as opencti_health

            opencti = await opencti_health()
            components["opencti"] = (
                "ok" if opencti["status"] == "ok" else f"{opencti['status']}"
            )

        # 处置执行链路真实能力 (关键: 让用户知道哪些动作走 mock)
        from app.models.schemas import ActionType

        if settings.mock_mode or not settings.enable_shuffle:
            execution = {
                "mode": "mock",
                "reason": "mock_mode=true" if settings.mock_mode else "ENABLE_SHUFFLE=false",
                "configured_actions": [],
                "mock_actions": [a.value for a in ActionType],
            }
        else:
            from app.execution.shuffle import load_workflow_map

            wf_map = load_workflow_map()
            configured = [a.value for a in ActionType if wf_map.get(a.value)]
            execution = {
                "mode": "shuffle" if configured else "mock",
                "reason": None if configured else "无 workflow_id 配置",
                "configured_actions": configured,
                "mock_actions": [a.value for a in ActionType if not wf_map.get(a.value)],
            }

        # Proactive 调度器状态
        from app.agents.scheduler import scheduler_status
        from app.core.security import rate_limit_config
        from app.retrieval.embedding import embedding_status

        return {
            "status": "ok",
            "env": settings.env,
            "mock_mode": settings.mock_mode,
            "version": "0.6.0",
            "components": components,
            "execution": execution,
            "proactive_scheduler": scheduler_status(),
            "rate_limit": rate_limit_config(),
            "features": {
                "knowledge_sediment": settings.enable_knowledge_sediment,
                "alert_dedup": settings.enable_alert_dedup,
                "checkpointer": settings.enable_checkpointer,
                "opensearch": settings.enable_opensearch,
                "qdrant": settings.enable_qdrant,
                "threat_intel": settings.enable_threat_intel,
                "opencti": settings.enable_opencti,
            },
            "embedding": embedding_status(),
            "ts": datetime.utcnow().isoformat(),
        }

    @app.get("/metrics")
    async def metrics():
        from app.core.metrics import metrics_response
        from fastapi import Response

        return Response(content=metrics_response(), media_type="text/plain")

    @app.get("/")
    async def root() -> dict:
        return {
            "name": "SecSight",
            "description": "AI-driven security operations platform",
            "docs": "/docs",
            "mock_mode": settings.mock_mode,
        }

    app.include_router(api_router, prefix="/api")

    return app


app = create_app()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "app.main:app",
        host=settings.backend_host,
        port=settings.backend_port,
        reload=settings.env == "development",
    )
