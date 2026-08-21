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
    # 启动: 建表 (开发用,生产走 alembic)
    if settings.env == "development":
        await init_db()
    # 密钥校验 (警告不阻塞启动)
    for w in validate_secrets():
        structlog.get_logger().warning(w)
    yield


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
    from slowapi import _rate_limit_exceeded_handler
    from slowapi.errors import RateLimitExceeded

    from app.core.security import limiter

    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

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

        return {
            "status": "ok",
            "env": settings.env,
            "mock_mode": settings.mock_mode,
            "version": "0.2.0",
            "components": components,
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
