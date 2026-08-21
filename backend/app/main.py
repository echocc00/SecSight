"""SecSight FastAPI 入口"""
from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import datetime

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api import router as api_router
from app.core.config import settings
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
    yield


def create_app() -> FastAPI:
    app = FastAPI(
        title="SecSight",
        description="AI 驱动的安全运维平台 — API",
        version="0.1.0",
        docs_url="/docs",
        redoc_url="/redoc",
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],  # 开发期,生产收紧
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.get("/health")
    async def health() -> dict:
        return {
            "status": "ok",
            "env": settings.env,
            "mock_mode": settings.mock_mode,
            "version": "0.1.0",
            "ts": datetime.utcnow().isoformat(),
        }

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
