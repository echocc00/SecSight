"""API 路由汇总"""
from fastapi import APIRouter

from app.api import (
    agents,
    alerts,
    approvals,
    audit,
    auth,
    cases,
    compliance,
    evidence,
    knowledge,
    playbooks,
    realtime,
)

router = APIRouter()
router.include_router(auth.router, prefix="/auth", tags=["auth"])
router.include_router(alerts.router, prefix="/alerts", tags=["alerts"])
router.include_router(cases.router, prefix="/cases", tags=["cases"])
router.include_router(playbooks.router, prefix="/playbooks", tags=["playbooks"])
router.include_router(approvals.router, prefix="/approvals", tags=["approvals"])
router.include_router(evidence.router, prefix="/evidence", tags=["evidence"])
router.include_router(compliance.router, prefix="/compliance", tags=["compliance"])
router.include_router(agents.router, prefix="/agents", tags=["agents"])
router.include_router(knowledge.router, prefix="/knowledge", tags=["knowledge"])
router.include_router(audit.router, prefix="/audit", tags=["audit"])
# realtime.router 的 /ws/events 会叠加上 main.py 的 /api 前缀 → /api/ws/events
router.include_router(realtime.router, tags=["realtime"])
