"""API 路由汇总"""
from fastapi import APIRouter

from app.api import alerts, approvals, auth, cases, compliance, evidence, playbooks

router = APIRouter()
router.include_router(auth.router, prefix="/auth", tags=["auth"])
router.include_router(alerts.router, prefix="/alerts", tags=["alerts"])
router.include_router(cases.router, prefix="/cases", tags=["cases"])
router.include_router(playbooks.router, prefix="/playbooks", tags=["playbooks"])
router.include_router(approvals.router, prefix="/approvals", tags=["approvals"])
router.include_router(evidence.router, prefix="/evidence", tags=["evidence"])
router.include_router(compliance.router, prefix="/compliance", tags=["compliance"])
