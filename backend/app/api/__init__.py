"""API 路由汇总

鉴权基线 (P0 修复): 所有业务路由默认挂 JWT 依赖 —— 新增 router 必须显式声明
自己的鉴权策略,不允许"默认裸奔"。分层:
  - 全局: cases/playbooks/evidence/compliance/agents/knowledge → get_current_user
    (端点内再按需 require_permission 细化,如 alert:inject / approval:submit)
  - alerts: JWT 路由 + webhook_router (共享密钥 X-SecSight-Webhook-Token)
  - approvals: JWT 路由 + callback_router (IM 签名校验,fail-closed)
  - auth: 自管 (login/refresh 公开,me/users 端点级依赖)
  - audit: 端点级 require_permission
  - realtime (WebSocket): 握手 query token 自校验,不能挂 HTTP 依赖
"""
from fastapi import APIRouter, Depends

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
from app.auth.service import get_current_user

router = APIRouter()
router.include_router(auth.router, prefix="/auth", tags=["auth"])
router.include_router(alerts.router, prefix="/alerts", tags=["alerts"])
# 告警 webhook (Wazuh/国产设备): 共享密钥,不能并入 JWT 路由
router.include_router(alerts.webhook_router, prefix="/alerts", tags=["alerts-webhook"])
router.include_router(cases.router, prefix="/cases", tags=["cases"],
                      dependencies=[Depends(get_current_user)])
router.include_router(playbooks.router, prefix="/playbooks", tags=["playbooks"],
                      dependencies=[Depends(get_current_user)])
router.include_router(approvals.router, prefix="/approvals", tags=["approvals"])
# IM 审批回调: 签名校验代替 JWT
router.include_router(approvals.callback_router, prefix="/approvals",
                      tags=["approvals-callback"])
router.include_router(evidence.router, prefix="/evidence", tags=["evidence"],
                      dependencies=[Depends(get_current_user)])
router.include_router(compliance.router, prefix="/compliance", tags=["compliance"],
                      dependencies=[Depends(get_current_user)])
router.include_router(agents.router, prefix="/agents", tags=["agents"],
                      dependencies=[Depends(get_current_user)])
router.include_router(knowledge.router, prefix="/knowledge", tags=["knowledge"],
                      dependencies=[Depends(get_current_user)])
router.include_router(audit.router, prefix="/audit", tags=["audit"])
# realtime.router 的 /ws/events 会叠加上 main.py 的 /api 前缀 → /api/ws/events
router.include_router(realtime.router, tags=["realtime"])
