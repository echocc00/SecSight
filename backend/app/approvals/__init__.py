"""审批服务"""
from app.approvals.service import ApprovalError, ApprovalService, approval_service

__all__ = ["ApprovalService", "ApprovalError", "approval_service"]
