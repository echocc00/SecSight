"""API 请求/响应模型"""
from __future__ import annotations

from pydantic import BaseModel, Field


class AlertInjectRequest(BaseModel):
    """Mock 告警注入请求"""
    alert_type: str = Field(description="xmrig_process | mining_pool_connection | high_cpu_anomaly | custom")
    hostname: str = "web-prod-01"
    src_ip: str = "10.0.1.15"
    dst_ip: str | None = None
    pid: int | None = None


class ApprovalRequest(BaseModel):
    """审批提交"""
    approver_role: str = Field(description="incident_commander | approver | ciso_or_delegate")
    approver_user: str
    decision: str = Field(description="approved | rejected | deferred")
    comment: str = ""


class ApiResponse(BaseModel):
    """统一响应信封"""
    success: bool = True
    data: dict | list | None = None
    error: str | None = None
