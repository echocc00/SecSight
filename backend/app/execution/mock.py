"""处置执行层 (mock + 真实接口)"""
from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime
from uuid import uuid4

import structlog

from app.db.database import async_session
from app.db.repositories import AuditLogRepository
from app.models.schemas import Action

log = structlog.get_logger()


class ActionExecutor(ABC):
    """处置执行抽象"""

    @abstractmethod
    async def execute(self, action: Action) -> dict: ...


class MockExecutor(ActionExecutor):
    """mock 执行: 打日志 + 审计 + 返回 success (替代 Shuffle)"""

    async def execute(self, action: Action) -> dict:
        task_id = str(uuid4())
        log.info(
            "mock.execute",
            action_type=action.action_type.value,
            target=action.target,
            autonomy=action.autonomy_level.value,
            task_id=task_id,
        )
        # 审计记录
        async with async_session() as session:
            audit = AuditLogRepository(session)
            await audit.record(
                action=f"execute:{action.action_type.value}",
                actor="mock-executor",
                case_id=None,  # TODO: 传 case_id
                detail={
                    "action_id": action.action_id,
                    "target": action.target,
                    "autonomy": action.autonomy_level.value,
                    "task_id": task_id,
                },
            )
        return {
            "success": True,
            "task_id": task_id,
            "message": f"[MOCK] executed {action.action_type.value}",
            "executed_at": datetime.utcnow().isoformat(),
        }


class ShuffleExecutor(ActionExecutor):
    """真实 Shuffle 执行 (Phase2 接入)

    实现: 调用 Shuffle REST API 触发 Workflow (不 import Shuffle 代码)
      POST {SHUFFLE_BASE_URL}/api/v1/workflows/{workflow_id}/execute
    License 隔离: AGPL-3.0,仅 HTTP 调用。
    """

    async def execute(self, action: Action) -> dict:
        raise NotImplementedError("Shuffle executor 未实现,当前用 MockExecutor")


def get_executor() -> ActionExecutor:
    from app.core.config import settings

    # 仅当 mock_mode=False 且显式启用 Shuffle 才用真实执行
    if settings.mock_mode or not settings.enable_shuffle:
        return MockExecutor()
    return ShuffleExecutor()
