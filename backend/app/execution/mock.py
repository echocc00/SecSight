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
    async def execute(self, action: Action, case_id: str | None = None) -> dict: ...


class MockExecutor(ActionExecutor):
    """mock 执行: 打日志 + 审计 + 返回 success (替代 Shuffle)"""

    async def execute(self, action: Action, case_id: str | None = None) -> dict:
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
                case_id=case_id,
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
    """真实 Shuffle 执行 — 包装 execution/shuffle.py,加故障降级

    license 隔离: AGPL-3.0,仅 HTTP 调用,不 import Shuffle 代码。
    降级: 调用失败/超时/workflow 未配置 → 回退 MockExecutor,保证闭环。
    """

    async def execute(self, action: Action, case_id: str | None = None) -> dict:
        from app.core.config import settings
        from app.execution.shuffle import ShuffleExecutor as _Real, ShuffleError

        # 环境变量映射优先 (SHUFFLE_WORKFLOW_ISOLATE_HOST 等)
        import os

        workflow_map: dict[str, str] = {}
        for at in [
            "isolate_host", "block_ip", "block_domain", "kill_process",
            "quarantine_file", "freeze_account", "notify", "service_restart",
        ]:
            env_val = os.environ.get(f"SHUFFLE_WORKFLOW_{at.upper()}")
            if env_val:
                workflow_map[at] = env_val

        try:
            real = _Real(
                base_url=settings.shuffle_base_url,
                api_key=settings.shuffle_api_key,
                workflow_map=workflow_map or None,
                timeout=30,
            )
            return await real.execute(action, case_id=case_id)
        except ShuffleError as e:
            log.warning("shuffle.fallback_to_mock", action=action.action_type.value, error=str(e))
            mock_result = await MockExecutor().execute(action, case_id=case_id)
            mock_result["fallback_reason"] = f"Shuffle: {e}"
            return mock_result


def get_executor() -> ActionExecutor:
    from app.core.config import settings

    # 仅当 mock_mode=False 且显式启用 Shuffle 才用真实执行
    if settings.mock_mode or not settings.enable_shuffle:
        return MockExecutor()
    return ShuffleExecutor()
