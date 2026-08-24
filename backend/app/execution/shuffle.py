"""Shuffle SOAR 执行器 — 调 Shuffle REST API 触发 Workflow

License 隔离: Shuffle AGPL-3.0,仅 HTTP 调用,不 import 其代码。

Shuffle Workflow 触发:
  POST {base_url}/api/v1/workflows/{workflow_id}/execute
  Body: {"execution_argument": JSON.stringify(action)}
  Headers: Authorization: Bearer {api_key}

Workflow ID 映射: action_type → shuffle_workflow_id (配置在 SHUFFLE_WORKFLOW_MAP)
用户需在 Shuffle UI 创建对应 Workflow,把 ID 填入配置。
"""
from __future__ import annotations

import json
from typing import Any

import httpx
import structlog

from app.execution.mock import ActionExecutor
from app.models.schemas import Action

log = structlog.get_logger()


class ShuffleError(Exception):
    """Shuffle 调用失败 (触发降级)"""
    pass


# 默认 action_type → workflow_id 映射 (用户在 Shuffle UI 创建后填入)
_DEFAULT_WORKFLOW_MAP: dict[str, str] = {
    "isolate_host": "",
    "block_ip": "",
    "block_domain": "",
    "kill_process": "",
    "quarantine_file": "",
    "freeze_account": "",
    "notify": "",
    "service_restart": "",
}


class ShuffleExecutor(ActionExecutor):
    """真实 Shuffle 执行器 (REST API,AGPL 隔离)"""

    def __init__(
        self,
        base_url: str,
        api_key: str,
        workflow_map: dict[str, str] | None = None,
        timeout: int = 30,
    ) -> None:
        if not base_url:
            raise ShuffleError("Shuffle base_url 未配置")
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.workflow_map = workflow_map or _DEFAULT_WORKFLOW_MAP
        self.timeout = timeout

    async def execute(self, action: Action, case_id: str | None = None) -> dict:
        """触发 Shuffle Workflow 执行处置动作"""
        action_type = action.action_type.value
        workflow_id = self.workflow_map.get(action_type, "")

        if not workflow_id:
            raise ShuffleError(
                f"action_type '{action_type}' 未配置 Shuffle workflow_id "
                f"(在 Shuffle UI 创建 Workflow 后填入 SHUFFLE_WORKFLOW_MAP)"
            )

        payload = {
            "execution_argument": json.dumps(
                {
                    "action_type": action_type,
                    "target": action.target,
                    "action_id": action.action_id,
                    "playbook_id": action.playbook_id,
                    "case_id": case_id,
                },
                ensure_ascii=False,
            ),
            "execution_source": "secsight",
        }
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(
                    f"{self.base_url}/api/v1/workflows/{workflow_id}/execute",
                    json=payload,
                    headers=headers,
                )
                resp.raise_for_status()
                data = resp.json()
        except Exception as e:  # noqa: BLE001
            raise ShuffleError(f"Shuffle 调用失败: {e}") from e

        # Shuffle 返回 execution_id
        execution_id = data.get("execution_id") or data.get("id") or ""
        success = data.get("status", "executing") in ("executing", "success", "queued")

        log.info(
            "shuffle.execute",
            action_type=action_type,
            workflow_id=workflow_id,
            execution_id=execution_id,
        )
        return {
            "success": success,
            "task_id": execution_id,
            "message": f"Shuffle workflow {workflow_id} triggered for {action_type}",
            "shuffle_execution_id": execution_id,
            "shuffle_response": data,
        }

    async def get_execution_status(self, execution_id: str) -> dict:
        """查询 Shuffle 执行状态"""
        headers = {}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(
                    f"{self.base_url}/api/v1/executions/{execution_id}",
                    headers=headers,
                )
                resp.raise_for_status()
                return resp.json()
        except Exception as e:  # noqa: BLE001
            raise ShuffleError(f"Shuffle 状态查询失败: {e}") from e
