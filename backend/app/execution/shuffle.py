"""Shuffle SOAR 执行器 — 调 Shuffle REST API 触发 Workflow

License 隔离: Shuffle AGPL-3.0,仅 HTTP 调用,不 import 其代码。

Shuffle Workflow 触发:
  POST {base_url}/api/v1/workflows/{workflow_id}/execute
  Body: {"execution_argument": JSON.stringify(action)}
  Headers: Authorization: Bearer {api_key}

Workflow ID 配置 (两种方式,环境变量优先):
  1. 单动作环境变量: SHUFFLE_WORKFLOW_ISOLATE_HOST=abc-123
  2. JSON 映射:      SHUFFLE_WORKFLOW_MAP={"isolate_host":"abc-123",...}

未配置的动作会抛 ShuffleError → get_executor 降级 MockExecutor,
启动时 validate_execution_config() 会显式警告哪些动作走 mock。
Workflow 模板见 deploy/shuffle-workflows/。
"""
from __future__ import annotations

import json
import os
from typing import Any

import httpx
import structlog

from app.execution.mock import ActionExecutor
from app.models.schemas import Action, ActionType

log = structlog.get_logger()


class ShuffleError(Exception):
    """Shuffle 调用失败 (触发降级)"""
    pass


def load_workflow_map() -> dict[str, str]:
    """加载 action_type → workflow_id 映射

    优先级: 单动作环境变量 > SHUFFLE_WORKFLOW_MAP JSON > 空
    环境变量命名: SHUFFLE_WORKFLOW_<ACTION_TYPE_UPPER>
      例: SHUFFLE_WORKFLOW_ISOLATE_HOST=abc-123-def
    """
    from app.core.config import settings

    result: dict[str, str] = {}

    # 1. JSON 映射 (批量配置)
    raw = (settings.shuffle_workflow_map or "").strip()
    if raw:
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                result.update({k: str(v) for k, v in parsed.items() if v})
        except json.JSONDecodeError as e:
            log.warning("shuffle.workflow_map_invalid_json", error=str(e))

    # 2. 单动作环境变量 (覆盖 JSON)
    for action in ActionType:
        env_key = f"SHUFFLE_WORKFLOW_{action.value.upper()}"
        wf_id = os.environ.get(env_key, "").strip()
        if wf_id:
            result[action.value] = wf_id

    return result


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
        self.workflow_map = workflow_map if workflow_map is not None else load_workflow_map()
        self.timeout = timeout

    async def execute(self, action: Action, case_id: str | None = None) -> dict:
        """触发 Shuffle Workflow 执行处置动作"""
        action_type = action.action_type.value
        workflow_id = self.workflow_map.get(action_type, "")

        if not workflow_id:
            raise ShuffleError(
                f"action_type '{action_type}' 未配置 Shuffle workflow_id。"
                f"设 SHUFFLE_WORKFLOW_{action_type.upper()}=<workflow_id> "
                f"(Workflow 模板见 deploy/shuffle-workflows/)"
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
            "executor": "shuffle",
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
