"""WebSocket 实时事件广播 — 审批/执行/Case 状态变更推给前端

单实例部署用 in-memory 连接集合。事件不落库,断线后前端重连靠轮询或
重新拉取兜底 (审批面板保底 30s 轮询)。

事件类型 (前端按 type 订阅):
  case_created       {case_id, severity, playbook_id}
  alert_deduped      {case_id, alert_count}
  approval_submitted {case_id, action_id, all_approved, case_status}
  execution_step     {case_id, action_id, status, action_type, executor}
  case_resolved      {case_id, tttr_seconds}
  case_escalated     {case_id}
"""
from __future__ import annotations

import asyncio
from datetime import datetime
from typing import Any

import structlog
from fastapi import WebSocket

log = structlog.get_logger()


class EventBroadcaster:
    def __init__(self) -> None:
        self._connections: set[WebSocket] = set()
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        async with self._lock:
            self._connections.add(websocket)
        log.info("ws.connected", total=len(self._connections))

    async def disconnect(self, websocket: WebSocket) -> None:
        async with self._lock:
            self._connections.discard(websocket)
        log.info("ws.disconnected", total=len(self._connections))

    async def publish(self, event_type: str, payload: dict[str, Any] | None = None) -> None:
        """广播事件给所有客户端。单客户端失败不影响其他。"""
        message = {
            "type": event_type,
            "payload": payload or {},
            "ts": datetime.utcnow().isoformat(),
        }
        async with self._lock:
            connections = list(self._connections)

        dead: list[WebSocket] = []
        for ws in connections:
            try:
                await ws.send_json(message)
            except Exception as e:  # noqa: BLE001 — 客户端断开不应中断广播
                log.warning("ws.send_failed", error=str(e))
                dead.append(ws)

        if dead:
            async with self._lock:
                for ws in dead:
                    self._connections.discard(ws)

    @property
    def connected_count(self) -> int:
        return len(self._connections)


broadcaster = EventBroadcaster()