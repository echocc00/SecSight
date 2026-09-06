"""WebSocket 实时推送端点 — /ws/events

鉴权: 握手时带 ?token=<access token> (前端从 localStorage 读取)。
refresh token 不能用于握手 —— 只接受 access token。
"""
from __future__ import annotations

from fastapi import APIRouter, Query, WebSocket, WebSocketDisconnect

router = APIRouter()


def _authorize(token: str) -> str | None:
    """校验 access token,返回 username;无效返回 None"""
    try:
        from app.auth.service import decode_token

        user = decode_token(token)
        return user.username
    except Exception:  # noqa: BLE001
        return None


@router.websocket("/ws/events")
async def ws_events(
    websocket: WebSocket,
    token: str = Query("", alias="token"),
) -> None:
    from app.realtime.broadcast import broadcaster

    username = _authorize(token)
    if not username:
        await websocket.close(code=4401, reason="unauthorized")
        return

    await broadcaster.connect(websocket)
    try:
        # 维持连接直到客户端断开;当前无需上行协议,只做下行广播
        while True:
            # 读取但不消费: ping 保活由浏览器/proxy 层负责
            message = await websocket.receive_text()
            if message == "ping":
                await websocket.send_text("pong")
            # 其余消息忽略 (未来可做按 type 订阅过滤)
    except WebSocketDisconnect:
        pass
    finally:
        await broadcaster.disconnect(websocket)