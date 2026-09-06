"""WebSocket 实时推送 — 鉴权 / 连接管理 / 事件广播端到端

starlette TestClient 支持 websocket_connect;事件触发(HTTP)与 WS 连接
在同一 TestClient portal 事件循环内,跨循环问题不存在。
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def ws_client():
    """带 lifespan 的 TestClient (init_db + seed 在 portal 循环内完成)"""
    from app.main import app

    with TestClient(app) as client:
        yield client


def _token(client) -> str:
    resp = client.post(
        "/api/auth/login", json={"username": "admin", "password": "ChangeMe_123!"}
    )
    assert resp.status_code == 200, resp.text
    return resp.json()["access_token"]


class TestWSAuth:
    def test_missing_token_rejected(self, ws_client):
        with pytest.raises(Exception) as exc_info:
            with ws_client.websocket_connect("/api/ws/events"):
                pass
        assert exc_info.value is not None  # starlette 抛 WebSocketDisconnect/Exception

    def test_invalid_token_rejected(self, ws_client):
        with pytest.raises(Exception):
            with ws_client.websocket_connect("/api/ws/events?token=garbage"):
                pass

    def test_refresh_token_rejected(self, ws_client):
        """refresh token 不能握手,必须 access token"""
        login = ws_client.post(
            "/api/auth/login", json={"username": "admin", "password": "ChangeMe_123!"}
        ).json()
        with pytest.raises(Exception):
            with ws_client.websocket_connect(
                f"/api/ws/events?token={login['refresh_token']}"
            ):
                pass

    def test_valid_token_connects(self, ws_client):
        token = _token(ws_client)
        with ws_client.websocket_connect(f"/api/ws/events?token={token}") as ws:
            # 连接成功即可,握手由 starlette 保证
            ws.send_text("ping")
            assert ws.receive_text() == "pong"


class TestBroadcastEndToEnd:
    def test_case_created_pushed_to_ws(self, ws_client):
        token = _token(ws_client)
        with ws_client.websocket_connect(f"/api/ws/events?token={token}") as ws:
            resp = ws_client.post(
                "/api/alerts/inject",
                json={"alert_type": "xmrig_process", "hostname": "ws-case-1"},
            )
            assert resp.status_code == 200
            case_id = resp.json()["data"]["case_id"]

            # 等到收到 case_created (进入 workflow 前一定会广播)
            event = ws.receive_json()
            assert event["type"] == "case_created"
            assert event["payload"]["case_id"] == case_id
            assert event["payload"]["severity"] == "high"

    def test_approval_submitted_pushed(self, ws_client):
        token = _token(ws_client)
        inject = ws_client.post(
            "/api/alerts/inject",
            json={"alert_type": "data_exfiltration", "hostname": "ws-approval-1"},
        ).json()["data"]["case_id"]
        pending = ws_client.get(f"/api/approvals/{inject}/pending").json()["data"]
        assert pending, "应存在待审批动作"

        with ws_client.websocket_connect(f"/api/ws/events?token={token}") as ws:
            target = pending[0]
            resp = ws_client.post(
                f"/api/approvals/{inject}/actions/{target['action_id']}/approve",
                json={
                    "approver_role": target["required_roles"][0],
                    "approver_user": "u1",
                    "decision": "approved",
                },
            )
            assert resp.status_code == 200

            event = ws.receive_json()
            assert event["type"] == "approval_submitted"
            assert event["payload"]["case_id"] == inject
            assert event["payload"]["action_id"] == target["action_id"]
            assert event["payload"]["all_approved"] is False

    def test_execution_step_and_resolved_pushed_after_full_approval(self, ws_client):
        """全批 → 恢复执行 → 时间线每步 execution_step + 最终 case_resolved"""
        token = _token(ws_client)
        inject = ws_client.post(
            "/api/alerts/inject",
            json={"alert_type": "xmrig_process", "hostname": "ws-exec-1"},
        ).json()["data"]["case_id"]
        pending = ws_client.get(f"/api/approvals/{inject}/pending").json()["data"]

        with ws_client.websocket_connect(f"/api/ws/events?token={token}") as ws:
            # 全批全部动作
            for item in pending:
                for role in item["required_roles"]:
                    resp = ws_client.post(
                        f"/api/approvals/{inject}/actions/{item['action_id']}/approve",
                        json={
                            "approver_role": role,
                            "approver_user": f"{role}-u",
                            "decision": "approved",
                        },
                    )
                    assert resp.status_code == 200

            # 收集事件直到 case_resolved (默认模式 workflow 同步跑完)
            seen_types: set[str] = set()
            steps = 0
            resolved = False
            for _ in range(60):
                event = ws.receive_json()
                seen_types.add(event["type"])
                if event["type"] == "execution_step":
                    steps += 1
                if event["type"] == "case_resolved":
                    resolved = True
                    assert event["payload"]["case_id"] == inject
                    break

            assert resolved, f"应收到 case_resolved,实际事件: {seen_types}"
            assert "execution_step" in seen_types
            assert steps >= 1, "已批准的动作必须广播执行步骤"

    def test_disconnect_does_not_break_broadcast(self, ws_client):
        """一个客户端断开不应影响后续广播"""
        token = _token(ws_client)
        # 连一个,主动断开
        with ws_client.websocket_connect(f"/api/ws/events?token={token}") as ws:
            ws.send_text("ping")
        # 再连一个,事件仍能到达
        with ws_client.websocket_connect(f"/api/ws/events?token={token}") as ws:
            ws_client.post(
                "/api/alerts/inject",
                json={"alert_type": "xmrig_process", "hostname": "ws-disconnect-1"},
            )
            event = ws.receive_json()
            assert event["type"] == "case_created"


class TestBroadcasterUnit:
    async def test_publish_reaches_all_connections(self):
        from app.realtime.broadcast import EventBroadcaster

        broadcaster = EventBroadcaster()

        received: list = []

        class _FakeWS:
            def __init__(self, name):
                self.name = name

            async def accept(self):
                pass

            async def send_json(self, message):
                received.append((self.name, message["type"]))

        await broadcaster.connect(_FakeWS("a"))  # type: ignore
        await broadcaster.connect(_FakeWS("b"))  # type: ignore
        await broadcaster.publish("some_event", {"x": 1})

        assert len(received) == 2
        assert all(t == "some_event" for _, t in received)
        assert broadcaster.connected_count == 2

    async def test_publish_skips_dead_connection(self):
        from app.realtime.broadcast import EventBroadcaster

        broadcaster = EventBroadcaster()

        class _BrokenWS:
            async def accept(self):
                pass

            async def send_json(self, message):
                raise ConnectionError("gone")

        await broadcaster.connect(_BrokenWS())  # type: ignore
        await broadcaster.publish("evt", {})  # 不应抛异常

        assert broadcaster.connected_count == 0