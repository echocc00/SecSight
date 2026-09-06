"""处置目标解析 — 从告警提取真实资产,而非空 target

背景: 剧本 parameters 只有静态策略 (mode/protocols),不含具体主机/IP。
如果 target 为空,执行器和审批人都不知道会影响谁。
"""
from __future__ import annotations

import pytest

from app.agents.nodes import build_action_from_config, resolve_action_target
from app.models.schemas import ActionType
from app.playbooks.models import ContainmentActionConfig


def _alert(**overrides) -> dict:
    alert = {
        "src_ip": "45.33.32.156",
        "dst_ip": "10.0.2.20",
        "user": None,
        "asset": {
            "host_id": "web-prod-01",
            "hostname": "web-prod-01",
            "ips": ["10.0.5.11"],
        },
        "raw": {
            "pid": 28371,
            "process_name": "xmrig",
            "domain": "pool.supportxmr.com",
            "file_path": "/tmp/xmrig",
            "file_hash": "a" * 64,
            "service": "nginx",
        },
    }
    alert.update(overrides)
    return alert


class TestIsolateHost:
    def test_resolves_host_identity(self):
        target = resolve_action_target(ActionType.isolate_host, [_alert()])
        assert target["host_id"] == "web-prod-01"
        assert target["hostname"] == "web-prod-01"
        assert target["host_ip"] == "10.0.5.11"

    def test_omits_unrelated_fields(self):
        """隔离主机不该带 domain/pid,否则 workflow 容易误用错字段"""
        target = resolve_action_target(ActionType.isolate_host, [_alert()])
        assert "domain" not in target
        assert "pid" not in target


class TestBlockIP:
    def test_prefers_source_ip(self):
        """封的是攻击者侧,src_ip 优先"""
        target = resolve_action_target(ActionType.block_ip, [_alert()])
        assert target == {"ip": "45.33.32.156"}

    def test_falls_back_to_dst_when_no_src(self):
        """内网横向场景 src_ip 可能缺失,退回目标 IP"""
        target = resolve_action_target(ActionType.block_ip, [_alert(src_ip=None)])
        assert target == {"ip": "10.0.2.20"}

    def test_empty_when_no_ip_at_all(self):
        target = resolve_action_target(
            ActionType.block_ip, [_alert(src_ip=None, dst_ip=None)]
        )
        assert target == {}


class TestOtherActionTypes:
    def test_kill_process_carries_pid_and_name(self):
        target = resolve_action_target(ActionType.kill_process, [_alert()])
        assert target["pid"] == 28371
        assert target["process_name"] == "xmrig"
        assert target["hostname"] == "web-prod-01"

    def test_block_domain(self):
        target = resolve_action_target(ActionType.block_domain, [_alert()])
        assert target == {"domain": "pool.supportxmr.com"}

    def test_block_domain_extracted_from_cmdline(self):
        """采集器常不给独立 domain 字段,矿池域名藏在 cmdline 里"""
        alert = _alert()
        alert["raw"] = {
            "cmdline": "xmrig -o stratum+tcp://pool.supportxmr.com:3333 -u 48Bit",
        }
        target = resolve_action_target(ActionType.block_domain, [alert])
        assert target["domain"] == "pool.supportxmr.com"

    def test_block_domain_extracted_from_message(self):
        alert = _alert(message="连接矿池 evil.pool.xyz 被检测")
        alert["raw"] = {}
        target = resolve_action_target(ActionType.block_domain, [alert])
        assert target["domain"] == "evil.pool.xyz"

    def test_block_domain_empty_when_no_domain_anywhere(self):
        alert = _alert(message="high cpu usage")
        alert["raw"] = {}
        assert resolve_action_target(ActionType.block_domain, [alert]) == {}

    def test_quarantine_file(self):
        target = resolve_action_target(ActionType.quarantine_file, [_alert()])
        assert target["file_path"] == "/tmp/xmrig"
        assert target["file_hash"] == "a" * 64

    def test_freeze_account_uses_alert_user(self):
        target = resolve_action_target(
            ActionType.freeze_account, [_alert(user="svc_backup")]
        )
        assert target["account"] == "svc_backup"

    def test_freeze_account_falls_back_to_raw_username(self):
        alert = _alert()
        alert["raw"]["srcuser"] = "root"
        target = resolve_action_target(ActionType.freeze_account, [alert])
        assert target["account"] == "root"

    def test_service_restart(self):
        target = resolve_action_target(ActionType.service_restart, [_alert()])
        assert target["service"] == "nginx"

    def test_notify_has_no_target_fields(self):
        """通知类动作不需要处置目标"""
        assert resolve_action_target(ActionType.notify, [_alert()]) == {}

    def test_no_alerts_yields_empty(self):
        assert resolve_action_target(ActionType.isolate_host, []) == {}


class TestBuildActionMergesPlaybookParams:
    def _cfg(self, action_type: str, parameters: dict | None = None):
        return ContainmentActionConfig(
            id=f"A1_{action_type}",
            name="test",
            action_type=action_type,
            autonomy="L2",
            approval="double",
            risk="high",
            parameters=parameters or {},
        )

    def test_playbook_params_preserved(self):
        action = build_action_from_config(
            self._cfg("isolate_host", {"mode": "network_only", "keep_ssh": True}),
            "pb_test",
            [_alert()],
        )
        assert action.target["mode"] == "network_only"
        assert action.target["keep_ssh"] is True

    def test_alert_target_added_alongside_params(self):
        action = build_action_from_config(
            self._cfg("isolate_host", {"mode": "network_only"}),
            "pb_test",
            [_alert()],
        )
        assert action.target["hostname"] == "web-prod-01"
        assert action.target["mode"] == "network_only"

    def test_alert_resolution_wins_on_conflict(self):
        """剧本里写死的 hostname 是模板占位,真实资产必须覆盖它"""
        action = build_action_from_config(
            self._cfg("isolate_host", {"hostname": "PLACEHOLDER"}),
            "pb_test",
            [_alert()],
        )
        assert action.target["hostname"] == "web-prod-01"

    def test_without_alerts_falls_back_to_params_only(self):
        action = build_action_from_config(
            self._cfg("isolate_host", {"mode": "network_only"}), "pb_test"
        )
        assert action.target == {"mode": "network_only"}


class TestEndToEndTargetPopulated:
    async def test_injected_case_actions_have_targets(self, client):
        """回归: 编排产出的 L2 动作必须带真实目标,不能是 {}"""
        resp = await client.post(
            "/api/alerts/inject",
            json={
                "alert_type": "xmrig_process",
                "hostname": "tgt-host-1",
                "src_ip": "45.33.32.156",
            },
        )
        case_id = resp.json()["data"]["case_id"]
        case = (await client.get(f"/api/cases/{case_id}")).json()["data"]

        actionable = [
            a
            for a in case["proposed_actions"]
            if a["action_type"] in ("isolate_host", "block_ip", "kill_process")
        ]
        assert actionable, "挖矿剧本应含隔离/封禁/杀进程动作"
        for action in actionable:
            assert action["target"], f"{action['action_type']} target 为空"

    async def test_isolate_target_matches_injected_host(self, client):
        resp = await client.post(
            "/api/alerts/inject",
            json={"alert_type": "xmrig_process", "hostname": "tgt-host-2"},
        )
        case_id = resp.json()["data"]["case_id"]
        case = (await client.get(f"/api/cases/{case_id}")).json()["data"]

        isolate = next(
            (a for a in case["proposed_actions"] if a["action_type"] == "isolate_host"),
            None,
        )
        assert isolate is not None
        assert isolate["target"]["hostname"] == "tgt-host-2"

    async def test_pending_panel_shows_target(self, client):
        """审批面板要能看出会影响哪台机器"""
        await client.post(
            "/api/alerts/inject",
            json={"alert_type": "xmrig_process", "hostname": "tgt-host-3"},
        )
        items = (await client.get("/api/approvals/pending")).json()["data"]["items"]
        isolate_items = [i for i in items if i["action_type"] == "isolate_host"]
        assert isolate_items
        assert isolate_items[0]["target"]

    async def test_no_l2_action_left_with_empty_target(self, client):
        """回归: 任何需要审批的处置动作都不能是空 target"""
        for alert_type in ("xmrig_process", "lateral_movement", "ssh_bruteforce"):
            await client.post(
                "/api/alerts/inject",
                json={"alert_type": alert_type, "hostname": f"tgt-{alert_type}"},
            )

        items = (await client.get("/api/approvals/pending")).json()["data"]["items"]
        assert items
        empty = [
            (i["action_type"], i["case_id"])
            for i in items
            if i["action_type"] in _TARGET_FIELDS_NAMES and not i["target"]
        ]
        assert not empty, f"以下动作 target 为空: {empty}"


_TARGET_FIELDS_NAMES = {
    "isolate_host",
    "kill_process",
    "quarantine_file",
    "block_ip",
    "block_domain",
    "freeze_account",
    "service_restart",
    "rollback_file",
    "forensic_capture",
}
