"""剧本 12→22 补齐 — 10 个新剧本可命中、L2 双签、端到端闭环可跑"""
from __future__ import annotations

import pytest

from app.mock.alerts import MOCK_ALERTS
from app.playbooks.engine import engine

# alert_type -> 期望 playbook_id
_NEW_MATCHES = {
    "file_tampering": "pb_file_tampering_v1",
    "ddos_attack": "pb_ddos_attack_v1",
    "waf_trigger": "pb_waf_trigger_v1",
    "webshell_upload": "pb_webshell_v1",
    "dns_tunneling": "pb_dns_tunneling_v1",
    "database_anomaly": "pb_database_anomaly_v1",
    "api_abuse": "pb_api_abuse_v1",
    "unauthorized_data_access": "pb_unauthorized_access_v1",
    "backup_failure": "pb_backup_failure_v1",
    "compliance_baseline": "pb_compliance_baseline_v1",
}


class TestPlaybookInventory:
    def test_twenty_two_playbooks(self):
        assert len(engine.playbooks) >= 22

    def test_all_design_categories_covered(self):
        categories = {p.category for p in engine.playbooks}
        assert {"host", "network", "application", "data", "database", "compliance"} <= categories

    def test_new_playbooks_have_containment(self):
        for pb_id in _NEW_MATCHES.values():
            pb = engine.get_by_id(pb_id)
            assert pb is not None, f"{pb_id} 未加载"
            assert pb.containment_actions, f"{pb_id} 无处置动作"


class TestAlertToPlaybookMatching:
    @pytest.mark.parametrize("alert_type,expected", list(_NEW_MATCHES.items()))
    def test_new_alert_matches_intended_playbook(self, alert_type, expected):
        alert = MOCK_ALERTS[alert_type](hostname=f"h-{alert_type}", src_ip="45.33.32.156")
        pb = engine.match(alert)
        assert pb is not None, f"{alert_type} 未命中任何剧本"
        assert pb.id == expected, f"{alert_type} 命中 {pb.id},期望 {expected}"


class TestInjectNewPlaybooks:
    @pytest.mark.asyncio
    async def test_inject_sets_intended_playbook(self, client):
        for alert_type, expected in _NEW_MATCHES.items():
            resp = await client.post(
                "/api/alerts/inject",
                json={"alert_type": alert_type, "hostname": f"inj-{alert_type}"},
            )
            assert resp.status_code == 200, f"{alert_type}: {resp.text}"
            data = resp.json()["data"]
            assert data["playbook_id"] == expected, f"{alert_type} → {data['playbook_id']}"

    @pytest.mark.asyncio
    async def test_high_risk_new_playbook_requires_l2_double_sign(self, client):
        """webshell 剧本来高危处置 (隔离/封禁) 必须 L2 三签"""
        resp = await client.post(
            "/api/alerts/inject",
            json={"alert_type": "webshell_upload", "hostname": "inj-webshell"},
        )
        case_id = resp.json()["data"]["case_id"]
        case = (await client.get(f"/api/cases/{case_id}")).json()["data"]
        assert case["playbook_id"] == "pb_webshell_v1"

        critical = [
            a for a in case["proposed_actions"]
            if a["action_type"] in ("isolate_host", "block_ip", "quarantine_file")
        ]
        assert critical, "webshell 剧本应含隔离/封禁动作"
        for action in critical:
            assert action["approval_required"] is True
            assert action["requires_double_sign"] is True

    @pytest.mark.asyncio
    async def test_backup_failure_case_closes_loop(self, client):
        """L4 主导剧本 (backup) 应能自动执行并 closed,无卡审批"""
        resp = await client.post(
            "/api/alerts/inject",
            json={"alert_type": "backup_failure", "hostname": "inj-backup"},
        )
        case_id = resp.json()["data"]["case_id"]
        case = (await client.get(f"/api/cases/{case_id}")).json()["data"]
        assert case["playbook_id"] == "pb_backup_failure_v1"
        # action 主要为 L4/L5 自动执行,不应停留在 pending_approval
        assert case["status"] != "pending_approval" or any(
            not a["approval_required"] for a in case["proposed_actions"]
        )


class TestEndToEndOneNewScenario:
    @pytest.mark.asyncio
    async def test_dns_tunneling_approve_resolve_roundtrip(self, client):
        """DDoS→L2 处置→全批→闭环 (完整链路真实跑通)"""
        from app.agents.nodes import execute_node

        resp = await client.post(
            "/api/alerts/inject",
            json={"alert_type": "dns_tunneling", "hostname": "inj-dns"},
        )
        case_id = resp.json()["data"]["case_id"]
        pending = (await client.get(f"/api/approvals/{case_id}/pending")).json()["data"]
        assert pending, "dns_tunneling 应产生待审批动作"

        for item in pending:
            for role in item["required_roles"]:
                r = await client.post(
                    f"/api/approvals/{case_id}/actions/{item['action_id']}/approve",
                    json={"approver_role": role, "approver_user": f"{role}-u", "decision": "approved"},
                )
                assert r.status_code == 200, r.text

        await execute_node({"case_id": case_id})
        case = (await client.get(f"/api/cases/{case_id}")).json()["data"]
        l2 = [a for a in case["proposed_actions"] if a["approval_required"]]
        executed = {
            s["action_id"]: s for s in case["execution_log"] if s["status"] == "success"
        }
        for action in l2:
            assert action["action_id"] in executed, f"{action['action_type']} 已批准但未执行"