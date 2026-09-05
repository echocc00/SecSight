"""告警时间窗聚合 — agg_key / 窗口内并入 / resolved 不吸收 / 指标"""
from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from app.db.repositories import CaseRepository, compute_agg_key
from app.models.schemas import Alert, AssetRef, CaseStatus, Severity


def _alert(
    rule_id: str = "100001",
    hostname: str = "web-01",
    src_ip: str = "10.0.0.5",
    source: str = "wazuh",
) -> Alert:
    return Alert(
        source=source,
        rule_id=rule_id,
        rule_level=10,
        severity=Severity.high,
        src_ip=src_ip,
        asset=AssetRef(hostname=hostname, host_id=hostname),
        message="xmrig miner detected",
    )


class TestAggKey:
    def test_same_rule_host_ip_same_key(self):
        assert compute_agg_key(_alert()) == compute_agg_key(_alert())

    def test_different_host_different_key(self):
        assert compute_agg_key(_alert(hostname="web-01")) != compute_agg_key(
            _alert(hostname="web-02")
        )

    def test_different_rule_different_key(self):
        assert compute_agg_key(_alert(rule_id="1")) != compute_agg_key(
            _alert(rule_id="2")
        )

    def test_source_not_part_of_key(self):
        """同一事件经不同采集器上报仍应聚合"""
        assert compute_agg_key(_alert(source="wazuh")) == compute_agg_key(
            _alert(source="suricata")
        )

    def test_key_fits_column(self):
        assert len(compute_agg_key(_alert())) == 32


class TestIngestAggregation:
    async def test_first_alert_creates_case(self, db_session):
        repo = CaseRepository(db_session)
        case, deduped = await repo.ingest_alert(_alert())
        assert deduped is False
        assert case.status == CaseStatus.open

    async def test_second_alert_merges(self, db_session):
        repo = CaseRepository(db_session)
        first, _ = await repo.ingest_alert(_alert())
        second, deduped = await repo.ingest_alert(_alert())

        assert deduped is True
        assert second.case_id == first.case_id
        assert len(second.alerts) == 2

    async def test_alert_count_tracked(self, db_session):
        from app.db.models import CaseModel

        repo = CaseRepository(db_session)
        case, _ = await repo.ingest_alert(_alert())
        for _ in range(3):
            await repo.ingest_alert(_alert())

        model = await db_session.get(CaseModel, case.case_id)
        assert model.alert_count == 4

    async def test_different_host_creates_separate_case(self, db_session):
        repo = CaseRepository(db_session)
        a, _ = await repo.ingest_alert(_alert(hostname="web-01"))
        b, deduped = await repo.ingest_alert(_alert(hostname="web-02"))
        assert deduped is False
        assert a.case_id != b.case_id

    async def test_resolved_case_does_not_absorb(self, db_session):
        """已闭环的 Case 不能吸收新告警,否则归档证据被污染"""
        repo = CaseRepository(db_session)
        first, _ = await repo.ingest_alert(_alert())
        await repo.close(first.case_id, tttr_seconds=120)

        second, deduped = await repo.ingest_alert(_alert())
        assert deduped is False
        assert second.case_id != first.case_id

    async def test_stale_case_outside_window_not_reused(self, db_session):
        from app.db.models import CaseModel

        repo = CaseRepository(db_session)
        first, _ = await repo.ingest_alert(_alert())
        model = await db_session.get(CaseModel, first.case_id)
        model.updated_at = datetime.utcnow() - timedelta(minutes=120)
        await db_session.commit()

        second, deduped = await repo.ingest_alert(_alert())
        assert deduped is False
        assert second.case_id != first.case_id

    async def test_dedup_disabled_always_creates(self, db_session, monkeypatch):
        from app.core import config

        monkeypatch.setattr(config.settings, "enable_alert_dedup", False)
        repo = CaseRepository(db_session)
        first, _ = await repo.ingest_alert(_alert())
        second, deduped = await repo.ingest_alert(_alert())
        assert deduped is False
        assert second.case_id != first.case_id


class TestInjectEndpointAggregation:
    async def test_repeat_inject_merges_into_one_case(self, client):
        payload = {"alert_type": "xmrig_process", "hostname": "web-01", "src_ip": "10.0.0.5"}

        first = await client.post("/api/alerts/inject", json=payload)
        assert first.status_code == 200
        first_data = first.json()["data"]
        assert first_data["deduped"] is False

        second = await client.post("/api/alerts/inject", json=payload)
        second_data = second.json()["data"]
        assert second_data["deduped"] is True
        assert second_data["case_id"] == first_data["case_id"]
        assert second_data["alert_count"] == 2

    async def test_merged_alert_does_not_retrigger_workflow(self, client, monkeypatch):
        """聚合命中必须跳过编排,否则重复生成处置动作"""
        calls: list = []

        from app.api import alerts as alerts_api

        async def _spy(case_id, playbook_id=None):
            calls.append(case_id)

        monkeypatch.setattr(alerts_api, "trigger_workflow", _spy)
        payload = {"alert_type": "xmrig_process", "hostname": "web-09", "src_ip": "10.0.0.9"}
        await client.post("/api/alerts/inject", json=payload)
        await client.post("/api/alerts/inject", json=payload)

        assert len(calls) == 1

    async def test_different_hosts_create_two_cases(self, client):
        a = await client.post(
            "/api/alerts/inject",
            json={"alert_type": "xmrig_process", "hostname": "h-a", "src_ip": "10.0.0.1"},
        )
        b = await client.post(
            "/api/alerts/inject",
            json={"alert_type": "xmrig_process", "hostname": "h-b", "src_ip": "10.0.0.2"},
        )
        assert a.json()["data"]["case_id"] != b.json()["data"]["case_id"]


class TestDedupMetric:
    async def test_metric_incremented_on_merge(self, client):
        from app.core.metrics import ALERTS_DEDUPED_TOTAL

        def _value() -> float:
            total = 0.0
            for metric in ALERTS_DEDUPED_TOTAL.collect():
                for sample in metric.samples:
                    if sample.name.endswith("_total"):
                        total += sample.value
            return total

        before = _value()
        payload = {"alert_type": "xmrig_process", "hostname": "m-1", "src_ip": "10.0.1.1"}
        await client.post("/api/alerts/inject", json=payload)
        await client.post("/api/alerts/inject", json=payload)
        assert _value() > before

    async def test_metric_exposed(self, client):
        resp = await client.get("/metrics")
        assert "secsight_alerts_deduped_total" in resp.text
