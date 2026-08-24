"""知识反向注入测试 — L3 案例 → L1 战术 + 检测规则生成"""
from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
import yaml

from app.db.repositories import CaseRepository
from app.knowledge.sediment import (
    build_case_chunk,
    build_l1_injection,
    extract_case_knowledge,
    generate_detection_rules,
    sediment_case,
    vectorize_to_qdrant,
    write_l1_yaml,
)
from app.mock.alerts import xmrig_process_alert
from app.models.schemas import JudgmentReport, Severity


async def _build_resolved_case(db_session) -> str:
    """建一个带 judgment 的 resolved Case"""
    repo = CaseRepository(db_session)
    case = await repo.create_from_alert(xmrig_process_alert())
    case.judgment = JudgmentReport(
        incident_summary="xmrig 挖矿",
        severity=Severity.high,
        ttps=["T1496", "T1071.001"],
        confidence=0.88,
        rationale="进程名 xmrig + stratum 命令行 + 矿池连接,三重证据确认挖矿行为",
    )
    await repo.update_judgment(case.case_id, case.judgment)
    return case.case_id


class TestExtractCaseKnowledge:
    @pytest.mark.asyncio
    async def test_extracts_ttps_and_iocs(self, db_session):
        case_id = await _build_resolved_case(db_session)
        repo = CaseRepository(db_session)
        case = await repo.get(case_id)

        knowledge = extract_case_knowledge(case)
        assert "T1496" in knowledge["ttps"]
        assert knowledge["severity"] == "high"
        assert knowledge["confidence"] == 0.88
        # IoCs 从告警提取
        assert "10.0.1.15" in knowledge["iocs"]["ips"]
        assert "xmrig" in knowledge["iocs"]["processes"]

    @pytest.mark.asyncio
    async def test_extracts_action_summary(self, db_session):
        case_id = await _build_resolved_case(db_session)
        repo = CaseRepository(db_session)
        case = await repo.get(case_id)

        knowledge = extract_case_knowledge(case)
        assert "actions" in knowledge
        assert "executions" in knowledge
        assert "extracted_at" in knowledge


class TestGenerateDetectionRules:
    def test_generates_rules_per_ttp(self):
        knowledge = {
            "case_id": "test-123",
            "ttps": ["T1496", "T1071.001"],
            "iocs": {"ips": ["1.2.3.4"], "processes": ["xmrig"], "domains": [], "hashes": []},
        }
        rules = generate_detection_rules(knowledge)
        # 2 TTP 规则 + 1 IP 规则 + 1 进程规则
        assert len(rules) >= 2
        ttp_rule_titles = [r["title"] for r in rules if "T1496" in r.get("title", "")]
        assert any("T1496" in t for t in ttp_rule_titles)

    def test_rule_has_detection_condition(self):
        knowledge = {
            "case_id": "x",
            "ttps": ["T1496"],
            "iocs": {"ips": [], "processes": [], "domains": [], "hashes": []},
        }
        rules = generate_detection_rules(knowledge)
        assert rules[0]["detection"]["condition"] == "selection"

    def test_ioc_based_rules(self):
        knowledge = {
            "case_id": "x",
            "ttps": [],
            "iocs": {"ips": ["1.2.3.4"], "processes": ["evil.exe"], "domains": [], "hashes": []},
        }
        rules = generate_detection_rules(knowledge)
        # 无 TTP 但有 IoC → 生成 IoC 规则
        assert any("恶意 IP" in r["title"] for r in rules)
        assert any("恶意进程" in r["title"] for r in rules)

    def test_ttp_specific_detection_fields(self):
        knowledge = {
            "case_id": "x",
            "ttps": ["T1496"],
            "iocs": {"ips": [], "processes": [], "domains": [], "hashes": []},
        }
        rules = generate_detection_rules(knowledge)
        # T1496 → 检测 xmrig/minerd 进程名
        selection = rules[0]["detection"]["selection"]
        assert "process_name" in selection


class TestL1Injection:
    def test_builds_injection_package(self):
        knowledge = {
            "case_id": "c1",
            "playbook_id": "pb_cryptominer_v1",
            "ttps": ["T1496"],
            "iocs": {"ips": ["1.2.3.4"]},
            "rationale": "挖矿依据",
            "tttr_seconds": 60,
        }
        rules = [{"rule_id": "r1"}, {"rule_id": "r2"}]
        injection = build_l1_injection(knowledge, rules)
        assert injection["target_layer"] == "L1_tactic"
        assert injection["playbook_id"] == "pb_cryptominer_v1"
        assert injection["new_rules"] == ["r1", "r2"]
        assert injection["ttps_covered"] == ["T1496"]


class TestSedimentCase:
    @pytest.mark.asyncio
    async def test_full_sediment_pipeline(self, db_session):
        case_id = await _build_resolved_case(db_session)
        result = await sediment_case(case_id)
        assert result["case_id"] == case_id
        assert "T1496" in result["knowledge"]["ttps"]
        assert len(result["generated_rules"]) > 0
        assert result["l1_injection"]["target_layer"] == "L1_tactic"
        # 新增: L1 YAML 写入 + Qdrant 计数
        assert result["l1_yaml_path"] is not None
        assert Path(result["l1_yaml_path"]).exists()
        assert result["qdrant_points"] == 0  # enable_qdrant=false

    @pytest.mark.asyncio
    async def test_sediment_unknown_case_raises(self):
        with pytest.raises(ValueError, match="not found"):
            await sediment_case("nonexistent-case")

    @pytest.mark.asyncio
    async def test_sediment_writes_l1_yaml_with_rules(self, db_session):
        case_id = await _build_resolved_case(db_session)
        result = await sediment_case(case_id)
        path = result["l1_yaml_path"]
        assert path and os.path.exists(path)
        with open(path, encoding="utf-8") as f:
            doc = yaml.safe_load(f)
        assert doc["source_case"] == case_id
        assert doc["auto_generated"] is True
        assert len(doc["detection_rules"]) == len(result["generated_rules"])
        assert "T1496" in doc["ttps_covered"]

    @pytest.mark.asyncio
    async def test_sediment_is_idempotent_on_rewrite(self, db_session):
        case_id = await _build_resolved_case(db_session)
        r1 = await sediment_case(case_id)
        r2 = await sediment_case(case_id)
        # 同一 case 重写覆盖,路径不变
        assert r1["l1_yaml_path"] == r2["l1_yaml_path"]

    @pytest.mark.asyncio
    async def test_sediment_qdrant_ingest_when_enabled(self, db_session, monkeypatch):
        case_id = await _build_resolved_case(db_session)
        # 模拟 enable_qdrant=true + QdrantRetriever.ingest_knowledge 成功
        from app.core.config import settings

        monkeypatch.setattr(settings, "enable_qdrant", True)
        fake_retriever = AsyncMock()
        fake_retriever.ingest_knowledge = AsyncMock(return_value=1)
        with patch(
            "app.retrieval.qdrant_retriever.QdrantRetriever",
            return_value=fake_retriever,
        ):
            result = await sediment_case(case_id)
        assert result["qdrant_points"] == 1
        fake_retriever.ingest_knowledge.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_sediment_qdrant_failure_does_not_break(self, db_session, monkeypatch):
        case_id = await _build_resolved_case(db_session)
        from app.core.config import settings

        monkeypatch.setattr(settings, "enable_qdrant", True)
        with patch(
            "app.retrieval.qdrant_retriever.QdrantRetriever",
            side_effect=RuntimeError("qdrant down"),
        ):
            result = await sediment_case(case_id)
        # Qdrant 失败不阻塞,仍返回结果
        assert result["qdrant_points"] == 0
        assert result["l1_yaml_path"] is not None


class TestVectorizeToQdrant:
    @pytest.mark.asyncio
    async def test_skipped_when_disabled(self, monkeypatch):
        from app.core.config import settings

        monkeypatch.setattr(settings, "enable_qdrant", False)
        knowledge = {"case_id": "c1", "ttps": ["T1496"], "iocs": {}}
        count = await vectorize_to_qdrant(knowledge)
        assert count == 0


class TestCaseChunk:
    def test_builds_chunk_with_text_fields(self):
        knowledge = {
            "case_id": "abc-123",
            "playbook_id": "pb_x",
            "ttps": ["T1496"],
            "severity": "high",
            "confidence": 0.9,
            "iocs": {"ips": ["1.2.3.4"]},
            "rationale": "挖矿",
            "actions": [],
            "tttr_seconds": 30,
            "extracted_at": "2026-01-01T00:00:00",
        }
        chunk = build_case_chunk(knowledge)
        assert chunk["id"] == "case:abc-123"
        assert chunk["type"] == "case"
        assert chunk["ttps"] == ["T1496"]
        # name/description 供 embedding 使用
        assert "abc" in chunk["name"]
        assert "T1496" in chunk["description"]


class TestWriteL1Yaml:
    def test_writes_valid_yaml(self, tmp_path, monkeypatch):
        from app.knowledge import sediment

        monkeypatch.setattr(sediment, "_L1_ROOT", tmp_path)
        knowledge = {
            "case_id": "case-xyz-12345678",
            "playbook_id": "pb_cryptominer_v1",
            "ttps": ["T1496"],
            "rationale": "依据",
            "iocs": {"ips": ["1.2.3.4"]},
        }
        rules = [{"rule_id": "r1", "title": "t", "status": "experimental", "detection": {"condition": "selection"}, "mitre": {"id": ["T1496"]}}]
        path = write_l1_yaml(knowledge, rules)
        assert path and Path(path).exists()
        with open(path, encoding="utf-8") as f:
            doc = yaml.safe_load(f)
        assert doc["detection_rules"][0]["rule_id"] == "r1"


class TestSedimentAPI:
    @pytest.mark.asyncio
    async def test_sediment_endpoint(self, client):
        # 先注入告警建 Case
        r = await client.post("/api/alerts/inject", json={"alert_type": "xmrig_process"})
        case_id = r.json()["data"]["case_id"]

        r = await client.post(f"/api/knowledge/{case_id}/sediment")
        assert r.status_code == 200
        data = r.json()["data"]
        assert data["case_id"] == case_id
        assert data["rules_generated"] > 0
        assert "T1496" in data["ttps"]

    @pytest.mark.asyncio
    async def test_sediment_unknown_case_404(self, client):
        r = await client.post("/api/knowledge/no-such-case/sediment")
        assert r.status_code == 404
