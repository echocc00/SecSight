"""合规报告测试 — 生成 HTML/Markdown"""
from __future__ import annotations

import pytest


class TestReportGeneration:
    @pytest.mark.asyncio
    async def test_generate_html_report(self, client):
        # 先注入一个告警建 Case
        r = await client.post("/api/alerts/inject", json={"alert_type": "xmrig_process"})
        case_id = r.json()["data"]["case_id"]

        # 生成报告
        r = await client.post(f"/api/compliance/{case_id}/report?format=html")
        assert r.status_code == 200
        data = r.json()
        assert data["case_id"] == case_id
        assert data["format"] == "html"
        assert "<html" in data["content"]
        assert "等保" in data["content"]

    @pytest.mark.asyncio
    async def test_generate_markdown_report(self, client):
        r = await client.post("/api/alerts/inject", json={"alert_type": "xmrig_process"})
        case_id = r.json()["data"]["case_id"]

        r = await client.post(f"/api/compliance/{case_id}/report?format=markdown")
        assert r.status_code == 200
        data = r.json()
        assert data["format"] == "markdown"
        assert "# 等保" in data["content"]
        assert case_id in data["content"]

    @pytest.mark.asyncio
    async def test_get_html_report_endpoint(self, client):
        r = await client.post("/api/alerts/inject", json={"alert_type": "xmrig_process"})
        case_id = r.json()["data"]["case_id"]

        r = await client.get(f"/api/compliance/{case_id}/report")
        assert r.status_code == 200
        assert "<html" in r.text

    @pytest.mark.asyncio
    async def test_report_404_for_unknown_case(self, client):
        r = await client.post("/api/compliance/no-such-case/report")
        assert r.status_code == 404

    @pytest.mark.asyncio
    async def test_report_contains_judgment_and_actions(self, client):
        r = await client.post("/api/alerts/inject", json={"alert_type": "xmrig_process"})
        case_id = r.json()["data"]["case_id"]

        r = await client.post(f"/api/compliance/{case_id}/report?format=markdown")
        content = r.json()["content"]
        # 研判内容应在报告中
        assert "T1496" in content or "xmrig" in content
        # 处置动作应出现
        assert "isolate_host" in content or "动作" in content
