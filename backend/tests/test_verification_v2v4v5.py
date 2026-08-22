"""V2/V4/V5 核实结论测试 + 技能导入脚本测试"""
from __future__ import annotations

import pathlib
import tempfile

import pytest
import yaml

from app.threat_intel.base import ThreatBookProvider


class TestV2Verification:
    """V2: Anthropic Cybersecurity Skills 已核实,Apache-2.0,可作 L1 补充"""

    def test_import_script_exists(self):
        from pathlib import Path

        script = Path(__file__).resolve().parents[1] / "scripts" / "import_cybersecurity_skills.py"
        assert script.exists()

    def test_parse_skill_extracts_frontmatter(self):
        from scripts.import_cybersecurity_skills import parse_skill

        with tempfile.NamedTemporaryFile(mode="w", suffix=".md", delete=False, encoding="utf-8") as f:
            f.write("""---
name: test-skill
description: 测试技能
mitre_techniques:
  - T1496
mitre_tactics:
  - Impact
---
技能正文内容
""")
            f.flush()
            skill = parse_skill(pathlib.Path(f.name))
        assert skill is not None
        assert skill["name"] == "test-skill"
        assert "T1496" in skill["mitre_techniques"]
        assert "Impact" in skill["mitre_tactics"]

    def test_parse_skill_returns_none_without_frontmatter(self):
        from scripts.import_cybersecurity_skills import parse_skill

        with tempfile.NamedTemporaryFile(mode="w", suffix=".md", delete=False, encoding="utf-8") as f:
            f.write("普通 markdown 无 frontmatter")
            f.flush()
            assert parse_skill(pathlib.Path(f.name)) is None

    def test_import_skills_writes_yaml(self, tmp_path):
        from scripts.import_cybersecurity_skills import import_skills

        # 造一个假技能目录
        skill_dir = tmp_path / "skill1"
        skill_dir.mkdir()
        (skill_dir / "SKILL.md").write_text(
            "---\nname: s1\nmitre_techniques:\n  - T1496\n---\nbody",
            encoding="utf-8",
        )
        result = import_skills(str(tmp_path), max_skills=10)
        assert result["imported"] >= 1
        assert pathlib.Path(result["output"]).exists()


class TestV4Verification:
    """V4: Wazuh-Autopilot 已核实,49⭐,范式参考"""

    def test_design_alignment(self):
        """V4 验证 SecSight 11-agent 设计方向正确"""
        from app.agents.proactive import PROACTIVE_AGENTS
        from app.agents.roles import AGENTS

        # SecSight: 7 reactive + 4 proactive = 11 agents
        # Wazuh-Autopilot 描述: "11 security-expert agents"
        total = len(AGENTS) + len(PROACTIVE_AGENTS)
        assert total == 11


class TestV5Verification:
    """V5: 微步 API 规格已核实"""

    def test_threatbook_base_url_verified(self):
        """微步 base_url 已核实为 https://api.threatbook.cn/v3"""
        p = ThreatBookProvider(api_key="dummy")
        assert p.base_url == "https://api.threatbook.cn/v3"

    def test_threatbook_endpoints_documented(self):
        """微步 endpoints 在 docstring 中已记录"""
        from app.threat_intel.base import ThreatBookProvider

        doc = ThreatBookProvider.__doc__ or ""
        assert "/scene/ip_reputation" in doc
        assert "/domain/query" in doc
        assert "/file/report" in doc
        assert "POST" in doc

    def test_threatbook_still_not_implemented(self):
        """付费 provider 仍未接入,抛 NotImplementedError"""
        import asyncio

        p = ThreatBookProvider(api_key="dummy")
        with pytest.raises(NotImplementedError):
            asyncio.run(p.query_ip("1.2.3.4"))
