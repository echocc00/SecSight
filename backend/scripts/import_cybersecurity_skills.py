"""Anthropic Cybersecurity Skills 导入脚本 (L1 战术层补充)

V2 已核实: mukul975/Anthropic-Cybersecurity-Skills
  30628⭐, Apache-2.0, 817 结构化安全技能, 映射 6 框架 (MITRE ATT&CK/NIST CSF 等)

此脚本将社区技能导入 SecSight L1 战术知识层,供 RAG 召回。

用法:
  git clone https://github.com/mukul975/Anthropic-Cybersecurity-Skills.git /tmp/acs
  PYTHONPATH=. python scripts/import_cybersecurity_skills.py /tmp/acs

技能映射: 每个技能的 MITRE ATT&CK technique → SecSight L1 战术 YAML
"""
from __future__ import annotations

import json
import os
import pathlib
import sys

import yaml

import structlog

log = structlog.get_logger()

# SecSight L1 战术层目录
L1_DIR = pathlib.Path(__file__).resolve().parents[2] / "knowledge" / "L1_tactic"


def parse_skill(skill_path: pathlib.Path) -> dict | None:
    """解析单个技能 (SKILL.md frontmatter + 内容)"""
    try:
        content = skill_path.read_text(encoding="utf-8")
    except Exception:
        return None

    # 简化的 frontmatter 解析
    if not content.startswith("---"):
        return None

    parts = content.split("---", 2)
    if len(parts) < 3:
        return None

    frontmatter_text = parts[1].strip()
    body = parts[2].strip()

    try:
        frontmatter = yaml.safe_load(frontmatter_text) or {}
    except Exception:
        return None

    return {
        "name": frontmatter.get("name", skill_path.stem),
        "description": frontmatter.get("description", ""),
        "mitre_techniques": frontmatter.get("mitre_techniques", []),
        "mitre_tactics": frontmatter.get("mitre_tactics", []),
        "body": body[:500],  # 截断,完整内容入库时再读
        "source": "anthropic_cybersecurity_skills",
    }


def import_skills(repo_path: str, max_skills: int = 50) -> dict:
    """导入技能到 L1 战术层

    repo_path: 克隆的 Anthropic-Cybersecurity-Skills 仓库路径
    max_skills: 最大导入数 (避免一次性太多,默认 50)
    """
    repo = pathlib.Path(repo_path)
    if not repo.exists():
        raise FileNotFoundError(f"仓库不存在: {repo_path}")

    # 技能文件模式: */SKILL.md 或 */*.md
    skill_files: list[pathlib.Path] = []
    for pattern in ["**/SKILL.md", "**/skill.md"]:
        skill_files.extend(repo.glob(pattern))

    if not skill_files:
        # 退化: 找所有 .md
        skill_files = list(repo.glob("**/*.md"))[:max_skills]

    imported: list[dict] = []
    skipped = 0
    for sf in skill_files[:max_skills]:
        skill = parse_skill(sf)
        if not skill or not skill.get("mitre_techniques"):
            skipped += 1
            continue
        imported.append(skill)

    # 写入 L1 汇总文件
    output = L1_DIR / "anthropic_skills_imported.yaml"
    L1_DIR.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8") as f:
        yaml.safe_dump(
            {
                "source": "mukul975/Anthropic-Cybersecurity-Skills",
                "license": "Apache-2.0",
                "imported_count": len(imported),
                "skills": imported,
            },
            f,
            allow_unicode=True,
        )

    log.info("skills.imported", count=len(imported), skipped=skipped, output=str(output))
    return {
        "imported": len(imported),
        "skipped": skipped,
        "total_scanned": len(skill_files),
        "output": str(output),
    }


def main() -> int:
    if len(sys.argv) < 2:
        print("用法: python import_cybersecurity_skills.py <repo_path> [max_skills]")
        print("  repo_path: 克隆的 mukul975/Anthropic-Cybersecurity-Skills 路径")
        return 1

    repo = sys.argv[1]
    max_skills = int(sys.argv[2]) if len(sys.argv) > 2 else 50

    try:
        result = import_skills(repo, max_skills=max_skills)
        print(f"\n导入完成:")
        print(f"  扫描: {result['total_scanned']}")
        print(f"  导入: {result['imported']}")
        print(f"  跳过: {result['skipped']}")
        print(f"  输出: {result['output']}")
        return 0
    except Exception as e:
        print(f"导入失败: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
