"""剧本加载器 — 从 YAML 文件加载剧本"""
from __future__ import annotations

from pathlib import Path

import yaml

from app.playbooks.models import Playbook


def load_all(playbooks_dir: str) -> list[Playbook]:
    """加载目录下所有 .yaml 剧本"""
    path = Path(playbooks_dir)
    if not path.exists():
        return []
    playbooks: list[Playbook] = []
    for yml_file in sorted(path.rglob("*.yaml")):
        with open(yml_file, encoding="utf-8") as f:
            data = yaml.safe_load(f)
        if data:
            playbooks.append(Playbook(**data))
    return playbooks


def load_one(yaml_path: str) -> Playbook:
    with open(yaml_path, encoding="utf-8") as f:
        data = yaml.safe_load(f)
    return Playbook(**data)
