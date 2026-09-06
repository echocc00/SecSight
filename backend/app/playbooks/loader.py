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


def validate_playbooks(playbooks: list[Playbook]) -> list[str]:
    """剧本配置校验 —— 不静默漏签

    返回 warning 列表 (不阻塞启动,但必须显式看到):
      - L2 动作若 YAML 漏写 approval 字段,会退化为单签。
        critical (隔离/封禁) 动作已在 build_action_from_config 强制三签兜底;
        这里仍然列出,提醒补上 YAML 声明。
    """
    from app.approvals.service import CRITICAL_ACTIONS

    warnings: list[str] = []
    for pb in playbooks:
        for action in pb.containment_actions:
            if action.autonomy != "L2":
                continue
            if action.approval in ("", "none"):
                warnings.append(
                    f"playbook {pb.id}: L2 动作 '{action.id}' ({action.action_type or '?'}) "
                    f"未声明 approval 字段,当前按单签处理"
                )
            elif action.action_type in CRITICAL_ACTIONS and action.approval != "double":
                warnings.append(
                    f"playbook {pb.id}: 高危动作 '{action.id}' ({action.action_type}) "
                    f"approval={action.approval},应显式 double (已由代码强制三签兜底)"
                )
    return warnings
