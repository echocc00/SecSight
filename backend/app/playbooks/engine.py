"""剧本匹配引擎 — 告警 → 剧本"""
from __future__ import annotations

from app.models.schemas import Alert
from app.playbooks.loader import load_all
from app.playbooks.models import Playbook

_PRIORITY_ORDER = {"P0": 0, "P1": 1, "P2": 2}


class PlaybookEngine:
    def __init__(self, playbooks_dir: str) -> None:
        self.playbooks: list[Playbook] = load_all(playbooks_dir)

    def match(self, alert: Alert) -> Playbook | None:
        """评分匹配: 命中 trigger 计分,选最高分剧本。

        评分权重 (越具体越高):
          sigma_id 精确匹配 = 10
          进程名/命令行模式 = 8
          indicators 命令 = 6
          网络模式 = 5
          wazuh rule (泛化,易误配) = 2
        """
        scored: list[tuple[int, Playbook]] = []
        for pb in self.playbooks:
            score = self._score(alert, pb)
            if score > 0:
                scored.append((score, pb))
        if not scored:
            return None
        # 同分时按 priority (P0 优先),再按加载顺序稳定
        scored.sort(key=lambda x: (-x[0], _PRIORITY_ORDER.get(x[1].priority, 9)))
        return scored[0][1]

    def get_by_id(self, playbook_id: str) -> Playbook | None:
        for pb in self.playbooks:
            if pb.id == playbook_id:
                return pb
        return None

    def _score(self, alert: Alert, playbook: Playbook) -> int:
        triggers = playbook.triggers
        score = 0
        raw_str = str(alert.raw).lower()
        message = (alert.message or "").lower()

        # sigma_id 精确匹配 (最具体)
        sigma_id = alert.raw.get("sigma_id", "")
        if sigma_id and sigma_id in triggers.sigma_rules:
            score += 10
        # 进程名/命令行模式
        if triggers.process_patterns:
            names = triggers.process_patterns.get("names", [])
            cmdline_contains = triggers.process_patterns.get("cmdline_contains", [])
            for name in names:
                if name.lower() in raw_str or name.lower() in message:
                    score += 8
            for pattern in cmdline_contains:
                if pattern.lower() in raw_str:
                    score += 8
        # indicators 命令/后缀
        if triggers.indicators:
            commands = triggers.indicators.get("commands", [])
            for cmd in commands:
                if cmd.lower() in raw_str:
                    score += 6
        # 网络模式
        if triggers.network:
            pool_ports = triggers.network.get("pool_ports", [])
            if alert.dst_ip and any(
                str(port) in str(alert.raw.get("dst_port", "")) for port in pool_ports
            ):
                score += 5
        # wazuh rule (泛化,低权重)
        if str(alert.rule_id) in triggers.wazuh_rules:
            score += 2
        return score


# 单例 (playbooks 目录: 优先环境变量,默认相对 backend 的 ../playbooks)
import os
import pathlib

_PLAYBOOKS_DIR = os.environ.get(
    "PLAYBOOKS_DIR",
    str(pathlib.Path(__file__).resolve().parents[3] / "playbooks"),
)
engine = PlaybookEngine(_PLAYBOOKS_DIR)
