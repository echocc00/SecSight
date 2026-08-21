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
        """匹配剧本: 命中任一 trigger 即候选,按 priority 选最优"""
        candidates = [pb for pb in self.playbooks if self._match_triggers(alert, pb)]
        if not candidates:
            return None
        return sorted(candidates, key=lambda p: _PRIORITY_ORDER.get(p.priority, 9))[0]

    def get_by_id(self, playbook_id: str) -> Playbook | None:
        for pb in self.playbooks:
            if pb.id == playbook_id:
                return pb
        return None

    def _match_triggers(self, alert: Alert, playbook: Playbook) -> bool:
        triggers = playbook.triggers
        # Wazuh rule ID 匹配
        if str(alert.rule_id) in triggers.wazuh_rules:
            return True
        # Sigma rule 匹配 (alert.raw 里可能带 sigma_id)
        sigma_id = alert.raw.get("sigma_id", "")
        if sigma_id and sigma_id in triggers.sigma_rules:
            return True
        # 进程名/命令行模式匹配 (挖矿等)
        if triggers.process_patterns:
            names = triggers.process_patterns.get("names", [])
            cmdline_contains = triggers.process_patterns.get("cmdline_contains", [])
            message = (alert.message or "").lower()
            raw_str = str(alert.raw).lower()
            for name in names:
                if name.lower() in raw_str or name.lower() in message:
                    return True
            for pattern in cmdline_contains:
                if pattern.lower() in raw_str:
                    return True
        # 网络模式匹配 (矿池端口/域名)
        if triggers.network:
            pool_ports = triggers.network.get("pool_ports", [])
            if alert.dst_ip and any(
                str(port) in str(alert.raw.get("dst_port", "")) for port in pool_ports
            ):
                return True
        # indicators (文件后缀/命令)
        if triggers.indicators:
            commands = triggers.indicators.get("commands", [])
            raw_str = str(alert.raw).lower()
            for cmd in commands:
                if cmd.lower() in raw_str:
                    return True
        return False


# 单例 (playbooks 目录: 优先环境变量,默认相对 backend 的 ../playbooks)
import os
import pathlib

_PLAYBOOKS_DIR = os.environ.get(
    "PLAYBOOKS_DIR",
    str(pathlib.Path(__file__).resolve().parents[3] / "playbooks"),
)
engine = PlaybookEngine(_PLAYBOOKS_DIR)
