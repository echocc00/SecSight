"""剧本数据模型 (Pydantic,加载 YAML 后的结构)"""
from __future__ import annotations

from pydantic import BaseModel, Field


class TriggerConfig(BaseModel):
    sigma_rules: list[str] = Field(default_factory=list)
    suricata_rules: list[str] = Field(default_factory=list)
    wazuh_rules: list[str] = Field(default_factory=list)
    process_patterns: dict | None = None
    network: dict | None = None
    indicators: dict | None = None


class MitreMapping(BaseModel):
    tactics: list[str] = Field(default_factory=list)
    techniques: list[str] = Field(default_factory=list)


class InvestigationStep(BaseModel):
    id: str
    name: str
    description: str = ""
    tools: list[str] = Field(default_factory=list)
    autonomy: str = "L4"
    output: str = ""


class ContainmentActionConfig(BaseModel):
    id: str
    name: str
    action_type: str = ""  # 显式指定 ActionType 枚举值 (isolate_host/block_ip/kill_process...)
    autonomy: str = "L2"
    approval: str = "none"  # none | required | double
    risk: str = "medium"
    tools: list[str] = Field(default_factory=list)
    rollback: str | None = None
    parameters: dict = Field(default_factory=dict)
    deadline: str | None = None


class Playbook(BaseModel):
    id: str
    name: str
    category: str
    priority: str = "P1"  # P0 | P1 | P2
    phase: int = 1
    version: str = "1.0"
    autonomy_level_default: str = "L2"
    description: str = ""
    triggers: TriggerConfig = Field(default_factory=TriggerConfig)
    mitre_mapping: MitreMapping = Field(default_factory=MitreMapping)
    investigation_steps: list[InvestigationStep] = Field(default_factory=list)
    containment_actions: list[ContainmentActionConfig] = Field(default_factory=list)
    knowledge_assets: dict = Field(default_factory=dict)
