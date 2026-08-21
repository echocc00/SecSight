# SecSight Phase1 实施计划

> **版本**: v1.0
> **日期**: 2026-08-21
> **前置**: [03-selection-arbitration.md](03-selection-arbitration.md) v1.1 (选型已收敛)
> **目标**: 12 周内跑通 6 个 P0 剧本的最小闭环(采集→AI研判→L2审批→处置→知识沉淀)
> **范围**: 100 主机以内验证,TTTR < 10 分钟

---

## 0. Phase1 交付物总览

| # | 交付物 | 验收标准 |
|---|---|---|
| 1 | 基础设施 docker-compose | Wazuh+OpenSearch+Shuffle+LiteLLM+OpenCTI+DFIR-IRIS 六件套一键起 |
| 2 | 采集归一化管道 | Wazuh/Suricata 告警经 Vector→ECS→OpenSearch,可视化可查 |
| 3 | AI 编排骨架 | LangGraph StateGraph 3角色(Triage/Investigation/Containment)+ 5级自主性路由 |
| 4 | LLM 网关 | LiteLLM 接 DeepSeek/MiniMax,按任务路由,成本可统计 |
| 5 | 6 个剧本 YAML | 勒索/挖矿/持久化/暴破/日志合规/服务崩溃,含 autonomy_level 字段 |
| 6 | 知识库 L0+L1 | MITRE ATT&CK STIX 导入 + 7 类业务系统战术知识 |
| 7 | 情报层 | OpenCTI + 免费 provider(AbuseIPDB/OTX)+ 付费 provider 接口预留 |
| 8 | L2 审批闭环 | Shuffle User Input 节点 + 飞书/钉钉 webhook + 双签 |
| 9 | Evidence Pack | 每案件完整留痕,Dashboard 可视化 |
| 10 | 6 场景测试 | 可控样本跑通全链路 |

---

## 1. 技术栈落地清单(对应裁决 §4.1)

| 组件 | 版本 | 部署方式 | 资源 | License 隔离 |
|---|---|---|---|---|
| Wazuh | 4.x Manager+Indexer+Dashboard | docker-compose 独立栈 | 8C/16G | 独立进程,API 调用 |
| OpenSearch | 2.x | docker-compose | 4C/8G | 无 |
| Shuffle | latest | docker-compose 独立 | 2C/4G | **AGPL 隔离**,Webhook/REST |
| LiteLLM | 1.x | docker-compose | 1C/2G | 无 |
| OpenCTI | 6.x CE | docker-compose 独立 | 8C/16G | 无 |
| DFIR-IRIS | iris-web 2.4.x | docker-compose 独立 | 4C/8G | **LGPL,禁用 AGPL 模块** |
| Vector | 0.3x | docker-compose | 1C/1G | 无 |
| Suricata | 7.x | 旁路监听机 | 4C/8G | 无 |
| Qdrant | 1.x | docker-compose | 1C/2G | 无 |
| Postgres | 16 | docker-compose | 2C/4G | 无(案件/审计/checkpoint) |
| SecSight Backend | FastAPI | docker-compose | 2C/4G | 主体,可闭源 |
| SecSight Frontend | Vite+React+Antd | docker-compose/nginx | 1C/1G | 无 |

**最小硬件**: 单台 32C/64G/2TB 可跑全部(含 OpenCTI);或拆 2 台(控制面+数据面)。无 GPU 要求(云端 LLM)。

---

## 2. 12 周任务拆解

### W1-2: 基础设施 + LLM 网关

| 任务 | 产出 |
|---|---|
| 编写 `deploy/docker-compose.yml` | 12 服务一键起 |
| 部署 Wazuh 栈(Manager/Indexer/Dashboard) | 100 Agent 可注册 |
| 部署 OpenSearch + Vector | 日志可入可查 |
| 部署 Shuffle(独立网络隔离) | Workflow 可触发 |
| 部署 LiteLLM + 接 DeepSeek/MiniMax API | `/v1/chat/completions` 可调通 |
| 部署 OpenCTI + 导入 MITRE ATT&CK connector | 关系图可查 |
| 部署 DFIR-IRIS(仅主本体,不装 AGPL 模块) | 案件可建 |
| 部署 Qdrant + Postgres | 向量库/关系库就绪 |
| 配置 `.env.example` | 所有密钥占位 |

**验收**: `docker compose up -d` 全绿;LiteLLM 调 DeepSeek 返回正常;OpenCTI 可查 ATT&CK T1486。

### W3-4: 采集归一化 + 编排骨架

| 任务 | 产出 |
|---|---|
| Vector pipeline: Wazuh alerts.json → ECS → OpenSearch | 告警入库,字段统一 |
| Vector pipeline: Suricata eve.json → ECS → OpenSearch | 网络告警入库 |
| 国产设备 syslog → Vector → ECS(预留适配器) | 统一接入点 |
| FastAPI 后端骨架 + 配置/安全/日志 | API 可访问 |
| LangGraph StateGraph 骨架(3角色节点) | 状态机可跑 |
| MCP server: wazuh_mcp(查询告警/active response) | 工具可调 |
| Tier1 分诊 Agent(基于规则严重性 + LLM 摘要) | 告警→Case 生成 |

**验收**: 模拟一条 Wazuh 告警 → 自动生成 Case + MITRE 映射 + 严重性评级。

### W5-7: 6 剧本 + 知识库 L0/L1

| 任务 | 产出 |
|---|---|
| 编写 6 个剧本 YAML(含 autonomy_level) | `playbooks/phase1/*.yaml` |
| L0 框架层: MITRE ATT&CK STIX 导入脚本 | `knowledge/L0_framework/` |
| L1 战术层: 7 类业务系统知识 YAML | `knowledge/L1_tactic/` |
| 剧本匹配引擎(告警特征 → 剧本 ID) | 可路由到正确剧本 |
| RAG: Qdrant 向量化 L0/L1 知识 + BGE-m3 embedding | 知识可检索 |
| LiteLLM 路由配置(分诊=MiniMax/推理=DeepSeek) | 按任务选模型 |

**验收**: 输入"xmrig 进程"告警 → 匹配 cryptominer 剧本 → RAG 召回 T1496 知识。

### W8-9: Tier2 调查 + 情报层

| 任务 | 产出 |
|---|---|
| Tier2 调查 Agent(pivot 查询 + LLM 推理) | 根因分析输出 |
| `ThreatIntelProvider` 抽象接口 | `backend/app/threat_intel/base.py` |
| 免费 provider: AbuseIPDB + OTX + MISP社区 | IoC 可富化 |
| 付费 provider 适配器(仅类定义,不实现) | 接口预留 |
| 置信度合成器(多源交叉验证) | confidence 计算 |
| OpenCTI GraphQL 集成(IoC→TTP→ThreatActor) | 关系图富化 |
| MCP server: opencti_mcp / threat_intel_mcp | 工具可调 |

**验收**: 告警 IoC → 多源富化 → 输出 confidence + ATT&CK TTP + 处置建议。

### W10-11: 审批闭环 + Containment

| 任务 | 产出 |
|---|---|
| Shuffle Workflow 模板(6 剧本各一个) | User Input 审批节点 |
| 飞书/钉钉 webhook App | 审批通知可推送 |
| L2 双签 UI(Incident Commander + Approver) | 双人确认 |
| Containment Agent(隔离/封禁/kill,仅生成 Plan) | Plan 可审计 |
| Shuffle 执行适配器(Plan → Shuffle Action) | 处置可执行 |
| Evidence Pack 生成 + Postgres 归档 | 完整留痕 |
| Web Dashboard(Case 详情 + 时间线 + 审批) | 可视化 |

**验收**: 高危告警 → 飞书推送 → 双签审批 → Shuffle 执行隔离 → Evidence Pack 归档。

### W12: 6 场景测试 + 文档

| 场景 | 测试方法 | 预期 TTTR |
|---|---|---|
| 勒索病毒 | 可控 VM 批量改文件后缀(无真实加密) | < 5 min(含审批) |
| 挖矿 | xmrig + 矿池 mock | < 5 min |
| 持久化 | 模拟可疑 crontab + 进程创建 | < 3 min |
| 暴力破解 | SSH 撞库脚本 | < 3 min |
| 日志合规 | 故意停日志写入 | < 2 min |
| 服务崩溃 | kill -9 关键服务 | < 2 min |

| 文档 | 产出 |
|---|---|
| README + 部署文档 | 可复现安装 |
| demo 视频 | 6 场景链路展示 |
| Phase1 评审报告 | 完成度 + 问题 + Phase2 建议 |

---

## 3. 核心数据结构(接口契约)

### 3.1 统一告警(Alert) — ECS 子集

```python
class Alert(BaseModel):
    alert_id: str                    # uuid
    ts: datetime                     # ISO8601 UTC
    source: str                      # wazuh|suricata|sysmon|firewall|custom
    rule_id: str
    rule_level: int                  # 0-15 (Wazuh) 或 severity (Suricata)
    severity: Literal["low","medium","high","critical"]
    src_ip: str | None
    dst_ip: str | None
    user: str | None
    asset: AssetRef
    raw: dict                        # 原始 payload
    mitre_tactics: list[str] = []
    mitre_techniques: list[str] = []
```

### 3.2 案件(Case)

```python
class Case(BaseModel):
    case_id: str
    status: Literal["open","investigating","pending_approval","contained","resolved","closed"]
    alerts: list[Alert]
    playbook_id: str | None
    enriched_context: dict           # IoC/资产/身份富化结果
    judgment: JudgmentReport | None  # Tier2 输出
    proposed_actions: list[Action]   # Containment Plan
    approvals: dict[str, ApprovalRecord]
    execution_log: list[ExecutionStep]
    evidence_pack_id: str | None
    autonomy_level_default: Literal["L1","L2","L3","L4","L5"]
    created_at: datetime
    tttr_seconds: int | None         # 响应耗时
```

### 3.3 研判报告(JudgmentReport)

```python
class JudgmentReport(BaseModel):
    incident_summary: str = Field(max_length=200)
    severity: Literal["low","medium","high","critical"]
    ttps: list[str]                  # ATT&CK technique IDs (白名单,必须 RAG 召回)
    kill_chain_phase: str
    true_positive: Literal["yes","no","uncertain"]
    confidence: float = Field(ge=0, le=1)
    recommended_actions: list[str]   # action 类型枚举
    rationale: str = Field(min_length=20, max_length=500)
    citations: list[str]             # RAG 文档 ID
```

### 3.4 动作(Action) — 含自主性标注

```python
class Action(BaseModel):
    action_id: str
    action_type: Literal[
        "isolate_host","block_ip","block_domain","kill_process",
        "quarantine_file","freeze_account","notify","create_ticket",
        "query_asset","forensic_capture","report_regulator"
    ]
    target: dict                     # {ip/pid/host/account...}
    autonomy_level: Literal["L1","L2","L3","L4","L5"]
    risk: Literal["low","medium","high","critical"]
    approval_required: bool          # L2=True 双签
    requires_double_sign: bool       # 高危=True
    timeout_seconds: int = 300
    rollback_action_id: str | None   # 对偶回滚动作
```

### 3.5 剧本(Playbook) YAML schema

```yaml
id: pb_ransomware_v1
name: 勒索病毒加密文件应急响应
category: host
priority: P0
phase: 1
autonomy_level_default: L2

triggers:
  sigma_rules: [suspicious_mass_file_modification, ransomware_extension_creation]
  suricata_rules: [ET MALWARE Ransomware]
  wazuh_rules: [5710, 5711]

mitre_mapping:
  tactics: [TA0040 Impact]
  techniques: [T1486 Data Encrypted for Impact, T1490 Inhibit Recovery]

investigation_steps:
  - id: I1
    name: 进程白名单校验
    tools: [osquery_processes, virustotal_hash]
    autonomy: L4
  - id: I2
    name: 父子进程关系
    tools: [sysmon_parent_child]
    autonomy: L4

containment_actions:
  - id: A1_isolate_host
    autonomy: L2
    approval: double
    tools: [firewall_block_host, wazuh_active_response]
    rollback: A1_rollback
  - id: A7_report_regulator
    autonomy: L2
    approval: required
    deadline: 24h

knowledge_assets:
  iocs_db: [process_hashes, c2_ips, ransom_emails]
  ttps_db: [ransomware_family_techniques]
```

---

## 4. LangGraph StateGraph 设计

### 4.1 状态定义

```python
class SecSightState(TypedDict):
    case_id: str
    raw_alerts: list[dict]
    enriched_context: dict
    retrieved_knowledge: list[dict]      # RAG 结果
    judgment: dict | None                # JudgmentReport
    proposed_actions: list[dict]         # Action 列表
    approval_status: dict                # {action_id: pending|approved|rejected}
    execution_log: list[dict]
    current_playbook_id: str | None
```

### 4.2 节点与边

```
ingest_alerts ──> retrieve_knowledge ──> analyze(Tier1+Tier2)
                                            │
                                            ▼
                                      plan_actions(IR Lead/Containment)
                                            │
                              ┌─────────────┴──────────────┐
                              │ autonomy_level?            │
                              ├─ L1/L5 ──> execute(只读/自动)
                              ├─ L3/L4 ──> execute + 异步审计
                              └─ L2 ──> human_approve(interrupt_before)
                                            │
                                  ┌─────────┴─────────┐
                                  │ approved?         │
                                  ├─ yes ──> execute
                                  └─ no/timeout ──> escalate
                                            │
                                            ▼
                                      update_case + evidence_pack ──> END
```

### 4.3 关键: L2 审批 gate 用 interrupt_before

```python
workflow.add_node("plan_actions", plan_actions_node)
workflow.add_node("human_approve", human_approve_node)
workflow.add_node("execute", execute_node)

# L2 动作在执行前中断,等待人工
workflow.add_edge("plan_actions", "human_approve")
workflow.add_conditional_edges(
    "human_approve",
    lambda s: "execute" if all_approved(s) else "escalate",
)
```

---

## 5. ThreatIntelProvider 抽象(对应裁决 §3.5.1)

```python
class ThreatIntelProvider(ABC):
    @abstractmethod
    def query_ip(self, ip: str) -> IntelResult: ...
    @abstractmethod
    def query_domain(self, domain: str) -> IntelResult: ...
    @abstractmethod
    def query_file_hash(self, hash: str) -> IntelResult: ...
    @abstractmethod
    def query_url(self, url: str) -> IntelResult: ...

# Phase1 实现(免费)
class AbuseIPDBProvider(ThreatIntelProvider): ...
class OTXProvider(ThreatIntelProvider): ...
class MISPCommunityProvider(ThreatIntelProvider): ...

# 预留(仅类定义,不实现,很长一段时间不接入)
class ThreatBookProvider(ThreatIntelProvider): ...   # 微步
class QianxinProvider(ThreatIntelProvider): ...      # 奇安信
class Qihu360Provider(ThreatIntelProvider): ...      # 360

# 置信度合成
class ConfidenceSynthesizer:
    def synthesize(self, results: list[IntelResult]) -> float:
        # 多源命中 → 0.7+;单源 → 0.4 标黄
```

---

## 6. docker-compose 编排清单

`deploy/docker-compose.yml` 包含以下服务(分组):

**SecSight 主体组**(可闭源):
- `secsight-backend` (FastAPI)
- `secsight-frontend` (nginx)
- `litellm` (LLM 网关)
- `qdrant` (向量库)
- `postgres` (案件/审计/checkpoint)

**基础设施组**:
- `wazuh-manager` / `wazuh-indexer` / `wazuh-dashboard`
- `opensearch` / `opensearch-dashboards`
- `vector` (采集管道)
- `suricata` (旁路,可选单独机)

**隔离组**(AGPL/GPL,独立网络):
- `shuffle` (AGPL,仅暴露 webhook 端口)
- `opencti` + 依赖(redis/minio/rabbitmq)
- `dfir-iris` + 依赖(iris-db/rabbitmq)

**网络隔离策略**:
- SecSight 主体 ↔ Shuffle/OpenCTI/DFIR-IRIS 仅通过 HTTP API
- Shuffle 不在 SecSight 代码中 import

---

## 7. License 隔离验证清单(Phase1 验收)

- [ ] SecSight backend `pyproject.toml` 不含 shuffle/wazuh/iris 任何 SDK import
- [ ] 所有 AGPL/GPL 组件作为独立 docker 服务
- [ ] DFIR-IRIS 未安装 iris-skeleton-module / iris-mwdb-module / iris-intelowl-module
- [ ] ASP 代码未被 fork(仅借鉴领域模型设计)
- [ ] Shuffle 调用仅经 Webhook/REST,无代码链接

---

## 8. 风险与缓解(Phase1 专项)

| 风险 | 缓解 |
|---|---|
| 云端 LLM API 限流/故障 | LiteLLM 多厂商 fallback(DeepSeek→MiniMax→Qwen) |
| 免费情报置信度低误封 | 封禁类动作默认 L2 审批,不自动封 |
| Shuffle AGPL 误传染 | W1-2 即验证隔离:主体代码 grep 确认无 import |
| 剧本误匹配 | 剧本匹配 + Tier1 LLM 二次确认,不确定则标黄人工 |
| 勒索测试样本失控 | 仅用文件改名模拟,不含真实加密代码;隔离 VM |
| LLM 幻觉 ATT&CK 编号 | TTP 白名单(必须 RAG 召回)+ Pydantic 校验 |

---

## 9. 人力与里程碑

**人力**: 2-3 人(1 安全工程师 + 1 后端 + 0.5 LLM/前端)

| 里程碑 | 周次 | 交付 |
|---|---|---|
| M0 基础设施 | W2 末 | 六件套上线,LLM 可调通 |
| M1 编排+分诊 | W4 末 | 告警→Case 流程跑通 |
| M2 剧本+知识库 | W7 末 | 6 剧本可匹配,RAG 可检索 |
| M3 调查+情报 | W9 末 | IoC 富化 + 研判报告 |
| M4 审批+处置 | W11 末 | L2 双签闭环 + Evidence Pack |
| M5 验收 | W12 末 | 6 场景跑通,TTTR<10min |

---

## 10. 下一步

1. 初始化项目仓库骨架(目录结构 + 基础配置 + 核心代码骨架)
2. W1-2 落地:编写完整 docker-compose + .env
3. W3-4 落地:FastAPI + LangGraph StateGraph 骨架

> 本计划基于裁决 v1.1。若 Phase1 执行中发现选型问题,回退到裁决记录修订(走 v1.2)。
