# SecSight 垂直切片开发计划 — 挖矿剧本端到端

> **版本**: v1.0
> **日期**: 2026-08-21
> **策略**: 垂直切片优先 + 全 mock + 先跑通后补测试
> **目标**: 打通挖矿剧本完整闭环(注入→研判→审批→处置→沉淀),可见可演示,再横向扩展

---

## 0. 垂直切片目标

用 mock 驱动打通一条完整链路,不依赖真实 Wazuh Agent / LLM API / 飞书 webhook:

```
[mock 告警注入] xmrig 进程 + 矿池连接
    ↓
[剧本匹配] → pb_cryptominer_v1
    ↓
[LangGraph 编排]
    ├─ ingest_alerts        (建 Case)
    ├─ retrieve_knowledge   (RAG mock 召回 T1496)
    ├─ analyze              (mock LLM 输出 JudgmentReport)
    ├─ plan_actions         (剧本提取 Action,标注 L2)
    ├─ human_approve        (L2 双签,Web UI 审批)
    ├─ execute              (mock Shuffle 执行隔离/kill/清理)
    └─ update_case          (Evidence Pack 归档 + L3 沉淀)
    ↓
[Dashboard 可视化] Case 详情 + 时间线 + 审批 + 执行结果
```

**验收**:
- `POST /api/alerts/inject` 注入 xmrig 告警 → 自动生成 Case + 匹配剧本
- Web UI 可见 Case + 研判报告 + 待审批动作
- 点击"批准" → 执行隔离/kill/清理 → Evidence Pack 归档
- TTTR 可计算,全链路 trace 可查

---

## 1. Mock 策略

| 组件 | 真实方案 | Mock 方案(当前) | 替换点 |
|---|---|---|---|
| 告警源 | Wazuh Agent + Suricata | `POST /api/alerts/inject` 注入预设告警 | Vector 接 Wazuh alerts.json |
| LLM | DeepSeek/MiniMax via LiteLLM | `MockLLMGateway` 返回预设 JudgmentReport | 切换 `LLMGateway` 实现 |
| RAG | Qdrant + BGE-m3 | `MockRetriever` 返回预设 ATT&CK chunks | 接 Qdrant |
| 情报 | AbuseIPDB/OTX API | `MockThreatIntelProvider` 返回预设 IoC 结果 | 实现 httpx 调用 |
| Shuffle | Shuffle Workflow REST | `MockExecutor` 打日志 + 返回 success | 接 Shuffle webhook |
| 审批通知 | 飞书/钉钉 webhook | Web UI 审批按钮 | 加飞书 webhook 适配器 |
| DFIR-IRIS | IRIS REST 案件 | Postgres 本地 Case 表 | 接 IRIS API |
| OpenSearch | OpenSearch 检索 | Postgres JSONB 查询 | 接 OpenSearch |

**设计原则**: 每层用接口抽象,mock 与真实实现可切换。`settings.mock_mode=True` 时全走 mock。

---

## 2. 模块实现细节

### 2.1 数据持久层 (`backend/app/db/`)

**文件**:
- `db/database.py` — async engine + session
- `db/models.py` — SQLAlchemy ORM (Case/Alert/Action/Approval/EvidencePack/AuditLog)
- `db/repositories.py` — 仓储类 (CaseRepository 等)

**ORM 模型** (对应 schemas.py,但带持久化):

```python
class CaseModel(Base):
    __tablename__ = "cases"
    case_id: Mapped[str] = mapped_column(String, primary_key=True)
    status: Mapped[str]
    playbook_id: Mapped[str | None]
    alerts: Mapped[list] = mapped_column(JSONB)  # JSONB 存 Alert 列表
    enriched_context: Mapped[dict] = mapped_column(JSONB)
    judgment: Mapped[dict | None] = mapped_column(JSONB)
    proposed_actions: Mapped[list] = mapped_column(JSONB)
    approvals: Mapped[dict] = mapped_column(JSONB)
    execution_log: Mapped[list] = mapped_column(JSONB)
    evidence_pack_id: Mapped[str | None]
    autonomy_level_default: Mapped[str]
    created_at: Mapped[datetime]
    updated_at: Mapped[datetime]
    tttr_seconds: Mapped[int | None]

class EvidencePackModel(Base):
    __tablename__ = "evidence_packs"
    pack_id: Mapped[str] = mapped_column(String, primary_key=True)
    case_id: Mapped[str] = mapped_column(String, ForeignKey("cases.case_id"))
    process_tree: Mapped[dict] = mapped_column(JSONB)
    timeline: Mapped[list] = mapped_column(JSONB)
    llm_reasoning_trace: Mapped[list] = mapped_column(JSONB)
    iocs: Mapped[dict] = mapped_column(JSONB)
    created_at: Mapped[datetime]

class AuditLogModel(Base):
    __tablename__ = "audit_logs"
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    case_id: Mapped[str | None]
    action: Mapped[str]
    actor: Mapped[str]
    detail: Mapped[dict] = mapped_column(JSONB)
    ts: Mapped[datetime]
```

### 2.2 告警注入与 Case API (`backend/app/api/`)

**文件**:
- `api/alerts.py` — `POST /api/alerts/inject` (mock 注入), `GET /api/alerts`
- `api/cases.py` — Case CRUD + 触发编排
- `api/playbooks.py` — 剧本列表 + 剧本匹配
- `api/approvals.py` — 审批提交
- `api/evidence.py` — Evidence Pack 查询

**告警注入端点**:

```python
@router.post("/inject")
async def inject_alert(payload: AlertInjectRequest, repo=Depends(case_repo)):
    alert = build_alert_from_payload(payload)  # 构造 Alert
    case = await repo.create_case_from_alert(alert)
    playbook = playbook_engine.match(alert)    # 匹配剧本
    case.playbook_id = playbook.id
    # 异步触发 LangGraph workflow
    await workflow.ainvoke(build_initial_state(case))
    return {"case_id": case.case_id, "playbook_id": playbook.id}
```

**预设 mock 告警** (`app/mock/alerts.py`):
- `xmrig_process_alert` — Wazuh 可疑进程 (xmrig + stratum cmdline)
- `mining_pool_connection` — Suricata 矿池连接 (pool.supportxmr.com:3333)
- `high_cpu_anomaly` — CPU 持续 > 80%

### 2.3 剧本匹配引擎 (`backend/app/playbooks/`)

**文件**:
- `playbooks/engine.py` — `PlaybookEngine.match(alert) -> Playbook | None`
- `playbooks/loader.py` — 加载 `playbooks/phase1/*.yaml`

**匹配逻辑**:
1. 遍历已加载剧本
2. 检查 triggers: sigma_rules / wazuh_rules / process_patterns / network
3. 命中任一 trigger → 返回剧本
4. 多剧本命中 → 按 priority (P0 > P1)

```python
class PlaybookEngine:
    def __init__(self, playbooks_dir: str):
        self.playbooks = loader.load_all(playbooks_dir)

    def match(self, alert: Alert) -> Playbook | None:
        candidates = []
        for pb in self.playbooks:
            if self._match_triggers(alert, pb.triggers):
                candidates.append(pb)
        if not candidates:
            return None
        return sorted(candidates, key=lambda p: p.priority)[0]
```

### 2.4 LangGraph 编排完善 (`backend/app/agents/workflow.py`)

各节点实现(用 mock 服务):

```python
async def ingest_alerts(state):
    # 从 state.raw_alerts 建 Case,写 Postgres
    case = await case_repo.get(state["case_id"])
    case.status = CaseStatus.investigating
    await case_repo.save(case)
    return state

async def retrieve_knowledge(state):
    # mock RAG: 根据告警 MITRE 技术召回 ATT&CK chunks
    chunks = await mock_retriever.search(state["raw_alerts"])
    state["retrieved_knowledge"] = chunks
    return state

async def analyze(state):
    # mock LLM: 输出 JudgmentReport (结构化)
    report = await mock_llm.tier2_structured(
        build_analysis_prompt(state), JudgmentReport
    )
    state["judgment"] = report.model_dump()
    return state

async def plan_actions(state):
    # 从剧本提取 containment_actions → Action 列表,标注 autonomy
    pb = playbook_engine.get_by_id(state["current_playbook_id"])
    actions = [build_action(a, pb) for a in pb.containment_actions]
    state["proposed_actions"] = [a.model_dump() for a in actions]
    return state

async def human_approve(state):
    # 标记 Case 为 pending_approval,等 Web 审批
    await case_repo.update_status(state["case_id"], CaseStatus.pending_approval)
    return state

async def execute(state):
    # mock Shuffle: 执行每个 approved action
    for action in approved_actions(state):
        result = await mock_executor.execute(action)
        state["execution_log"].append(result)
    return state

async def update_case(state):
    # 生成 Evidence Pack + 沉淀 L3 + 计算 TTTR
    pack = await evidence_pack_builder.build(state)
    await case_repo.update_status(state["case_id"], CaseStatus.resolved)
    return state
```

### 2.5 Mock LLM (`backend/app/llm_gateway/mock.py`)

```python
class MockLLMGateway:
    """mock LLM,根据告警类型返回预设 JudgmentReport"""

    async def tier2_structured(self, messages, schema):
        alert_type = extract_alert_type(messages)
        return PRESET_REPORTS[alert_type]  # 预设研判报告

PRESET_REPORTS = {
    "cryptominer": JudgmentReport(
        incident_summary="检测到 xmrig 挖矿进程连接矿池",
        severity=Severity.high,
        ttps=["T1496", "T1071.001"],
        true_positive="yes",
        confidence=0.88,
        recommended_actions=[ActionType.isolate_host, ActionType.kill_process, ActionType.block_domain],
        rationale="进程名 xmrig + stratum+tcp 命令行 + 矿池 IP 连接,三重证据确认挖矿",
        citations=["attck:T1496", "case_hist:2025-xxx"],
    ),
    ...
}
```

**LLMGateway 工厂** (`client.py` 扩展):
```python
def get_llm() -> LLMGateway | MockLLMGateway:
    if settings.mock_mode:
        return MockLLMGateway()
    return LLMGateway()
```

### 2.6 情报层 mock (`backend/app/threat_intel/mock.py`)

```python
class MockThreatIntelProvider(ThreatIntelProvider):
    name = "mock"
    is_paid = False

    async def query_ip(self, ip):
        # 预设: 已知矿池 IP 返回恶意
        if ip in KNOWN_MINING_POOL_IPS:
            return IntelResult(indicator=ip, confidence=0.85, malicious=True,
                               tags=["cryptomining","botnet"], mitre_ttps=["T1496"])
        return IntelResult(indicator=ip, confidence=0.1, malicious=False)

    async def query_domain(self, domain):
        if "supportxmr.com" in domain or "minexmr.com" in domain:
            return IntelResult(indicator=domain, confidence=0.9, malicious=True,
                               tags=["mining-pool"], mitre_ttps=["T1496","T1071.001"])
        return IntelResult(indicator=domain, confidence=0.1, malicious=False)
    ...
```

### 2.7 Containment 执行 mock (`backend/app/execution/mock.py`)

```python
class MockExecutor:
    """mock Shuffle,执行动作打日志 + 返回 success"""
    async def execute(self, action: Action) -> dict:
        log.info(f"[MOCK EXEC] {action.action_type} target={action.target}")
        audit_log.record(action)  # 审计
        return {"success": True, "task_id": uuid4(), "message": f"mock executed {action.action_type}"}
```

**真实切换**: `ShuffleExecutor` 调 `SHUFFLE_BASE_URL/api/v1/workflows/{id}/execute` (REST,不 import)。

### 2.8 Evidence Pack (`backend/app/evidence/`)

```python
class EvidencePackBuilder:
    async def build(self, state) -> EvidencePack:
        return EvidencePack(
            pack_id=uuid4(),
            case_id=state["case_id"],
            process_tree=extract_process_tree(state),
            timeline=build_timeline(state),
            llm_reasoning_trace=state.get("judgment", {}),
            iocs=collect_iocs(state),
        )
```

### 2.9 审批 API (`backend/app/api/approvals.py`)

```python
@router.post("/{case_id}/actions/{action_id}/approve")
async def approve_action(case_id, action_id, req: ApprovalRequest):
    # 双签校验: 需 incident_commander + approver 两个角色
    case = await case_repo.get(case_id)
    validate_double_sign(case, req)
    record_approval(case, action_id, req)
    if all_approved(case):
        # 所有 L2 动作批准 → 恢复 workflow 执行
        await workflow_resume(case_id)
    return {"status": "all_approved" if all_approved else "pending"}
```

### 2.10 前端 Dashboard (`frontend/src/`)

**页面**:
- `Dashboard` — 总览 (Case 统计 + 待审批数)
- `Cases` — Case 列表 + 状态筛选
- `CaseDetail` — Case 详情 (告警/研判/动作/审批/时间线/Evidence)
- `Playbooks` — 剧本列表

**关键组件**:
- `ApprovalPanel` — L2 审批操作 (选角色 + 批准/拒绝)
- `Timeline` — 执行时间线可视化
- `AlertInjector` — mock 告警注入按钮(开发用)

---

## 3. 开发顺序(文件级)

### 阶段 A: 数据层 (Task #5)
1. `backend/app/db/database.py` — engine/session
2. `backend/app/db/models.py` — ORM
3. `backend/app/db/repositories.py` — 仓储
4. `backend/app/db/__init__.py`

### 阶段 B: 告警注入 + Case API + 剧本 (Task #6)
5. `backend/app/playbooks/loader.py`
6. `backend/app/playbooks/engine.py`
7. `backend/app/mock/alerts.py` — 预设 mock 告警
8. `backend/app/api/alerts.py`
9. `backend/app/api/cases.py`
10. `backend/app/api/playbooks.py`
11. `backend/app/api/__init__.py` — router 汇总

### 阶段 C: 编排 + mock LLM + RAG (Task #7)
12. `backend/app/llm_gateway/mock.py`
13. `backend/app/llm_gateway/client.py` — 加工厂
14. `backend/app/retrieval/mock.py` — RAG mock
15. `backend/app/agents/workflow.py` — 完善各节点
16. `backend/app/agents/nodes.py` — 节点实现拆分

### 阶段 D: 情报 + 执行 + Evidence (Task #8)
17. `backend/app/threat_intel/mock.py`
18. `backend/app/execution/mock.py`
19. `backend/app/execution/base.py`
20. `backend/app/evidence/builder.py`
21. `backend/app/audit/logger.py`

### 阶段 E: 审批闭环 (Task #9)
22. `backend/app/api/approvals.py`
23. `backend/app/approvals/service.py` — 双签逻辑
24. `backend/app/api/evidence.py`

### 阶段 F: 前端 (Task #10)
25. `frontend/src/main.tsx` + `App.tsx`
26. `frontend/src/api/client.ts`
27. `frontend/src/pages/Dashboard.tsx`
28. `frontend/src/pages/Cases.tsx`
29. `frontend/src/pages/CaseDetail.tsx`
30. `frontend/src/components/ApprovalPanel.tsx`
31. `frontend/src/components/Timeline.tsx`
32. `frontend/vite.config.ts` + `tsconfig.json`

### 阶段 G: 端到端验证 (Task #11)
33. `backend/scripts/seed.py` — 灌入 mock 告警
34. 跑通全链路
35. 补关键路径测试

---

## 4. 配置扩展

`config.py` 加:
```python
mock_mode: bool = True  # 默认 mock,真实环境切 false
```

`.env.example` 加:
```
SECSIGHT_MOCK_MODE=true
```

---

## 5. 验收脚本

`backend/scripts/demo_cryptominer.py`:
```python
# 1. 注入 xmrig 告警
POST /api/alerts/inject {type: "xmrig_process", src_ip, dst_ip, hostname}
# 2. 查询 Case
GET /api/cases/{case_id}  → 状态 pending_approval
# 3. Web 审批 (双签)
POST /api/approvals/{case_id}/actions/{action_id}/approve {role: incident_commander}
POST /api/approvals/{case_id}/actions/{action_id}/approve {role: approver}
# 4. 验证执行
GET /api/cases/{case_id}  → 状态 resolved, execution_log 完整
GET /api/evidence/{case_id} → Evidence Pack 存在
```

---

## 6. 横向扩展路径(切片跑通后)

1. 替换 mock → 真实 (LLM/情报/Shuffle/飞书) — 逐个切换
2. 加 5 个剧本 (勒索/持久化/暴破/日志合规/服务崩溃) — 复用引擎
3. 接 Wazuh/Suricata 真实告警 — Vector pipeline
4. 接 OpenSearch 检索 — 替换 Postgres JSONB
5. 接 Qdrant RAG — 替换 mock retriever
6. 补测试到 80%
