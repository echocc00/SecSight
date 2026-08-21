# SecSight Phase2 详细规划

> **版本**: v1.0
> **日期**: 2026-08-22
> **前置**: v0.2.0 (6 剧本 + 5 真实组件接入, 177 tests, 88.5% 覆盖率)
> **目标**: 从"可演示原型"到"可生产运行平台"
> **周期**: 8-10 周 (2-3 人)
> **里程碑**: v0.3.0 (生产化) → v0.4.0 (合规 + 扩展)

---

## 0. Phase2 定位

Phase1 完成了**架构验证**:mock 全栈 + 5 个组件可切换真实实现,但都是"代码就绪、未真实部署验证"。Phase2 要解决三个核心问题:

1. **真实闭环验证** — 所有组件真实部署跑通,不止"能调通"而是"持续运行"
2. **生产化加固** — 认证/监控/日志/性能/高可用,达到可交付质量
3. **合规与扩展** — 等保报告生成 + 更多剧本 + 国产设备接入

### Phase2 不做的事 (YAGNI)
- 多租户/SaaS 化 (先自用,确认 P1)
- 分布式集群 (单机/双机足够 ≤500 资产)
- 自研向量模型 (numpy TF-IDF 够用,升级延后)
- Web 前端深度重构 (现有 Antd 够用)

---

## 1. Phase2 工作流 (6 个工作流)

| # | 工作流 | 目标 | 周期 | 优先级 |
|---|---|---|---|---|
| W1 | 真实部署验证 | docker-compose 全栈跑通,7 个组件真实运行 | W1-2 | P0 |
| W2 | 真实告警闭环 | Wazuh Agent → Manager → SecSight 端到端 | W3-4 | P0 |
| W3 | 生产化加固 | 认证/监控/日志/性能/安全 | W5-6 | P0 |
| W4 | P1 剧本扩展 | 横向扩展 6 个 P1 剧本 (共 12 个) | W7 | P1 |
| W5 | 前端完善 | 实时告警/告警详情/合规报告页 | W8 | P1 |
| W6 | 合规报告 | 等保 2.0 三级报告生成 | W9 | P1 |
| — | 测试与发布 | 补测试 + v0.3.0/v0.4.0 发布 | W10 | — |

---

## 2. W1: 真实部署验证 (W1-2)

### 2.1 目标
docker-compose 一键起 7 个组件,所有组件真实运行(非 mock),持续 24h 稳定。

### 2.2 任务

| 任务 | 产出 | 验收 |
|---|---|---|
| 完善 deploy/docker-compose.yml | 7 服务编排 + 健康检查 + 资源限制 | `docker compose up -d` 全绿 |
| Wazuh 栈部署 | Manager + Indexer + Dashboard | Agent 可注册,告警可视 |
| OpenSearch + Vector | 日志聚合 + ECS 归一化 | 告警入库可查 |
| Shuffle 部署 | Shuffle + 依赖 (app/db/redis) | Workflow 可创建执行 |
| OpenCTI 部署 | OpenCTI + redis/minio/rabbitmq | ATT&CK connector 同步 |
| DFIR-IRIS 部署 | iris-web + db (仅主本体,禁 AGPL 模块) | 案例可建 |
| Qdrant 部署 | qdrant 容器 + 知识入库 | 检索可查 |
| LiteLLM 部署 | LiteLLM + DeepSeek/MiniMax 路由 | 多厂商可切换 |
| 资源调优 | 各服务 CPU/内存限制 | 单机 32C/64G 可跑全栈 |

### 2.3 关键设计: 网络隔离落地

```
┌─ secsight-net (主体,可闭源) ──────────────────┐
│  secsight-backend / frontend / litellm         │
│  qdrant / postgres                             │
└──────────┬─────────────────────────────────────┘
           │ HTTP API (不 import)
   ┌───────┴──────────────┬──────────────────┐
┌──▼── infra-net ──────────┐  ┌──▼── isolation-net (AGPL/GPL) ──┐
│ wazuh-manager/indexer     │  │ shuffle / opencti / dfir-iris   │
│ opensearch / vector       │  │ (独立网络,仅暴露 webhook 端口)  │
└───────────────────────────┘  └─────────────────────────────────┘
```

### 2.4 部署文档
新增 `docs/deploy-guide.md`:
- 硬件要求 (最小/推荐)
- 一步步部署 + 健康检查命令
- 常见故障排查 (端口冲突/资源不足/license 隔离验证)
- 升级流程

### 2.5 风险
- **资源**: 7 组件全栈约 40GB 内存 → 单机 64G 或拆 2 台
- **Shuffle 镜像**: 社区版多组件,部署复杂 → 优先用 docker-compose 官方编排
- **license 隔离验证**: 部署后 grep 代码确认无 AGPL import

---

## 3. W2: 真实告警闭环 (W3-4)

### 3.1 目标
Wazuh Agent 真实上报告警 → SecSight 自动建 Case → AI 研判 → 审批 → Shuffle 真实处置 → Evidence Pack。

### 3.2 任务

| 任务 | 产出 |
|---|---|
| 部署 3-5 台 Wazuh Agent (测试 VM) | 真实主机接入 |
| 配置 Wazuh 规则 | 挖矿/持久化/暴破/日志合规 规则激活 |
| SecSight 轮询/订阅 Wazuh 告警 | `POST /api/alerts/wazuh/poll` 或 webhook |
| 真实告警 → Case → 剧本匹配 | 验证 6 剧本在真实告警下匹配正确 |
| Shuffle Workflow 创建 | 6 剧本各一个 Workflow (UI 配置 + workflow_id 填入) |
| 真实处置验证 | 隔离/封禁/kill 在测试 VM 真实执行 |
| Evidence Pack 真实数据 | 进程树/时间线来自真实系统 |

### 3.3 关键设计: 告警接入两种模式

```python
# 模式 A: 轮询 (Phase2 默认,简单)
# SecSight 定时调 Wazuh API /security/events 拉新告警
# 优点: 无需 Wazuh 配置; 缺点: 延迟 (轮询间隔)

# 模式 B: Webhook 推送 (Phase2 后期)
# Wazuh 集成 → Shuffle/Vector → SecSight /api/alerts/webhook
# 优点: 实时; 缺点: 需配置 Wazuh integrator
```

### 3.4 真实处置安全边界
- **测试 VM 隔离**: 处置只在专用测试机执行,禁碰生产
- **dry_run 模式**: `EXECUTION_DRY_RUN=true` 时只生成 Plan 不真实执行
- **白名单**: `policies/protected_assets.yaml` 列出永不自动处置的主机
- **回滚**: 每个 action 的 rollback_action_id 必须可执行

### 3.5 验收 (端到端真实闭环)
```
测试 VM 跑 xmrig → Wazuh 检测 → SecSight Case → AI 研判 →
L2 审批 → Shuffle 真实 kill 进程 + 封禁 → Evidence Pack → resolved
TTTR < 5 min (含人工审批)
```

---

## 4. W3: 生产化加固 (W5-6)

### 4.1 目标
达到可交付质量:认证、监控、日志、性能、安全。

### 4.2 认证与授权

| 任务 | 实现 |
|---|---|
| JWT 认证 | `/api/auth/login` + FastAPI dependency |
| 角色权限 | admin / analyst / approver / viewer |
| API key (外部调用) | `/api/auth/apikey` 生成 + 权限范围 |
| 前端登录页 | Login + 权限路由 |
| 审批角色校验 | approver_role 必须匹配当前用户角色 |

**角色权限矩阵**:
| 操作 | admin | analyst | approver | viewer |
|---|---|---|---|---|
| 查看 Case | ✓ | ✓ | ✓ | ✓ |
| 注入告警 | ✓ | ✓ | — | — |
| 提交审批 | ✓ | — | ✓ | — |
| 触发处置 | ✓ | — | ✓ (双签) | — |
| 管理剧本 | ✓ | ✓ | — | — |
| 用户管理 | ✓ | — | — | — |

### 4.3 监控与可观测

| 任务 | 实现 |
|---|---|
| Prometheus 指标 | `/metrics` (Case 数/TTTR/LLM 调用/降级次数) |
| Grafana Dashboard | 预置面板 (SOC KPI) |
| 结构化日志 | structlog JSON → OpenSearch |
| 告警 (平台自身) | LLM 降级率 > 20% / 执行失败率 > 10% 告警 |
| 健康检查 | `/health` 扩展: 各组件连通性 |

**核心指标**:
- `secsight_cases_total{status}` — Case 计数
- `secsight_tttr_seconds` — 响应耗时分布
- `secsight_llm_fallback_total` — LLM 降级次数
- `secsight_execution_success_rate` — 处置成功率

### 4.4 性能

| 任务 | 实现 |
|---|---|
| 并发处理 | LangGraph async + FastAPI async (已具备) |
| 数据库连接池 | 调优 pool_size/max_overflow |
| LLM 调用缓存 | LiteLLM cache (Redis) — 相同 prompt 命中 |
| 批量告警处理 | 单 Case 聚合多条告警,避免 LLM 重复调用 |
| 前端分页/虚拟滚动 | Case 列表大量数据 |

### 4.5 安全加固

| 任务 | 实现 |
|---|---|
| CORS 收紧 | 生产环境限定域名 |
| 速率限制 | slowapi: 登录/注入/审批 端点限流 |
| PII 脱敏 | 告警入库前脱敏 (已配置,需落地) |
| 密钥管理 | .env 不入库 + secrets 加密存储 |
| 审计日志不可篡改 | append-only + 签名 |
| API 输入校验 | Pydantic strict + 长度限制 |

### 4.6 高可用 (可选,Phase2 后期)
- Postgres 持久化 + 定期备份
- Qdrant 快照
- 服务重启自恢复 (docker restart=always)

---

## 5. W4: P1 剧本扩展 (W7)

### 5.1 目标
横向扩展 6 个 P1 剧本,共 12 个。

### 5.2 P1 剧本清单

| 剧本 | MITRE | 场景 | 检测源 |
|---|---|---|---|
| Web 攻击 | T1190 | SQL注入/XSS/路径遍历 | Wazuh + ModSecurity |
| 数据外泄 | T1048 | 大量数据外传 | Suricata + DLP |
| 横向移动 | T1021 | SMB/RDP/PsExec | Wazuh + Sysmon |
| 权限提升 | T1068 | 漏洞提权/sudo滥用 | auditd + Sysmon |
| C2 通信 | T1071 | 信标/心跳流量 | Suricata + Zeek |
| 钓鱼邮件 | T1566 | 恶意附件/链接 | 邮件网关 + Wazuh |

### 5.3 任务
- 6 个剧本 YAML (含 action_type + autonomy_level)
- 6 个 mock 告警 builder + LLM PRESET_REPORTS
- 剧本匹配评分调优 (避免 P1 与 P0 误配)
- 每个剧本端到端测试

---

## 6. W5: 前端完善 (W8)

### 6.1 目标
Dashboard 从"可演示"到"可日常使用"。

### 6.2 页面/功能

| 功能 | 实现 |
|---|---|
| 实时告警流 | SSE/WebSocket 推送新 Case |
| 告警详情页 | 进程树可视化 + IoC 关系图 |
| 审批工作台 | 批量审批 + 审批历史 |
| 合规报告页 | 生成 + 下载等保报告 |
| 剧本管理 | 启用/禁用 + 编辑 YAML |
| 资产视图 | 主机列表 + 风险评分 |
| 用户管理 | 角色分配 (admin) |
| 搜索 | 全文检索 Case/告警/IoC |

### 6.3 技术栈
- React 19 + Antd 6 (现有)
- recharts (图表,已装)
- react-flow (进程树/IoC 关系图)
- SSE (实时推送,比 WebSocket 简单)

---

## 7. W6: 合规报告 (W9)

### 7.1 目标
等保 2.0 三级事件报告自动生成,可提交监管。

### 7.2 报告内容

| 章节 | 内容 |
|---|---|
| 事件概述 | 时间/影响范围/严重等级 |
| 检测过程 | 告警链 + MITRE 映射 |
| 分析研判 | LLM 研判报告 + 证据 |
| 处置措施 | 执行动作 + 时间线 + 操作人 |
| 影响评估 | 业务影响 + 数据影响 |
| 根因分析 | 入侵路径 + 漏洞 |
| 整改建议 | 加固措施 + 知识沉淀 |
| 附件 | Evidence Pack + IoC 列表 |

### 7.3 实现
- `app/compliance/report_generator.py`
- 模板: Jinja2 → PDF (weasyprint) / Word (python-docx)
- `POST /api/cases/{id}/report` 生成
- 24h 上报时限提醒 (等保要求)

### 7.4 合规留痕
- 审计日志保留 ≥ 180 天 (已配置)
- 报告生成记录不可篡改
- 审批记录双签留痕

---

## 8. 里程碑与发布

### 8.1 v0.3.0 (W6 末, 生产化)
- W1-W3 完成: 真实部署 + 真实告警闭环 + 生产化加固
- 177 → 220+ 测试,覆盖率维持 88%+
- Release: 生产化里程碑

### 8.2 v0.4.0 (W10 末, 合规 + 扩展)
- W4-W6 完成: 12 剧本 + 前端完善 + 合规报告
- Release: 合规里程碑
- 可对外交付 demo

---

## 9. 风险与缓解

| 风险 | 缓解 |
|---|---|
| Wazuh Agent 测试环境不足 | 用 3-5 台 VM,可控勒索/挖矿样本 |
| Shuffle Workflow 配置复杂 | 预置 6 个 Workflow 模板 + 文档 |
| LLM 成本失控 | LiteLLM 缓存 + 简单分诊用便宜模型 + 降级 |
| 真实处置误伤 | dry_run + 白名单 + 测试 VM 隔离 |
| 资源不足 (单机跑全栈) | 拆控制面+数据面两台 |
| license 隔离破坏 | CI 加 grep 检查 AGPL import |

---

## 10. 成功标准 (Phase2 验收)

- [ ] docker-compose 一键起 7 组件,24h 稳定
- [ ] 真实 Wazuh Agent 告警端到端闭环 (TTTR < 5 min)
- [ ] JWT 认证 + 4 角色权限
- [ ] Prometheus 指标 + Grafana 面板
- [ ] 12 个剧本全部端到端通过
- [ ] 等保报告自动生成 (PDF/Word)
- [ ] 220+ 测试,覆盖率 88%+
- [ ] license 隔离 CI 检查通过

---

## 11. 下一步 (Phase3 预告,不在本期)

- 国产设备接入 (奇安信态势感知/深信服防火墙 syslog)
- 多租户/SaaS (确认商业化后)
- Agent 主动防御 (Phase4, 4 个 Proactive 角色)
- 检测规则反向优化 (L3 案例沉淀 → 检测规则)
- 威胁狩猎 (Threat Hunting) 工作台
