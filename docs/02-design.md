# AI 驱动的安全运维平台 — 设计与规划

> **日期:** 2026-08-20
> **前置文档:** [01-survey.md](01-survey.md)(开源生态调研)+ [03-real-scenarios.md](03-real-scenarios.md)(真实场景调研,v2 引入)
> **作者:** 程泽杰
> **版本:** **v2.0**(2026-08-20 重大修订:剧本 8→22、勒索病毒升至 P1 首位、加 5 级自主性框架、知识库 4 层分层、Phase 1 覆盖 6 个 P0 剧本)
> **目标:** 设计一款基于 AI 的安全运维工具,能监控业务系统、有安全事件能自动分析/判断/排错/应急处置
> **核心差异化:** 场景驱动(22 个真实企业剧本,勒索病毒置顶)+ 国产化适配 + 端到端自动处置 + 私有化 LLM + 5 级自主性 HITL

---

## 文档导航

- §0 设计哲学(一句话定位 / 6 大原则 / 关键决策表)
- §1 总体架构(5 层 + HITL 横切)
- §2 数据流(从告警到处置的完整链路 + 4 个回路)
- §3 Agent 角色定义(11 角色 + 5 级自主性 + 策略矩阵)
- §4 **22 大核心场景剧本**(按业务系统分组 + Phase 1 优先级)
- §5 知识库设计(L0/L1/L2/L3 四层架构)
- §6 LLM 集成策略(网关 / 模型 / Prompt 模板)
- §7 4 阶段 MVP 路线(Phase 1 = 勒索置顶 + 6 个 P0 剧本)
- §8 关键文件/目录结构(Fork ASP)
- §9 关键技术决策的论证(8 条)
- §10 风险与缓解(14 项)
- §11 落地前的待确认事项(⭐ Phase 1 前必确认 5 项 + 后可调整 7 项)
- §12 立即可执行的 30 天行动计划(Phase 1 启动版)
- §13 参考资料(分 6 类)

---

## 0. 设计哲学

### 0.1 一句话定位

**AI 辅助的 SecOps Copilot + 自动处置 SOAR 引擎。**

不是"另一个 SIEM"(Wazuh 已胜出),不是"通用 SOC 平台"(ASP 已胜出)。
而是:**站在 Wazuh + ASP + Anthropic Cybersecurity Skills 的肩膀上,做场景驱动的、国产化的、能落地的 AI 安全运维产品。**

### 0.2 核心原则

- **场景优先于功能:** 围绕 **22 个真实企业高频场景**(详见 [03-real-scenarios.md §3](03-real-scenarios.md))做剧本,按业务系统(主机/网络/应用/数据/云/身份/邮件)而非攻击链组织。**勒索病毒业务影响最高,作为 Phase 1 第 1 优先级**(论证见 03-real-scenarios.md §5)。
- **AI 提议 + 人类审批(5 级自主性):** 每个动作标注 autonomy_level L1-L5(Mohsin et al., 2025 理论),LLM 网关根据级别自动决定 HITL 策略。**高危处置动作(隔离主机/杀进程/封 IP/冻结账号)为 L2 强制双签审批**。
- **知识即资产:** 处置记录 + 调查推理 → **4 层知识库**(L0 框架/L1 战术/L2 剧本/L3 案例),后续场景可复用。
- **场景知识标准化:** 用 MITRE ATT&CK + MITRE D3FEND + 等保 2.0 + Sigma 规则描述每个场景,不发明新词。
- **私有化优先:** LLM 优先本地(Ollama/vLLM,Qwen2.5 + DeepSeek),云端 API 作为可选 fallback。
- **可观测:** 每个 agent 决策都有 Evidence Pack(类似 Wazuh-Autopilot),便于审计和复盘。

### 0.3 关键决策(基于调研)

| 决策项 | 选择 | 理由 |
|---|---|---|
| 底座 SIEM/XDR | **Wazuh** | 16611⭐ 事实标准, MIT 友好, 国内有中文社区 |
| Agent 平台基线 | **Fork ASP + 集成 Wazuh-Autopilot 范式** | 1150⭐ MIT Django 项目,直接二次开发 |
| 知识库 | **4 层分层架构**(L0/L1/L2/L3) + Anthropic Cybersecurity Skills | 817 技能 + 6 大框架映射 + 运行时沉淀 |
| 编排框架 | **Playbook (类 ASP) + SOAR (w5 国产)** | 剧本驱动 + 国产 SOAR 兜底 |
| LLM 策略 | **本地 Ollama(默认) + 云 API(fallback)** | 私有化, 国产场景可用 Qwen2.5/DeepSeek |
| Agent 通信 | **MCP 协议** | 2026 事实标准, 已大量现成 MCP server 可用 |
| Agent 编排 | **11 角色 + 5 级自主性(Mohsin et al. 2025)** | 7 reactive + 4 proactive + 每动作标注 L1-L5 |
| 处置执行 | **L2 强制双签 + Slack/飞书/钉钉 webhook** | Mohsin 论文 + Wazuh-Autopilot 实践双重验证 |
| 前端 | **Vite + Ant Design (沿用 ASP)** | 中文体验好 |
| 后端 | **Django (沿用 ASP) + FastAPI (新服务)** | Python 生态,异步支持 |
| 剧本数量 | **22 个真实企业剧本**(原 8 → 22) | 基于 [03-real-scenarios.md](03-real-scenarios.md) 调研扩展 |
| Phase 1 优先级 | **勒索病毒置顶**(原 挖矿优先) | 业务影响 + 合规处罚 + C-level 介入角度 |

---

## 1. 总体架构(5 层 + 5 级自主性 HITL 横切)

```
┌──────────────────────────────────────────────────────────────────┐
│  L5 交互层 (Copilot & Dashboard)                                │
│  ┌─────────────┐ ┌─────────────┐ ┌──────────────┐ ┌──────────┐ │
│  │ Web Console │ │ IM 群通知   │ │ CLI/Harness  │ │ MCP API  │ │
│  │ (Vite+Antd) │ │ 飞书/钉钉   │ │ ClaudeCode   │ │ SDK      │ │
│  └─────────────┘ └─────────────┘ └──────────────┘ └──────────┘ │
│       ↑ L2 双签按钮(Incident Commander + Approver)              │
└──────────────────────────────────────────────────────────────────┘
                              │
┌──────────────────────────────────────────────────────────────────┐
│  L4 智能层 (Agent Orchestration & Reasoning)                    │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  Agent 编排引擎 (11 角色:7 reactive + 4 proactive)        │  │
│  │  ┌────────────┐  ┌────────────┐  ┌────────────┐          │  │
│  │  │ Tier1 分诊 │  │ Tier2 调查 │  │ DFIR 取证  │  ...     │  │
│  │  │ (L4)       │  │ (L3)       │  │ (L3)       │          │  │
│  │  └────────────┘  └────────────┘  └────────────┘          │  │
│  │  + 4 个 Proactive: Vuln(L4) / TI(L5) / Hunt(L3) / DE(L4)│  │
│  │  + Containment Agent(L2 — 所有高危处置必经此节点)        │  │
│  └──────────────────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  LLM 网关(自主性分类器 + 路由/缓存/降级/审计)            │  │
│  │  接收每个动作的 autonomy_level (L1-L5) → 自动触发 HITL   │  │
│  │  L1→仅显示 L2→双签 L3→关键分支 L4→审计 L5→自动          │  │
│  └──────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────┘
                              │
┌──────────────────────────────────────────────────────────────────┐
│  L3 剧本层 (Playbook Engine)                                   │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  22 个真实企业剧本(按业务系统分组,详见 §4)              │  │
│  │  每个剧本 YAML 标注每个动作的 autonomy_level             │  │
│  │  + 剧本编排器(条件分支/并行/循环/超时/重试/回滚)         │  │
│  └──────────────────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  SOAR 适配器 (w5 国产 / Shuffle 适配 / 自研 Action)      │  │
│  └──────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────┘
                              │
┌──────────────────────────────────────────────────────────────────┐
│  L2 关联分析层 (Correlation & Enrichment)                       │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  事件关联引擎 (告警→案件,基于 ASP Case 模式)            │  │
│  │  + IOC 富化 (VT / AbuseIPDB / Shodan / MISP)            │  │
│  │  + 资产富化 (CMDB) + 身份富化 (LDAP/AD/SSO)             │  │
│  │  + 知识富化 (L0 框架 + L1 战术 + L3 案例 RAG 召回)      │  │
│  └──────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────┘
                              │
┌──────────────────────────────────────────────────────────────────┐
│  L1 数据采集层 (Telemetry & Detection)                         │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────┐ │
│  │ Wazuh    │ │ Suricata │ │ osquery  │ │ Sysmon   │ │ FW   │ │
│  │ (主机主) │ │ (网络)   │ │ (端点)   │ │ (Windows)│ │ /WAF │ │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘ └──────┘ │
│  + 自研 Agent(host probe: 计划任务/可疑进程/网络外连)          │
│  + 应用层 (Nginx/SkyWalking/APM) + 数据库审计 + IAM 日志       │
└──────────────────────────────────────────────────────────────────┘
```

**横切关注点:**
- **5 级自主性 HITL**(见 §3):横切所有层,LLM 网关是执行点
- **审计日志**:横切所有层,Compliance Agent(L5)统一记录
- **Evidence Pack**:横切 L3-L5,每个案件完整留痕
- **知识库反向注入**:L3 案例层 → L1 战术层(检测规则优化)

---

## 2. 数据流(从告警到处置的完整链路)

```
[业务系统/端点/网络] 
    ↓ 数据
[L1 数据采集层] ── Wazuh/Suricata/osquery/Sysmon/应用日志/IAM 日志
    ↓ 原始告警 (alerts.json, eve.json, results.json, access.log)
[L2 关联分析层] ── 事件关联 + IOC 富化 + 资产/身份/知识富化
    ↓ Case + Alert + Artifact (结构化案件,标注关联事件 + 历史相似度)
[L3 剧本层] ── 匹配场景剧本 → 编排动作链
    ↓ 执行计划(每个动作标注 autonomy_level L1-L5 + 风险评级 + 合规时限)
[L4 智能层] ── 11 Agent 协作推理(LLM 网关按 autonomy_level 自动路由)
    ├─ Tier1 分诊(L4) → 分诊 + 严重性评级 + MITRE 映射
    ├─ Tier2 调查(L3) → 7+ pivot 查询
    ├─ DFIR 取证(L3) → 时间线重建
    ├─ IR Lead(L4) → 编排处置动作链 + 风险评级
    ├─ Compliance(L5) → 审计记录 + 合规自检
    ├─ Containment(L2) → **待双签的高危处置**(必经节点)
    └─ SOC Manager(L3) → 综合判定 + 升级上报
    ↓ Evidence Pack(含 LLM 推理证据 + MITRE 映射 + 决策链)
[L5 交互层] ── Dashboard / IM / CLI
    ├─ 自动通知值班人(飞书/钉钉/Slack)
    ├─ ┌─ L2 双签审批(Incident Commander + Approver,默认 5 分钟超时)─┐
    │   │  同意 → Containment 执行                                       │
    │   │  拒绝 / 超时 → 案件升级 SOC Manager                            │
    │   └──────────────────────────────────────────┘
    └─ 执行 L4/L5 自主性动作(自动执行,异步审计)
    ↓ 反馈
[L3 剧本层] ── 记录处置结果 + 反馈到知识库
    ↓
[L4 知识库 L3 案例层] ── 案例沉淀 + Evidence Pack 归档 + 反哺 L1 战术层(检测规则优化) + 反哺 LLM 微调
```

**关键回路:**
1. **正向数据流:** L1 → L2 → L3 → L4 → L5 → 执行
2. **HITL 反馈回路:** L5 审批 → L4 Containment(确认)→ L3 剧本(更新执行状态)→ L2 案件(更新)
3. **知识反向注入:** L3 案例层 → L1 战术层(Detection Engineering Agent 用历史误报优化 Sigma rules)
4. **审计回路:** Compliance(L5)横切所有节点,独立记录 + 不依赖其他组件

---

## 3. Agent 角色定义(11 角色 + 5 级自主性)

### 3.0 设计理论基础:5 级 AI 自主性框架

参考 arxiv 论文 [Mohsin et al., 2025](03-real-scenarios.md §6.2) 提出的 SOC 任务 5 级自主性框架,我们把每个 Agent 的每个动作**都标注自主性级别**,LLM 网关根据级别自动决定 HITL(人在环)策略:

| 级别 | 名称 | 含义 | HITL 角色 |
|---|---|---|---|
| **L1** | Manual | AI 仅显示信息,人类执行所有动作 | 全程人工 |
| **L2** | Advisory | AI 推荐,人类必须批准 | **强制审批**(对应剧本里 Containment 类的"杀进程/隔离主机/封 IP")|
| **L3** | Shared | AI 在低风险自动,高风险需人 | 关键决策需人 |
| **L4** | Supervised | AI 自动执行但必须审计 | 抽样审计 |
| **L5** | Fully Autonomous | 完全自动,适合低风险场景 | 无需人 |

**实现要点**:每个剧本的每个动作标注 `autonomy_level: L1~L5`,LLM 网关根据这个字段决定:
- L1 → 仅显示,不执行
- L2 → 生成执行计划 + 等待人类审批(双轨:Incident Commander + Approver)
- L3 → 自动执行 + 复杂分支需人决策
- L4 → 自动执行 + 异步审计
- L5 → 自动执行,记录审计日志即可

### 3.1 7 个 Reactive Agent(响应告警)

| 角色 | 职责 | 自主性级别 | HITL | 主要工具 |
|---|---|---|---|---|
| **Tier1 分诊** | 接收原始告警 → 实体抽取(IOC/资产/身份) → MITRE ATT&CK 映射 → 严重性评级 → 去重/合并 | **L4** | 抽样审计 | Sigma rule lookup, ATT&CK mapper, LLM 摘要 |
| **Tier2 调查** | 上下文富化 → 7+ pivot 查询(认证历史/进程树/网络连接/文件变更) → 横向影响评估 | **L3** | 复杂调查需人 | Wazuh API, Suricata query, osquery, Threat Intel |
| **DFIR 取证** | 内存/磁盘取证 → 时间线重建 → IOC 提取 → 持久化机制定位(crontab/systemd/计划任务) | **L3** | 关键证据需人复核 | Velociraptor, Live-Forensicator, YARA |
| **IR Lead** | 综合 Tier2/DFIR 结论 → 编排处置动作链 → 风险评级 → 应急预案选择 | **L4** | 风险评级需人 | Playbook Engine |
| **Compliance** | 记录所有决策证据 → 审计日志 → 合规性检查(等保/GDPR/个保法) | **L5** | 无需人 | Audit DB, 等保基线库 |
| **Containment** | **执行处置动作**(隔离主机/封禁 IP/kill 进程/冻结账号/恢复备份) | **L2** | **强制审批**(Incident Commander + Approver 双签) | Firewall API, EDR API, IAM, Backup API |
| **SOC Manager** | 综合所有 agent 结论 → 升级判定 → 高风险案例上报 → 复盘建议 | **L3** | 升级判定需人 | Notification, Escalation |

### 3.2 4 个 Proactive Agent(主动防御)

| 角色 | 职责 | 自主性级别 | HITL |
|---|---|---|---|
| **Vulnerability Mgmt** | 持续扫描 → 漏洞匹配 CVE/EPSS → 优先级排序 → 修复建议 | **L4** | 修复决策需人(补丁/补偿措施) |
| **Threat Intel** | MISP 同步 → IOC 匹配 → 上下文关联 → 战术预判 | **L5** | 无需人 |
| **Threat Hunting** | 基于 hypothesis 的主动狩猎 → 数据查询 → 异常发现 | **L3** | 假设验证需人 |
| **Detection Engineering** | 监控检测规则有效性 → 优化 Sigma rules → 减少误报 | **L4** | 规则发布需人 |

### 3.3 自主性策略矩阵(从 [03-real-scenarios.md §6.2](03-real-scenarios.md))

| 剧本动作类型 | 自主性级别 | HITL 策略 |
|---|---|---|
| 告警分诊 / IOC 富化 / 审计日志 / 威胁情报同步 | L4-L5 | 抽样审计或全自动 |
| 调查取证 / 剧本编排 / 漏洞扫描 / 检测工程 | L3-L4 | 关键决策需人 |
| 复杂业务系统异常处置(数据恢复/账号冻结)| L3 | 关键决策需人 |
| **高危处置动作(隔离主机/杀进程/封 IP/冻结账号)** | **L2** | **强制双签审批** |

---

## 4. 22 大核心场景剧本(按业务系统分组)

> **重要更新:** 本节是 v2 版核心变更。基于 [03-real-scenarios.md](03-real-scenarios.md) 的事实驱动调研,剧本从原 8 个扩展到 22 个,**按业务系统而非攻击链组织**,并按业务影响标注 P0/P1/P2 优先级。
>
> **优先级口径:** P0 = 业务中断/合规处罚/C-level 介入级;P1 = 高频低危/中频中危;P2 = 低频/边缘场景。**勒索病毒在 v2 升至第 1 优先级,挖矿降为 P0 第 2**(理由见 03-real-scenarios.md §5)。

每个剧本结构:**触发条件 → 调查步骤 → 处置动作(每个动作标注 autonomy_level)→ 审批节点 → 知识沉淀**。

---

### 4.1 主机/端点场景(P0)

#### 剧本 1 ⭐⭐ 勒索病毒加密文件(Phase 1 第 1 优先级)

**业务影响:** **直接业务中断 + 触发等保事件上报 + C-level 介入**
**触发:** Wazuh 检测到批量文件修改(高熵后缀/.lock/.encrypted/) + Suricata 检测到勒索 IOC
**MITRE ATT&CK:** TA0040 Impact + TA0140 Ransomware + T1486 Data Encrypted for Impact

**自动调查步骤:**
1. **发现**
   - Wazuh FIM 检测批量文件修改
   - Suricata 检测勒索 C2/钱包地址/已知勒索家族
   - osquery 看进程父子关系(怀疑 PowerShell/certutil/mshta)
   - VirusTotal/MISP 比对 IOC
2. **判定**
   - 进程 hash 命中勒索家族
   - 文件熵值检测(7z+ 高熵加密特征)
   - 是否有备份副本(避免误恢复)
3. **横向**
   - 同 SMB/RDP 互信主机批量排查
   - 共享存储/域控是否被影响

**自动处置动作:**

| # | 动作 | 自主性 | 审批 |
|---|---|---|---|
| A1 | 隔离主机(防火墙禁用所有入站/出站,保留 SSH) | **L2** | **必审批** |
| A2 | 阻断勒索 C2(防火墙/HOSTS) | **L2** | **必审批** |
| A3 | 禁用 SMB/RDP 横向(防火墙策略) | **L2** | **必审批** |
| A4 | 评估备份可恢复性(从 Backup API) | **L3** | 关键决策需人 |
| A5 | **不支付赎金**(剧本强制) | L5 | 无需人(剧本级断言) |
| A6 | 备份验证后恢复 | **L3** | 恢复决策需人 |
| A7 | 24h 内向上级监管机关报告(等保/GDPR) | **L2** | **必审批** |
| A8 | 复盘 + 加固 + 知识沉淀 | L4 | 抽样审计 |

**知识沉淀:** 勒索家族 IoCs(钱包/邮箱/C2)+ 时间线 + 入侵路径 + 修复建议 → 反哺 Detection Engineering

---

#### 剧本 2 ⭐⭐ 挖矿病毒(Phase 1 第 2 优先级)

**业务影响:** CPU 占用 + 资损(算力)+ 合规(若含其他恶意行为则升级)
**触发:** Wazuh 规则命中(可疑进程/CPU 异常/外连矿池)OR Suricata 规则命中(矿池域名/IP/Stratum 协议)
**MITRE ATT&CK:** TA0040 Impact + T1496 Resource Hijacking + T1071.001 Web Protocols

**自动调查步骤:**
1. **发现**(同 03 §剧本 1)
2. **判定**(进程 hash 是否在 MISP 黑名单 + 是否有持久化)
3. **横向**(同网段/同 SSH 互信/同密码主机排查)

**自动处置动作:**

| # | 动作 | 自主性 | 审批 |
|---|---|---|---|
| A1 | 隔离主机(防火墙禁用所有入站/出站,保留 SSH) | **L2** | **必审批** |
| A2 | kill 挖矿进程 + 所有子进程 | **L2** | **必审批** |
| A3 | 清理持久化(crontab/systemd/init.d/systemd-timer) | **L2** | **必审批** |
| A4 | 删除挖矿本体(rm 二进制) | **L2** | **必审批** |
| A5 | 横向扫描并处置 | L4 | 抽样审计 |
| A6 | 加固:封禁矿池域名/IP(DNS 黑洞 / 防火墙出口) | **L2** | **高级审批** |
| A7 | 漏洞修复(若是 SSH 弱口令/Web 漏洞导致入侵) | L3 | 修复方案需人 |
| A8 | 复盘报告:完整时间线 + IoCs + 修复建议 | L4 | 抽样审计 |

**知识沉淀:** 挖矿进程 hash + 路径 + 启动参数 + 矿池域名/IP + 持久化手法 + 入侵路径

---

#### 剧本 3 ⭐ 可疑进程/计划任务创建(P0)

**业务影响:** **挖矿/勒索的前兆信号**,早发现可避免后续大事件
**触发:** Wazuh/EDR 检测到可疑进程启动 + 计划任务/服务/启动项被修改
**MITRE ATT&CK:** TA0003 Persistence + T1053 Scheduled Task + T1543 Boot/Logon Autostart

**自动调查步骤:**
1. 进程白名单校验(已知业务进程 hash/SignCert)
2. 父子进程关系分析(谁启动的?是否经由 Office/PowerShell/certutil?)
3. 文件 hash 上 VT/MISP 比对
4. 看进程命令行是否可疑(`-enc`/`-nop`/`IEX`/`DownloadFile`)

**处置:** 隔离主机(L2)+ 进程 kill(L2)+ 计划任务清理(L2)+ 文件取证备份(L3)+ 关联挖矿/勒索剧本

---

#### 剧本 4 敏感文件被篡改/误删(P0)

**业务影响:** **数据完整性 + 合规**(若涉及合同/财务/客户数据触发等保事件上报)
**触发:** Wazuh FIM 告警 + 关键目录(配置/代码/数据/证书)变更 + Wazuh who-data(谁改的、用什么命令)
**MITRE ATT&CK:** T1565 Data Manipulation + T1222 File Permissions Modification

**自动调查步骤:**
1. **变更来源判定:** Wazuh who-data 标记是谁/什么进程改的
   - 已知运维流程(运维同事用 Ansible 改的)→ L4 自动过审
   - 未知进程/可疑来源(挖矿/勒索进程)→ L2 升级审批
2. **变更内容评估:** git diff / 文件 hash 比对 + 备份恢复点定位
3. **影响范围:** 看是否涉及客户数据(grep 敏感字段)
4. **回滚能力:** 看是否有 git/备份可回滚

**自动处置动作:**

| # | 动作 | 自主性 | 审批 |
|---|---|---|---|
| A1 | 自动备份当前状态(LVM snapshot / Git commit) | L4 | 抽样审计 |
| A2 | 紧急快照关键数据(防止进一步损坏) | **L3** | 关键决策需人 |
| A3 | 若可疑来源(关联入侵剧本)→ 隔离涉事主机 | **L2** | **必审批** |
| A4 | 通知数据责任人 + 合规岗 | L5 | 自动通知 |
| A5 | 启动回滚(从 git/备份恢复) | **L3** | 回滚决策需人 |
| A6 | 24h 内向上级监管机关报告(若涉及敏感数据) | **L2** | **必审批** |
| A7 | 复盘 + 文件完整性规则调整 | L4 | 抽样审计 |

**知识沉淀:** 文件变更模式 + who-data 关联 + 回滚操作记录 + 影响范围评估

---

#### 剧本 5 主机漏洞补丁缺失(P0)

**业务影响:** **攻击面**(易被勒索/挖矿利用),合规处罚(等保要求及时修补高危漏洞)
**触发:** Wazuh Vulnerability Detector 命中 CVE + CISA KEV 收录 + EPSS 高分(>=0.5)
**MITRE ATT&CK:** 不适用(防御层场景)

**自动调查步骤:**
1. **CVE 风险评级:**
   - CISA KEV + EPSS >= 0.7 → P0 紧急
   - CISA KEV 或 EPSS >= 0.5 → P1 高
   - 其他 → P2 中
2. **影响范围:** 哪些业务系统有该漏洞(CMDB 关联)
3. **修复可行性:** 是否有可用补丁 / 是否需要重启 / 业务影响窗口
4. **临时缓解:** WAF 规则 / 防火墙阻断利用路径 / 服务关闭

**自动处置动作:**

| # | 动作 | 自主性 | 审批 |
|---|---|---|---|
| A1 | 自动通知漏洞责任团队(按 CMDB 归属) | L5 | 自动 |
| A2 | 临时缓解(WAF/防火墙阻断 EXP 路径) | **L2** | **必审批** |
| A3 | 创建补丁工单(按修复可行性建议) | L4 | 抽样审计 |
| A4 | 重要漏洞(P0/P1)→ 强制 7/30 天修复 SLA 跟踪 | L4 | 抽样审计 |
| A5 | 若已有利用迹象(关联剧本 1/2/3)→ 升级为应急响应 | **L2** | **必审批** |
| A6 | 等保合规报告(漏洞修复率)自动出 | L5 | 自动 |

**知识沉淀:** CVE + EPSS + 业务系统关联 + 修复历史 + 利用迹象(若有)

---

### 4.2 网络/边界场景(P0)

#### 剧本 6 ⭐⭐ 暴力破解/账号撞库(P0 第 3 优先级)

**业务影响:** 账号失陷入口,常触发后续勒索/数据外泄
**触发:** Wazuh/WAF/IDS 检测到短时间内大量认证失败(SSH/RDP/REST API/SSO)
**MITRE ATT&CK:** T1110 Brute Force + T1110.003 Password Spraying + T1110.004 Credential Stuffing

**自动调查步骤:**
1. 来源 IP 归属(VT/AbuseIPDB/威胁情报)
2. 攻击账号 / 命中账号
3. 是否有成功认证(账号失陷检测)
4. 同源 IP 历史行为

**处置:**

| # | 动作 | 自主性 | 审批 |
|---|---|---|---|
| A1 | 临时封禁源 IP(防火墙) | **L4** | 抽样审计(白名单机制)|
| A2 | 锁定被攻击账号 + 强制改密 | **L2** | **必审批**(避免误锁) |
| A3 | 触发 MFA 强制验证 | L4 | 抽样审计 |
| A4 | 全网同类排查(同账号是否在其他主机也被尝试) | L4 | 抽样审计 |
| A5 | fail2ban 策略调整(永久封禁) | L4 | 抽样审计 |

---

#### 剧本 7 异常出站连接(C2/矿池/暗网)(P0)

**触发:** Suricata/Wazuh 检测到非业务外连(已知 C2 IOC/矿池/暗网/Tor 出口)
**MITRE ATT&CK:** TA0011 Command and Control + T1071 + T1090 Proxy

**处置:** 隔离主机(L2)+ 阻断 C2 域名/IP(L2)+ 取证(L3)+ 关联入侵路径

---

#### 剧本 8 DDoS 攻击(P0)

**业务影响:** **业务可用性**
**触发:** 流量异常激增 + 多源 IP + 单一目标 + 服务响应时间飙升
**MITRE ATT&CK:** T1498 Network Denial of Service + T1499 Endpoint DoS

**处置:** 触发 CDN/高防 IP(L4)+ 流量清洗(L2)+ 封禁攻击源(L2)+ 通知 ISP/IDC(L3)+ 服务降级(L3)

---

#### 剧本 9 WAF 触发(注入/XSS/SSRF)(P0)

**业务影响:** Web 应用失陷入口
**触发:** WAF 命中规则 + Web 应用日志异常
**MITRE ATT&CK:** TA0001 Initial Access + T1190 Exploit Public-Facing Application

**处置:** 临时封禁源 IP(L4)+ Webshell 检测(L4)+ 关联 Webshell 剧本(剧本 10)+ 漏洞修复(L3)

---

#### 剧本 10 Webshell/网站后门(P0)

**触发:** Wazuh FIM + Web 访问日志异常 + YARA 命中
**MITRE ATT&CK:** T1505.003 Web Shell + TA0003 Persistence

**处置:** 隔离 Web 主机(L2 nginx 关站)+ Webshell 取证不删(L3)+ 关联入侵路径(L3)+ 文件上传加固(L3)

---

#### 剧本 11 横向移动(SMB/SSH/WMI)(P0)

**触发:** Wazuh 检测到异常认证(psexec/WMI/SMB/SSH)OR 异常内网扫描
**MITRE ATT&CK:** TA0008 Lateral Movement + T1021 Remote Services

**处置:** 隔离被攻陷主机(L2)+ 切断攻击路径(L2)+ 全网排查同凭证/同漏洞主机(L4)+ 凭证轮换(L2)

---

#### 剧本 12 DNS 隧道 / 异常 DNS 查询(P1)

**触发:** Suricata 检测异常长 DNS 域名/高频 TXT 查询/异常解析模式
**MITRE ATT&CK:** T1071.004 DNS + T1572 Protocol Tunneling

**处置:** 阻断可疑 DNS(L2)+ 关联数据外泄剧本(剧本 13)

---

### 4.3 应用/服务场景(P0 — 真实业务可用性)

#### 剧本 13 ⭐ 服务进程崩溃/OOM/重启(P0)

**业务影响:** **业务中断**,客户感知
**触发:** Wazuh/Sysmon APM 检测服务异常退出/OOM/重启
**MITRE ATT&CK:** T1529 System Shutdown/Reboot(若非恶意则无需映射)

**处置:** 自动拉起(L4)+ 失败告警(L5)+ 关联主机异常(资源耗尽?挖矿?漏洞利用?)+ 通知业务方(L5)

---

#### 剧本 14 Web 应用异常流量/慢请求(P0)

**业务影响:** **业务可用性 + 客户感知**
**触发:** Nginx/HAProxy/SkyWalking access log 异常

**处置:** 自动扩容建议(L4)+ CC 攻击识别(L4)+ 触发 CDN/限流(L3)+ 通知业务方(L5)

---

#### 剧本 15 数据库异常查询/慢 SQL/数据导出(P0)

**业务影响:** **数据完整性 + 性能 + 内鬼/失陷**
**触发:** 数据库审计日志 + 慢 SQL 阈值告警 + 异常导出量
**MITRE ATT&CK:** T1213 Data from Information Repositories + T1485 Data Destruction

**处置:** 阻断异常查询(L2)+ 阻断导出(L2)+ 取证(L3)+ 关联数据外泄剧本(剧本 18)+ 通知 DBA(L5)

---

#### 剧本 16 API 接口异常调用/爬虫/CC 攻击(P0)

**业务影响:** **业务可用性 + 业务损失(爬数据)**
**触发:** API 网关日志 + 异常 User-Agent/异常来源 IP/高频调用

**处置:** 限流(L4)+ 验证码挑战(L4)+ 封禁源 IP(L2)+ 通知业务方(L5)

---

#### 剧本 17 BEC 商业邮件诈骗(P0)

**业务影响:** **直接财务损失(数百万级)**,社交工程主流攻击
**触发:** 用户举报 OR 邮件网关识别冒充高管/财务
**MITRE ATT&CK:** T1566 Phishing + T1656 Impersonation

**处置:** 紧急冻结相关转账(L2 必审批,需财务+CEO 双签)+ 邮件网关阻断(L2)+ 全员预警(L5)+ 报警(L3)

---

### 4.4 数据/合规场景(P0 — 等保 2.0 强驱动)

#### 剧本 18 ⭐ 数据外泄/批量下载/上传(P0)

**业务影响:** **监管处罚 + 业务损失 + 公众形象**
**触发:** DLP 告警 + Suricata 检测大文件外传 + 异常 DNS 隧道 + 非常规时段外连
**MITRE ATT&CK:** TA0010 Exfiltration + T1041 Exfiltration Over C2 Channel

**处置:** 立即阻断出向连接(L2)+ 隔离涉事主机(L2)+ 评估数据敏感度(L3)+ 通知数据合规岗(L2)+ 24h 内向上级监管报告(L2)+ 追溯入侵路径 + 加固

---

#### 剧本 19 敏感数据访问/越权(P0)

**业务影响:** **内鬼/失陷**
**触发:** 数据库审计 + IAM 异常 + 越权访问告警

**处置:** 阻断访问(L2)+ 取证(L3)+ 通知数据合规 + HR(L3)

---

#### 剧本 20 ⭐ 日志留存缺失/审计失败(P0 — 等保 2.0)

**业务影响:** **合规一票否决(等保测评不通过)**
**触发:** 日志留存时间 < 6 个月 + 日志完整性校验失败 + 日志写入失败

**处置:** 自动告警(L5)+ 修复存储(L4)+ 回溯历史(L3)+ 通知合规岗(L5)

---

#### 剧本 21 备份失败/异常(P0)

**业务影响:** **业务连续性(勒索后无法恢复)**
**触发:** Backup API 失败 + 备份校验失败 + 备份任务中断

**处置:** 自动重试(L4)+ 多副本验证(L4)+ 通知备份管理员(L5)+ 触发勒索剧本演练

---

#### 剧本 22 合规基线偏差(等保 2.0)(P0)

**业务影响:** **合规处罚**
**触发:** 等保基线扫描器(Wazuh SCA)检测偏差

**处置:** 自动修复(可逆项 L4)+ 不可逆项需人(L3)+ 整改计划跟踪(L4)

---

### 4.5 场景汇总表

| # | 剧本 | 业务系统 | 优先级 | 自主性级别 | Phase |
|---|---|---|---|---|---|
| 1 | 勒索病毒加密文件 | 主机/端点 | **P0** | L2 主导 | **P1-1** |
| 2 | 挖矿病毒 | 主机/端点 | **P0** | L2 主导 | **P1-2** |
| 3 | 可疑进程/计划任务 | 主机/端点 | **P0** | L2 主导 | **P1-3** |
| 4 | 敏感文件被篡改 | 主机/端点 | **P0** | L4-L3 | P2 |
| 5 | 主机漏洞补丁缺失 | 主机/端点 | **P0** | L4-L3 | P2 |
| 6 | 暴力破解/账号撞库 | 网络/身份 | **P0** | L4-L2 | **P1-4** |
| 7 | 异常出站连接(C2)| 网络 | **P0** | L2 | P2 |
| 8 | DDoS 攻击 | 网络 | **P0** | L4-L2 | P3 |
| 9 | WAF 触发 | 网络/应用 | **P0** | L4 | P2 |
| 10 | Webshell | 网络/应用 | **P0** | L2-L3 | P2 |
| 11 | 横向移动 | 网络/身份 | **P0** | L2 | P2 |
| 12 | DNS 隧道 | 网络 | P1 | L2 | P3 |
| 13 | 服务进程崩溃/OOM | 应用/服务 | **P0** | L4-L5 | P2 |
| 14 | Web 异常流量 | 应用/服务 | **P0** | L4-L3 | P2 |
| 15 | 数据库异常查询 | 应用/数据 | **P0** | L2-L3 | P3 |
| 16 | API 异常调用 | 应用/服务 | **P0** | L4-L2 | P3 |
| 17 | BEC 邮件诈骗 | 邮件/社工 | **P0** | L2 | P3 |
| 18 | 数据外泄 | 数据/合规 | **P0** | L2 | P2 |
| 19 | 敏感数据访问/越权 | 数据/合规 | **P0** | L2-L3 | P3 |
| 20 | 日志留存缺失 | 数据/合规 | **P0** | L5-L3 | **P1-5** |
| 21 | 备份失败/异常 | 数据/合规 | **P0** | L4 | P2 |
| 22 | 合规基线偏差(等保)| 数据/合规 | **P0** | L4-L3 | P2 |

**Phase 覆盖:** Phase 1 = 剧本 1/2/3/6/20(勒索+挖矿+持久化迹象+账号失陷+日志合规);Phase 2 = 剧本 4/5/7/9/10/11/13/14/18/21/22;Phase 3 = 剧本 8/12/15/16/17/19。

---

## 5. 知识库设计(4 层分层架构)

> **v2 变更:** 从原来的「单层剧本模板」升级为 4 层分层架构,支持从框架标准到具体案例的完整链路。

### 5.0 4 层架构总览

```
┌─────────────────────────────────────────────────────────┐
│  L3 案例层 (Case Layer)                               │
│  - 历史案件 + Evidence Pack + LLM 推理轨迹              │
│  - 用于相似案例检索 / Few-shot Prompt                  │
├─────────────────────────────────────────────────────────┤
│  L2 剧本层 (Playbook Layer)                           │
│  - 具体剧本 YAML(22 个剧本)                            │
│  - 触发规则 + 调查步骤 + 处置动作 + autonomy_level      │
├─────────────────────────────────────────────────────────┤
│  L1 战术层 (Tactic Layer)                              │
│  - 按业务系统分类的场景知识                              │
│  - 主机/网络/应用/数据/云/身份/邮件 7 大类              │
│  - 每类包含:典型 IoC / 检测思路 / 应急要点              │
├─────────────────────────────────────────────────────────┤
│  L0 框架层 (Framework Layer)                          │
│  - MITRE ATT&CK Enterprise Tactics(14 个战术)        │
│  - NIST CSF 2.0(5 大功能)                            │
│  - 等保 2.0(三道防线 + 5 级保护)                       │
│  - MITRE D3FEND(防御技术对抗 ATT&CK)                   │
│  - MITRE ATLAS(AI 系统威胁)                            │
└─────────────────────────────────────────────────────────┘
```

### 5.1 L0 框架层(直接复用,无需自建)

- **MITRE ATT&CK Enterprise Tactics**[03 §6]:TA0040 Impact、TA0011 C2、TA0003 Persistence 等 14 个战术
- **MITRE D3FEND**:与 ATT&CK 对应的防御技术目录
- **NIST CSF 2.0**:Identify/Protect/Detect/Respond/Recover
- **等保 2.0**(GB/T 22239-2019):三道防线 + 5 级保护 + 10 个安全计算环境控制点
- **MITRE ATLAS**:AI 系统特有威胁(LLM Prompt Injection 等)— 为我们的 AI Agent 自身安全服务

**数据源:** 直接导入公开 STIX/JSON(`https://raw.githubusercontent.com/mitre/cti/master/`)+ 等保 2.0 标准正文。

### 5.2 L1 战术层(按业务系统分类)

每类包含 3 类知识:

```yaml
tactic_host:
  category: "主机/端点"
  typical_iocs:
    process_patterns: ["xmrig", "minerd", "powershell -enc", ...]
    file_patterns: ["*/.ssh/authorized_keys", "*/crontab", ...]
    network_patterns: ["Stratum 协议", "矿池域名", ...]
  detection_thinking:
    - "高 CPU + 可疑进程 = 挖矿"
    - "批量文件熵值突变 = 勒索"
    - "未签名进程 + 父子关系异常 = 前兆"
  response_essentials:
    - "隔离前先取证(Velociraptor)"
    - "kill 前先备份内存"
    - "清理持久化必须彻底"
```

7 大类:**主机/网络/应用/数据/云/身份/邮件**(对应 03 §3 的分组)。

### 5.3 L2 剧本层(22 个剧本 YAML)

每个剧本结构:

```yaml
playbook_template:
  id: "pb_ransomware_v1"
  name: "勒索病毒加密文件应急响应"
  category: "host"
  priority: "P0"
  phase: 1
  autonomy_level_default: "L2"   # 本剧本默认自主性级别
  
  triggers:
    sigma_rules: ["suspicious_mass_file_modification", "ransomware_extension_creation"]
    suricata_rules: ["ET MALWARE Ransomware"]
    wazuh_rules: ["5710", "5711"]  # Wazuh 规则 ID
  
  mitre_mapping:
    tactics: ["TA0040 Impact"]
    techniques: ["T1486 Data Encrypted for Impact", "T1490 Inhibit System Recovery"]
  
  investigation_steps:
    - id: "I1"
      name: "进程白名单校验"
      tools: ["osquery_processes", "virustotal_hash"]
      autonomy: L4
    - id: "I2"
      name: "父子进程关系"
      tools: ["sysmon_parent_child"]
      autonomy: L4
  
  containment_actions:
    - id: "A1_isolate_host"
      autonomy: L2
      approval: "double"  # 双签
      tools: ["firewall_block_host", "wazuh_active_response"]
    - id: "A7_report_regulator"
      autonomy: L2
      approval: "required"
      deadline: "24h"  # 合规时限
  
  knowledge_assets:
    iocs_db: "process_hashes, c2_ips, ransom_emails"
    ttps_db: "ransomware_family_techniques"
    cases_db: "historical_cases_for_similarity"
```

### 5.4 L3 案例层(运行时沉淀)

每个案件关闭时自动保存:

```yaml
case_record:
  case_id: "case_20260820_xxx"
  playbook_id: "pb_ransomware_v1"
  timeline: [...]            # 完整事件时间线
  evidence_packs: [...]      # LLM 推理证据
  containment_executed: [...]  # 已执行的处置动作 + L2 审批记录
  llm_reasoning_traces: [...] # LLM 决策过程(用于复盘 + 模型微调)
  outcome: "success|failure|partial"
  lessons_learned: "..."
```

**用途:**
- 相似案例检索(下次剧本启动时 RAG 召回历史案例)
- Few-shot Prompt(把成功案例给 LLM 学习)
- 模型微调数据(后期训练专用 SecOps LLM)
- Detection Engineering 优化(哪些 Sigma rules 误报率高)

### 5.5 复用现成知识源

- **Anthropic Cybersecurity Skills** (30206⭐ Apache-2.0)— 817 个结构化技能,29 个安全域
  - 直接导入 `skills/incident-response/`、`skills/malware-analysis/`、`skills/threat-hunting/`、`skills/threat-intelligence/`
  - 适配到 MCP 工具格式
  - 主要映射到 L1 战术层和 L2 剧本层

---

## 6. LLM 集成策略

### 6.1 LLM 网关(含自主性分类器)

```
                    ┌──────────────────────────┐
   ┌─────────────┐  │  LLM Gateway (FastAPI)   │  ┌──────────────┐
   │  Agent      │──│  - 自主性分类器(autonomy) │──│  Ollama 本地 │
   │  Request    │  │  - 路由/缓存/重试/降级  │  │  Qwen2.5-72B │
   └─────────────┘  │  - 审计 + Evidence Pack  │  └──────────────┘
                    │  - L1-L5 HITL 触发      │  ┌──────────────┐
                    └──────────────────────────┘  │  vLLM 自托管 │
                                                  │  DeepSeek-V3 │
                                                  └──────────────┘
                                                  ┌──────────────┐
                                                  │  云 API (备)  │
                                                  │  Claude/GPT-5 │
                                                  └──────────────┘
```

**新增 v2 能力:** 自主性分类器接收剧本的 `autonomy_level` 字段(L1-L5),自动决定:
- L1 → 仅显示 + 全程人工
- L2 → 生成执行计划 + 等待双签(Incident Commander + Approver)
- L3 → 自动执行 + 关键分支通知人
- L4 → 自动执行 + 异步审计
- L5 → 自动执行,记录审计日志

### 6.2 模型选择(推荐分级)

| 任务 | 模型 | 原因 |
|---|---|---|
| 简单分诊 | Qwen2.5-7B-Instruct(本地) | 快、便宜、够用 |
| 复杂调查/推理 | DeepSeek-V3(本地 vLLM) | 推理强,中文好 |
| 高风险决策审计 | Claude Sonnet(云 API) | 严谨,适合合规 |
| 代码生成/剧本编写 | Qwen2.5-Coder-32B(本地) | 国产,代码能力强 |

### 6.3 Prompt 模板

每个 Agent 的 Prompt 都遵循统一结构:
```
System:
  - 角色定义(你是 Tier1 分诊 Agent)
  - 能力边界(只能查询不能处置)
  - 输出格式(JSON: severity, confidence, mitre, recommendation)

Context (RAG):
  - 历史类似案例
  - 当前威胁情报
  - 资产/身份信息

User:
  - 当前告警(原始 payload)
  - 已有的关联信息
```

---

## 7. 4 阶段 MVP 路线(基于 22 个剧本重新规划)

> **v2 变更:** 原 Phase 1 是「挖矿 1 个剧本的完整闭环」,v2 改为「**勒索优先 + 6 个 P0 剧本**」,因为勒索业务影响远高于挖矿(详见 [03-real-scenarios.md §5](03-real-scenarios.md))。

### Phase 1 — MVP 核心闭环(M0 - M3,12 周)

**目标:** 跑通 **6 个 P0 剧本** 的完整闭环(勒索+挖矿+持久化+账号失陷+日志合规+服务异常),**勒索病毒剧本置顶**

**覆盖剧本(对应 §4 剧本汇总表):**
1. **剧本 1 勒索病毒**(P0 第 1)— 业务中断级,必须先做
2. **剧本 2 挖矿病毒**(P0 第 2)— 高频低危,勒索的姊妹场景
3. **剧本 3 可疑进程/计划任务**(P0 第 3)— 勒索/挖矿的前兆信号
4. **剧本 6 暴力破解/账号撞库**(P0 第 4)— 勒索的常见入口
5. **剧本 20 日志留存缺失**(P0 第 5)— 等保 2.0 强合规驱动
6. **剧本 13 服务进程崩溃/OOM**(P0 第 6)— 业务可用性第一线

**范围:**
- L1:**Wazuh(必须)** + Suricata(必须,因为勒索要网络层) + osquery(必须,因为进程/计划任务) + Sysmon(Windows)
- L2:基本告警采集 + IOC 富化(VT + AbuseIPDB + MISP) + 资产/身份富化(CMDB + LDAP)
- L3:**6 个剧本 YAML + Playbook Engine**
- L4:7 个 Reactive Agent 中优先实现 **Tier1 + Tier2 + IR Lead + Compliance + Containment**(简化版,**5 级自主性已内建在每个动作标注里**)
- L5:Web Dashboard(Vite+Antd) + 飞书/Slack 审批 + Evidence Pack

**交付:**
- 部署 Wazuh + Suricata + osquery(同主机或分离)
- Fork ASP 改造,接入 Wazuh API 替代默认 Splunk/ELK
- 6 个剧本 YAML 实现(勒索剧本含 8 个动作 + 自主性标注 + 知识沉淀)
- 飞书/Slack webhook 审批(强制双签场景)
- Ollama 集成(本地 LLM,Qwen2.5-7B + DeepSeek-V3)
- L0 框架层(MITRE ATT&CK + 等保 2.0 基线)
- L1 战术层(7 大业务系统分类)
- L3 案例层(每次剧本执行自动沉淀)

**验证:**
- **勒索场景:** 测试环境部署可控勒索样本(可控 VM,带文件加密但不含真实恶意代码),验证告警→调查→审批→处置→知识沉淀流程
- **挖矿场景:** 同上,xmrig + 矿池 mock
- **账号失陷场景:** 模拟 SSH 撞库 + MFA 绕过
- **合规场景:** 故意让日志写入失败,验证自动告警 + 通知合规岗
- **服务异常场景:** kill -9 关键服务,验证自动拉起 + 通知业务方

**Phase 1 关键里程碑:**
- M0 末:Wazuh + Suricata + osquery 上线 + Ollama 跑通
- M1 末:Fork ASP + Wazuh API 接入 + Tier1 分诊可用
- M2 末:6 个剧本 YAML 全部实现 + 飞书/Slack 审批通过
- M3 末:6 个验证场景全部跑通 + Evidence Pack 可视化

### Phase 2 — 剧本扩展到全 22 个 + DFIR 角色(M4 - M6,12 周)

**目标:** 实现**全部 22 个剧本**(已在 Phase 1 完成 6 个,本阶段新增 16 个),补齐 DFIR Agent

**覆盖新增剧本(对应 §4 剧本汇总表 P2 列):**
- 主机/端点:剧本 4(敏感文件)+ 剧本 5(主机漏洞)
- 网络/边界:剧本 7(异常出站)+ 剧本 9(WAF)+ 剧本 10(Webshell)+ 剧本 11(横向移动)
- 应用/服务:剧本 14(Web 异常流量)
- 数据/合规:剧本 18(数据外泄)+ 剧本 21(备份异常)+ 剧本 22(合规基线)

**新增能力:**
- L3:**16 个新剧本 YAML**
- L4:**DFIR Agent**(取证 + 时间线重建)
- L4:集成 **Anthropic Cybersecurity Skills** 的 `skills/incident-response/`、`skills/malware-analysis/`、`skills/threat-hunting/`、`skills/threat-intelligence/`
- L1:osquery 全网主机 + Sysmon Windows 主机
- L5:CLI/Harness Agent 接入(Claude Code)
- L1:对接国产安全设备(奇安信/深信服/启明星辰 API)— 优先做日志接入

**验证:** 全部 22 个剧本在测试环境验证,每个剧本跑 5+ 测试用例。

### Phase 3 — 完整 11 角色 + 4 个 Proactive(M7 - M9,12 周)

**目标:** 实现**完整 11 agent 角色模型** + 4 个 Proactive + 国产 LLM 调优

**新增剧本(对应 §4 剧本汇总表 P3 列):**
- 剧本 8(DDoS)+ 剧本 12(DNS 隧道)+ 剧本 15(数据库异常)+ 剧本 16(API 异常)+ 剧本 17(BEC)+ 剧本 19(敏感数据访问)

**新增能力:**
- L4:**4 个 Proactive Agent 全部上线**(Vuln Mgmt / Threat Intel / Threat Hunting / Detection Engineering)
- L2:**CMDB 集成 + 身份集成**(LDAP/AD/SSO)+ RBAC
- L5:移动端 + IM 增强(钉钉深度集成)
- L3:**剧本可视化编辑器**(低代码,基于 ASP 的 playbook 系统扩展)
- L4:LLM 网关完善(高可用/降级/缓存/审计)

**验证:** 完整 11 Agent 协作跑一个真实场景(钓鱼入口 → 暴力破解 → 勒索加密 → 数据外泄 串联)。

### Phase 4 — 国产化 + 企业级 + 模型微调(M10 - M12,12 周)

**目标:** 达到**企业生产可用 + 模型自我进化**

**新增能力:**
- L4:**用历史案例微调 Qwen/DeepSeek**(用 L3 案例层数据做 LoRA 微调,产出专用 SecOps LLM)
- L1:对接国产安全设备完整集成(奇安信态势感知/深信服 SIP/启明星辰天镜)
- L5:多租户 + 细粒度权限 + 完整审计 + 等保 2.0 三级合规
- 合规:**等保 2.0 / GDPR / 个保法** 完整适配(自动生成合规报告)
- L4:Detection Engineering Agent 自动优化 Sigma rules(基于历史误报)

**验证:**
- **性能压测**(1000 主机/10000 EPS)
- **安全审计**(自身 AI Agent 安全 + MCP server 沙箱)
- **合规自检**(等保 2.0 三级 + GDPR)
- **用户案例**(2-3 个生产客户 POC 验证)

---

## 8. 关键文件/目录结构(基于 ASP 改造)

```
secops-copilot/
├── backend/                       # Django 后端(沿用 ASP)
│   ├── apps/
│   │   ├── cases/                # 案件管理(沿用 ASP)
│   │   ├── alerts/               # 告警
│   │   ├── playbooks/            # 剧本执行引擎(自研)
│   │   ├── agents/               # Agent 编排(自研)
│   │   ├── llm_gateway/          # LLM 网关(自研)
│   │   ├── knowledge/            # 知识库(自研)
│   │   └── integrations/         # 对接 Wazuh/Suricata/osquery
│   ├── pyproject.toml
│   └── manage.py
├── frontend/                      # Vite + Antd 前端
│   └── src/
│       ├── pages/
│       │   ├── Dashboard/        # 总览
│       │   ├── Cases/            # 案件
│       │   ├── Playbooks/        # 剧本编辑器
│       │   ├── Agents/           # Agent 监控
│       │   └── Knowledge/        # 知识库
│       └── components/
├── agents/                       # Agent 配置(Wazuh-Autopilot 范式)
│   ├── tier1.triage.agent.yaml
│   ├── tier2.investigation.agent.yaml
│   ├── dfir.forensics.agent.yaml
│   ├── ir_lead.orchestrator.agent.yaml
│   ├── compliance.audit.agent.yaml
│   ├── containment.action.agent.yaml
│   ├── soc_manager.decision.agent.yaml
│   └── proactive/
│       ├── vuln_management.agent.yaml
│       ├── threat_intel.agent.yaml
│       ├── threat_hunting.agent.yaml
│       └── detection_engineering.agent.yaml
├── playbooks/                    # 剧本(YAML,22 个,标注 autonomy_level)
│   ├── phase1/                   # Phase 1 实现的 6 个 P0 剧本
│   │   ├── ransomware.yaml       # ⭐⭐ 剧本 1 — Phase 1 第 1 优先级
│   │   ├── cryptominer.yaml      # ⭐⭐ 剧本 2 — Phase 1 第 2 优先级
│   │   ├── suspicious_process.yaml  # ⭐ 剧本 3 — 持久化迹象
│   │   ├── bruteforce.yaml       # ⭐⭐ 剧本 6 — 账号失陷入口
│   │   ├── log_retention.yaml    # ⭐ 剧本 20 — 等保 2.0 强驱动
│   │   └── service_crash.yaml    # ⭐ 剧本 13 — 业务可用性
│   ├── phase2/                   # Phase 2 新增 11 个剧本
│   │   ├── sensitive_file_tamper.yaml  # 剧本 4
│   │   ├── host_vulnerability.yaml     # 剧本 5
│   │   ├── c2_outbound.yaml            # 剧本 7
│   │   ├── waf_trigger.yaml            # 剧本 9
│   │   ├── webshell.yaml               # 剧本 10
│   │   ├── lateral_movement.yaml       # 剧本 11
│   │   ├── web_traffic_anomaly.yaml    # 剧本 14
│   │   ├── data_exfiltration.yaml      # 剧本 18
│   │   ├── backup_failure.yaml         # 剧本 21
│   │   └── compliance_baseline.yaml    # 剧本 22
│   └── phase3/                   # Phase 3 新增 6 个剧本
│       ├── ddos.yaml                    # 剧本 8
│       ├── dns_tunnel.yaml              # 剧本 12
│       ├── db_anomaly.yaml              # 剧本 15
│       ├── api_abuse.yaml               # 剧本 16
│       ├── bec_fraud.yaml               # 剧本 17
│       └── sensitive_data_access.yaml   # 剧本 19
├── policies/                     # 策略/审批(5 级自主性配置)
│   ├── policy.yaml               # 全局策略(L1-L5 映射规则)
│   ├── approval_rules.yaml       # L2 强制双签规则
│   └── autonomy_levels.yaml      # 每个 agent 动作的 autonomy_level 默认值
├── knowledge/                    # 知识库(4 层分层)
│   ├── L0_framework/            # L0 框架层(只读)
│   │   ├── mitre_attack/         # MITRE ATT&CK STIX 导入
│   │   ├── mitre_d3fend/         # MITRE D3FEND
│   │   ├── nist_csf/             # NIST CSF 2.0
│   │   ├── 等保_2_0/              # 等保 2.0 标准
│   │   └── mitre_atlas/          # AI 系统威胁
│   ├── L1_tactic/               # L1 战术层(7 大业务系统)
│   │   ├── host/                 # 主机 IoC/检测/应急
│   │   ├── network/              # 网络 IoC/检测/应急
│   │   ├── application/          # 应用 IoC/检测/应急
│   │   ├── data/                 # 数据 IoC/检测/应急
│   │   ├── cloud/                # 云 IoC/检测/应急
│   │   ├── identity/             # 身份 IoC/检测/应急
│   │   └── email/                # 邮件 IoC/检测/应急
│   ├── L2_playbook/             # L2 剧本层(22 个 YAML)
│   ├── L3_case/                 # L3 案例层(运行时沉淀)
│   └── skills/                  # Anthropic Cybersecurity Skills 导入
├── mcp_servers/                  # MCP 工具 server(自研)
│   ├── wazuh_mcp/
│   ├── suricata_mcp/
│   ├── osquery_mcp/
│   ├── virustotal_mcp/
│   ├── misp_mcp/
│   ├── firewall_mcp/
│   └── edr_mcp/
├── scripts/                      # 运维脚本
├── tests/                        # 测试
├── docker-compose.yml            # 部署
├── Dockerfile
├── AGENTS.md                     # AI 开发规则
└── README.md
```

---

## 9. 关键技术决策的论证

### 9.1 为什么 Fork ASP 而不是完全自研?

- 1150⭐ MIT Django + Vite/Antd 项目,架构清晰,直接对标
- 自研成本高(3-6 月),Fork + 改造可压到 1-2 月
- ASP 的 Module→Case→Alert→Artifact 概念模型已经是行业最佳实践
- **改造重点:** 接入 Wazuh(替代 ASP 默认的 Splunk/ELK 简化版)、实现 **22 个剧本**(原 8 → 22)、集成 MCP 工具、加 5 级自主性框架

### 9.2 为什么 Wazuh 而不是自建 SIEM?

- 16611⭐ 事实开源标准,Linux 基金会旗下,中文社区活跃
- 内置 HIDS + 漏洞扫描 + 合规基线 + 文件完整性 + Sysmon 集成
- 端点 Agent + Manager + Dashboard 全套
- **对接成本:** 低(OpenSCAP REST API + Wazuh API)
- 国内有大量 Wazuh 实施经验,人才市场充足

### 9.3 为什么 MCP?

- 2026 年事实标准,Anthropic 主导,OpenAI/Google/Microsoft 跟进
- 已有大量现成 MCP server(hexstrike-ai, cve-mcp-server, mcp-for-security)
- LLM 工具调用标准协议,不需要为每个工具做定制集成

### 9.4 为什么 11 Agent 模型?

- Wazuh-Autopilot 已经验证过,587 测试通过
- 7 reactive + 4 proactive 分类清晰,职责单一
- 易于扩展,新增场景只需添加 Proactive Agent
- 符合 NIST CSF 2.0 的 Identify/Protect/Detect/Respond/Recover 五功能映射

### 9.5 为什么 5 级自主性 + L2 强制双签审批?

参考 arxiv 论文 [Mohsin et al., 2025](https://arxiv.org/abs/2505.23397) 提出的 SOC 任务 5 级自主性框架:
- **L1 Manual → L5 Fully Autonomous** 是业界共识的 AI 自主性分级
- 每个剧本动作标注 autonomy_level,LLM 网关自动决定 HITL 策略
- **L2 强制双签** 是高危处置动作(隔离主机/杀进程/封 IP/冻结账号)的安全底线
- 比原「一刀切两阶段审批」更精细 — 不同风险动作有不同审批要求
- Wazuh-Autopilot 实践已验证,587 测试通过
- 符合等保 2.0 / ISO 27001 访问控制要求
- 通过 Slack/飞书按钮实现,不增加操作复杂度

### 9.6 国产 LLM 选型理由

- DeepSeek-V3 推理能力强,中文优秀,API 价格低
- Qwen2.5 系列有 7B/32B/72B 全规格,适合本地部署
- 国产 LLM 不需要"内容审查绕道",适合企业场景
- 本地部署保证数据不出网(满足等保/金融合规)

### 9.7 为什么剧本按业务系统分组(而不是按攻击链)?

[03-real-scenarios.md §3](03-real-scenarios.md) 调研结论:
- **企业关心的不是"挖矿 vs 勒索"这种技术分类,而是"我的业务系统能不能正常跑"** — 这是 C-level 视角
- 按攻击链组织剧本(初始访问→执行→持久化→横向移动→外泄)对**安全分析师**友好,但对**业务负责人/管理层/合规岗**不友好
- 按业务系统分组(主机/网络/应用/数据/云/身份/邮件 7 类)天然对应**CMDB 资产分类**和**应急响应团队分工**
- **落地优势:** Phase 1 一个团队就能完成 6 个主机类剧本;Phase 2 网络团队接手 5 个网络类剧本;Phase 3 应用/DBA 团队各自接手对应剧本 — 与企业内部组织架构对齐
- **可观测性优势:** Dashboard 按业务系统展示风险,管理层一眼能看到「主机风险 3 个 / 网络风险 2 个 / 应用风险 1 个」,而不是「初始访问阶段 5 个 / 持久化阶段 3 个」

### 9.8 为什么勒索病毒置顶 Phase 1(而不是挖矿)?

[03-real-scenarios.md §5](03-real-scenarios.md) 详细对比了 7 个维度,核心结论:

| 维度 | 挖矿 | 勒索 | 差距 |
|---|---|---|---|
| 业务中断 | 无 | **直接中断** | 决定性 |
| 监管处罚 | 极少 | **触发等保事件上报** | 决定性 |
| C-level 介入 | 不会 | CFO/CEO 介入 | 决定性 |
| 媒体/公众关注 | 低 | **极高** | 决定性 |
| 恢复时间 | 几小时 | 几天到几周 | 10x |
| 资金损失 | 间接(算力)| **直接(赎金/赔偿)** | 100x+ |

**决策:** 勒索业务影响远高于挖矿,且勒索剧本的执行路径天然涵盖挖矿剧本(都是 L2 隔离主机 + 杀进程 + 清理持久化 + 横向排查)。**先做勒索,挖矿后续几乎是免费增量**。

---

## 10. 风险与缓解

| 风险 | 影响 | 缓解 |
|---|---|---|
| **LLM 误判**(将合法进程判为挖矿/勒索) | 高(误隔离业务) | **5 级自主性 L2 强制双签** + 白名单机制 + 灰度上线 |
| **LLM 误杀**(误执行 kill/隔离) | 高(业务中断) | L2 双签(Incident Commander + Approver)+ 黑名单(关键业务 IP/账号)+ 快速回滚 |
| **MCP server 被恶意利用** | 高 | MCP server 沙箱化 + 输入校验 + 审计日志 + MCP 协议 v0.3+ 安全特性 |
| **知识库中毒**(恶意剧本注入) | 高 | 剧本签名 + 人工审核 + 灰度上线 + L0 框架层只读 |
| **勒索剧本处置超时**(等保 24h 报告硬约束) | 高(合规处罚) | 剧本强制 deadline 字段 + 自动化报告生成 + L2 加速审批通道 |
| **合规剧本误判**(正常日志被标"留存缺失") | 中 | L4 抽样审计 + 业务白名单 + 等保基线版本管理 |
| **性能压力**(LLM 调用慢,案件堆积) | 中 | LLM 网关缓存(剧本级)+ 异步编排 + 小模型(Tier1 用 7B)分流 |
| **数据泄露**(LLM 云端 API) | 中 | 私有化部署优先,云端 API 用脱敏输入 + 审计 |
| **Agent 角色冲突**(同时发冲突处置) | 中 | Containment Agent 全局串行 + 资源锁(per-host/per-IP)+ 冲突检测 |
| **剧本失效**(新型攻击绕过) | 中 | Detection Engineering Agent 自适应 + 持续 Threat Hunting + 剧本版本管理 |
| **ASP 项目停止维护** | 低(MIT 可分叉) | MIT 协议可永久使用,关键模块自研备份 |
| **国产 LLM 被禁用/限流** | 中 | 多 LLM 路由(Qwen/DeepSeek/Claude/GPT-5)+ 离线 Ollama fallback |
| **勒索加密速度过快**(几小时破坏全盘) | 高 | M0 即部署 Wazuh FIM(文件完整性)+ 高频审计(分钟级)+ 自动快照(关键资产) |
| **BEC 邮件诈骗识别滞后**(财务被骗已转款) | 高 | 邮件网关预检测 + 财务流程二次验证 + 高风险转账强制审批 |

---

## 11. 落地前的待确认事项

按 Phase 1 启动前必须确认 vs 启动后可调整两类组织:

### 11.1 ⭐ Phase 1 启动前必须确认(否则影响代码架构)

| # | 事项 | 决策选项 | 默认建议 |
|---|---|---|---|
| **1** | **目标用户** | 企业自用 vs 产品化 SaaS | **企业自用**(允许使用 ASP MIT/Wazuh GPL-2.0/Anthropic Apache-2.0 等不同 License)|
| **2** | **部署环境** | 物理机 / 虚拟机 / 容器 / 国产化平台 | **容器(Docker Compose) + 国产化(鲲鹏/海光)CPU 兼容** |
| **3** | **网络环境** | 互联网隔离 / DMZ / 金融内网 | **金融内网(默认离线 Ollama,云 API 仅作 fallback)** |
| **4** | **合规要求** | 等保 2.0 / 关基 / 金融行业规范 | **等保 2.0 三级**(直接对应剧本 20/22 设计)|
| **5** | **LLM 选型** | 纯本地 Ollama / 国产云 API / 兼容云 API | **本地 Ollama(Qwen2.5-7B + DeepSeek-V3) + 国产云 API(可选)** |

### 11.2 Phase 1 启动后可调整(不影响核心架构)

| # | 事项 | 决策选项 | 默认建议 |
|---|---|---|---|
| 6 | 运维规模 | 100 主机 / 1000 主机 / 10000 主机 | Phase 1 用 100 主机验证,Phase 4 评估伸缩 |
| 7 | 国产设备集成 | 奇安信/深信服/启明星辰/天融信 | Phase 2 优先奇安信态势感知日志接入 |
| 8 | 国际化 | 仅国内 / 海外也有 | 仅国内,IM 优先飞书/钉钉 |
| 9 | 高危动作白名单 | 哪些主机/账号永不自动处置 | Phase 1 启动前给一份"高危业务主机清单" |
| 10 | LLM 输出审计策略 | 全量审计 / 抽样审计 / 仅 L2 审计 | Phase 1 默认全量审计(合规优先)|
| 11 | 案件保留时长 | 30 天 / 90 天 / 永久 | 归档 |
| 12 | 告警降噪策略 | 阈值 + 同源合并 + LLM 摘要 | Phase 1 用简单阈值 + 同源合并,Phase 2 加 LLM 智能合并 |

---

## 12. 立即可执行的 30 天行动计划(Phase 1 启动版)

> v2 调整:原计划是「挖矿 1 个剧本」,改为「**勒索病毒 + 挖矿 + 持久化迹象 + 账号失陷 + 日志合规 + 服务异常共 6 个 P0 剧本**」。

**Day 1-3: 环境准备 + L0 框架层**
- 申请/部署 Wazuh + Suricata + osquery 测试环境(2-3 台 VM)
- 安装 Ollama + 下载 Qwen2.5-7B + DeepSeek-V3
- Fork ASP 项目
- 导入 L0 框架层数据:MITRE ATT&CK STIX/JSON + 等保 2.0 基线库

**Day 4-7: Wazuh API 接入 + Tier1 分诊**
- 把 ASP 默认的 Splunk 适配器替换为 Wazuh API 适配器
- 实现 Tier1 分诊 Agent(L4 自主性,基于 Sigma rule 严重性映射)
- 验证告警接入 → Case 生成 → 分诊流程

**Day 8-14: 6 个 P0 剧本 YAML + L1 战术层**
- 编写 6 个剧本 YAML:`playbooks/ransomware.yaml`(剧本 1)+ `cryptominer.yaml`(剧本 2)+ `suspicious_process.yaml`(剧本 3)+ `bruteforce.yaml`(剧本 6)+ `log_retention.yaml`(剧本 20)+ `service_crash.yaml`(剧本 13)
- 每个剧本标注每个动作的 `autonomy_level: L1-L5`
- L1 战术层(7 大业务系统分类的 IoC/检测思路/应急要点)

**Day 15-21: LLM 集成 + Tier2 调查**
- 集成 Ollama 到 LLM 网关
- 实现 Tier2 调查 Agent(L3 自主性,用 LLM 生成调查步骤 + 解释)
- 验证 LLM 推理能给出有意义的处置建议
- 集成 VirusTotal + AbuseIPDB + MISP 的 MCP server

**Day 22-28: 审批闭环 + Containment Agent**
- 飞书/Slack webhook 集成
- **L2 双签审批 UI**(Incident Commander + Approver)
- Containment Agent(L2 自主性,基本动作:隔离主机/封禁 IP/kill 进程/冻结账号)
- Evidence Pack 生成 + Dashboard 展示
- L3 案例层(剧本执行后自动沉淀)

**Day 29-30: 6 场景测试验证**
- **勒索场景:** 可控 VM(带文件加密但不含真实恶意代码)
- **挖矿场景:** xmrig + 矿池 mock
- **账号失陷场景:** SSH 撞库 + MFA 绕过
- **合规场景:** 故意让日志写入失败
- **服务异常场景:** kill -9 关键服务
- **持久化场景:** 模拟可疑进程创建
- 写 README + 文档 + 录 demo 视频

**Day 30+: 评估**
- Phase 1 完成度评审
- 决定是否进入 Phase 2(扩到 22 个剧本 + DFIR Agent)

---

## 13. 参考资料(本设计引用)

### 13.1 直接对标项目(产品形态)
- [agentic-soc-platform (ASP)](https://github.com/FunnyWolf/agentic-soc-platform) — 1150⭐ MIT Django + Vite/Antd,直接对标基线
- [Wazuh-Autopilot](https://github.com/gensecaihq/Wazuh-Autopilot) — 47⭐ MIT,11 Agent 范式 + 两阶段审批 + 587 测试
- [M507/AI-SOC-Agent](https://github.com/M507/AI-SOC-Agent) — Blackhat 2025 演示代码

### 13.2 知识库与剧本来源
- [Anthropic-Cybersecurity-Skills](https://github.com/mukul975/Anthropic-Cybersecurity-Skills) — 30206⭐ Apache-2.0,817 技能 + 6 大框架映射
- [Sigma Rules](https://github.com/SigmaHQ/sigma) — 检测规则标准
- [Wazuh Rules](https://github.com/wazuh/wazuh-ruleset) — Wazuh 官方规则集
- [socfortress/Wazuh-Rules](https://github.com/socfortress/Wazuh-Rules) — 1380⭐ 高级 Wazuh 规则

### 13.3 底座与编排
- [Wazuh](https://github.com/wazuh/wazuh) — 16611⭐ XDR+SIEM 底座
- [Suricata](https://github.com/OISF/suricata) — 6558⭐ NIDS
- [MISP](https://github.com/MISP/MISP) — 6481⭐ 威胁情报共享
- [dsiem](https://github.com/defenxor/dsiem) — 446⭐ ELK 安全关联引擎
- [w5](https://github.com/w5teams/w5) — 1548⭐ 国产 SOAR

### 13.4 学术理论基础(5 级自主性框架来源)
- Albanese et al., "Towards AI-Driven Human-Machine Co-Teaming for Adaptive and Agile Cyber Security Operation Centers", arXiv:2505.06394, 2025 — https://arxiv.org/abs/2505.06394
- Mohsin et al., "A Unified Framework for Human AI Collaboration in Security Operations Centers with Trusted Autonomy", arXiv:2505.23397, 2025 — https://arxiv.org/abs/2505.23397

### 13.5 安全框架与标准
- [MITRE ATT&CK](https://attack.mitre.org/) — 攻击分类标准(L0 框架层)
- [MITRE D3FEND](https://d3fend.mitre.org/) — 防御技术标准
- [NIST CSF 2.0](https://www.nist.gov/cyberframework) — 安全框架
- [全国信安标委](https://www.tc260.org.cn) — 等保 2.0 标准(GB/T 22239-2019)

### 13.6 上游文档(项目内引用)
- [01-survey.md](01-survey.md) — 开源生态调研(本设计前置)
- [03-real-scenarios.md](03-real-scenarios.md) — 真实场景调研(v2 引入,22 剧本来源)

---

## 14. v1 → v2 变更日志

**v1 (2026-08-20 早期) → v2 (2026-08-20 当日) 主要变更:**

| 维度 | v1 | v2 | 触发原因 |
|---|---|---|---|
| 剧本数量 | 8 | **22** | 基于 03-real-scenarios.md 事实驱动调研,补充 14 个原剧本漏掉的真实业务场景 |
| 剧本组织 | 按攻击链(挖矿→勒索→数据外泄→横向移动→...) | **按业务系统**(主机/网络/应用/数据/云/身份/邮件 7 类)| 企业关心的是「业务系统能不能跑」,不是「哪个攻击阶段」 |
| Phase 1 优先级 | 挖矿优先 | **勒索病毒置顶** | 业务影响维度(中断/合规/C-level)勒索远高于挖矿 |
| Phase 1 覆盖 | 1 个剧本 | **6 个 P0 剧本**(勒索+挖矿+持久化+账号失陷+日志合规+服务异常) | 单一剧本验证价值低,6 个能验证告警-调查-审批-处置-知识闭环 |
| 自主性模型 | 一刀切「两阶段审批」 | **5 级自主性 L1-L5**(每动作标注 autonomy_level) | arxiv Mohsin et al. 2025 学术框架;不同风险动作不同审批要求 |
| 审批机制 | 两阶段审批(Incident Commander + Approver 模糊) | **L2 强制双签**(高危动作必经,5 分钟超时升级)| 明确"Incident Commander + Approver"角色和超时机制 |
| 知识库 | 单层剧本模板 | **4 层分层架构**(L0 框架/L1 战术/L2 剧本/L3 案例)| 复用 MITRE/等保 2.0 框架 + 运行时沉淀 |
| 架构图 | 5 层 | **5 层 + 5 级自主性 HITL 横切 + 4 个回路** | 横切关注点(审计/Evidence Pack/知识反向注入)显式呈现 |
| 数据采集 | Wazuh + Suricata + osquery | **+ 应用日志 + IAM 日志** | 覆盖 22 个剧本需要更全面的日志源 |
| Agent 角色 | 11 角色(自动化程度模糊) | **11 角色 + 每角色标注 autonomy_level** | 与 §3.0 自主性框架呼应 |
| 风险表 | 9 项 | **14 项**(加勒索/BEC/合规剧本专项)| 22 剧本引入新风险类型 |
| 待确认事项 | 8 项平等 | **⭐ 5 项 Phase 1 前必确认 + 7 项后可调整** | 避免后期返工 |

**保持不变的设计决策**(已验证):
- 底座:Wazuh + Suricata + osquery
- Agent 平台:Fork FunnyWolf/agentic-soc-platform(ASP) + 集成 Wazuh-Autopilot 范式
- LLM:Ollama(本地 Qwen2.5 + DeepSeek) + 云 API fallback
- Agent 通信:MCP 协议
- 编排:Playbook Engine + SOAR 适配器

**v3 候选改进(待你决定):**
- 加入 **BPMN 2.0** 剧本可视化编辑器(替代纯 YAML)
- 集成 **TheHive/Cortex** 作为外部案件管理
- 引入 **Cybereason/Elastic EDR** 作为商业 EDR 对接示例
- 加入 **CTI(网络威胁情报)** 订阅集成(Mandiant / Recorded Future)

---

**下一步:** 进入 `03-implementation-phase1.md`(待写)— Phase 1 详细实施计划,或选 1-2 个 P0 剧本(推荐勒索)写出完整剧本 YAML 模板