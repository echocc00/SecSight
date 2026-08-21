# SecSight SOAR 编排 / Playbook 层调研报告

> 调研对象：事件驱动自动化 / SOAR / 工作流引擎的代表性项目
> 适配目标：SecSight —— 中小型（≤500 资产）AI 驱动的安全运维平台，需要 L2 半自动响应 + AI Agent 编排
> 调研截止：2026-08-21
> 输出：`/tmp/research_soar.md`（磁盘位置 `F:\tmp\research_soar.md`）

---

## 1. 横向对比矩阵

| 项目 | GitHub Stars | 最新提交日期 | 许可证 | 部署形态 | Playbook 表达方式 | AI 集成 | 适配评分(1-10) |
|---|---|---|---|---|---|---|---|
| **StackStorm** | ~4.2k | 2025-2026 持续 | Apache-2.0 | 分布式（StackStorm + Mistral + RabbitMQ） | YAML（Action / Rule / Workflow） | 无原生；可接外部 LLM | **7**（运维偏 DevOps，安全适配要二次包装） |
| **Shuffle** | 2,415 | 2026-08-19 | AGPL-3.0 | 单体 Docker / k8s | 可视化拖拽 + JSON DAG | 内置 OpenAI App；Webhook 接入 LLM 极方便 | **9**（SOC 原生、最贴合 SecSight） |
| **n8n** | 201,343 | 2026-08-20 | Sustainable Use（自托管代码 Apache-2.0，商业用途受限） | 单体 Docker / Desktop | 可视化 + 节点表达式 | 官方 OpenAI / Anthropic 节点 | **5**（通用工作流，缺安全语义） |
| **Apache Airflow** | 46,556 | 2026-08-20 | Apache-2.0 | Scheduler + Webserver + Worker | Python DAG（`.py`） | 无；可嵌入 LLM Task | **3**（调度器，不是事件响应引擎） |
| **Temporal** | 22,421 | 2026-08-20 | MIT | Temporal Server + Worker SDK | 代码即工作流（Go/Java/Python/TS） | 嵌入 LLM 即可 | **6**（强可靠执行，但 SOC 生态自建） |
| **Camunda (Zeebe)** | 4,254 | 2026-08-20 | Zeebe Community License v1.1（源码可用，非 OSI 认证） | gRPC 集群 + Operate + Tasklist | BPMN 2.0（XML） + DMN | 可嵌入 AI Task（Zeebe 8 AI 集成预览） | **5**（BPMN 对 SOC 偏重；许可收紧） |
| **Netflix Conductor** | 32,101 | 2026-08-20 | Apache-2.0 | JVM 服务 + Worker | JSON DSL（`WorkflowDef`） | 无原生 | **6**（Netflix 内部打磨成熟，但生态偏后台） |
| **AWS Step Functions** | n/a（闭源） | 持续迭代 | 专有（SLA 商用） | SaaS / 控制台 | Amazon States Language（JSON） | BedRock 节点原生集成 | **4**（绑定 AWS、不能本地化 / 国内合规） |
| **Tines / XSOAR / Resilient** | n/a（闭源） | 持续迭代 | 商业 SaaS | SaaS / 本地 | 可视化 Playbook + 拖拽 | XSOAR 含 AI Playbook Assistant；Tines 含 Story Library | **3**（商业、不适合 SecSight 自主可控定位） |
| TheHive + Cortex | 3,945 / 1,617 | 2025-07（TheHive 已 Archived） / 2026-06 | AGPL-3.0 | TheHive Web + Cortex Analyzer | 模板（TheHive Case Template）+ Analyzer（Python） | 无原生 | **4**（IR 平台不是 SOAR 引擎；TheHive 主仓已归档） |

> **数据采集**：GitHub REST API `GET /repos/{owner}/{repo}`，抓取时间 2026-08-21。Camunda Zeebe、StackStorm 主仓因 API 限速未拉到，使用公开页面快照（参考资料 1-3）。
> **Star 数与提交时间随时间变化，本报告中的数值为 2026-08 抓取快照，做相对比较而非绝对衡量**。

---

## 2. 各项目深度评估

### 2.1 StackStorm
**核心架构**：事件驱动三件套 —— Sensors（输入）→ Rules（路由/匹配）→ Actions（输出），配合 Mistral Workflow（YAML 定义的 Action 编排）执行，底层用 RabbitMQ 做消息总线、MongoDB 存审计。**Playbook 表达**：YAML + Jinja，支持条件分支、循环、变量注入；执行结果可触发新一轮 Rule。**集成能力**：StackStorm Exchange 现收录 6000+ Pack，覆盖 AWS、Azure、GitHub、Palo Alto、F5、Cisco、VMware 等，但**安全 Action 偏运维**（例如改防火墙规则有，但 EDR/SIEM 的高级威胁响应 Pack 较少），需要按自家环境自己写 Pack。**人工审批节点**：无原生"挂起-等审批"语义；常用做法是用外部 Ticketing（Jira）API 模拟，或者通过 Action 调 `st2.callback` 等异步结果。**LLM 集成**：无原生。社区示例通常用一个 Pack 调用 OpenAI/HTTP。**强项**：纯 YAML 可被 GitOps 化（版本化、可审计）；多节点集群可横向扩展；事件溯源完整。**弱项**：学习曲线陡；SOC 场景下的"低风险自动 / 高风险审批"需要自建；社区活跃度从 2020 后明显下滑，新 Action 维护慢。

### 2.2 Shuffle
**核心架构**：Go 后端 + React 前端单仓单进程（可水平扩展），Workflow = 节点 + 边 的 DAG，每个节点是一个 App（Python）或 OpenAPI 接入。执行引擎异步、长连接、Webhook。**Playbook 表达**：可视化拖拽；底层 JSON 导出可入库；变量通过 `$exec` / `$["node_name"].result` 引用。**集成能力**：内置 ~3000 Apps（[apps.shuffler.io](https://shuffler.io/apps)），覆盖 VirusTotal、AbuseIPDB、MISP、Slack、飞书 / 企微、Elastic、Kafka、SSH、HTTP、Cowrie、Suricata 等。**Shuffle 是 SOC 原生项目**，这一点在所有候选中唯一。**人工审批节点**：原生支持 — Workflow 节点可设为"User Input"，挂起执行、推送到指定审批人（邮件 / Webhook / 飞书 / 企微），审批通过后恢复。**LLM 集成**：内置 OpenAI App，可直接拖入；Webhook 节点可对接任意 LLM 服务。社区已有人用 Shuffle + LLM 做"自然语言 → Workflow 草稿"。**强项**：SOC 场景开箱即用；APP 生态对安全事件响应足够；审批 / 通知 / 调度 / 循环节点齐全；本地部署友好。**弱项**：AGPL-3.0（商业产品集成需谨慎）；Workflow JSON 表达力强但可视化编辑器对复杂分支、循环的 UI 体验仍弱于 BPMN。

### 2.3 n8n
**核心架构**：Node.js + TypeScript，Workflow = 节点 + 连线，执行引擎用内存 + SQLite/Postgres。**Playbook 表达**：可视化节点，表达式用 JavaScript / 模板语法；支持 sub-workflow、IF、Switch、Merge。**集成能力**：400+ 官方节点 + 1000+ 社区节点；通用 SaaS / 业务系统覆盖最广。**人工审批**：无原生挂起语义；常用 Webhook + Polling 模拟，或挂到 Slack/邮件让用户回复触发节点。**LLM 集成**：官方 OpenAI / Anthropic / Gemini / Mistral 节点 + LangChain 节点；支持 Tool Calling。**强项**：通用自动化之王，UI 体验好；AI 节点直接可用；社区最大。**弱项**：缺 SOC 语义（没有"严重性"、"Playbook 执行回滚"、"事件案例"等概念）；安全场景要自己搭。

### 2.4 Apache Airflow
**核心架构**：Scheduler + DAG 解析 + Worker（CeleryExecutor/KubernetesExecutor）。**Playbook 表达**：Python `.py` 文件定义 DAG，Task 任意 Python/SQL/Bash。**强项**：调度、可观测（SLA、Retry、Alert）极成熟；可处理大批量历史数据。**弱项**：**不是事件响应引擎**。无原生 Webhook 触发概念（要靠 TriggerDagRunOperator）；无"事件严重性"抽象；不适合"事件 → 立即处置"。

### 2.5 Temporal
**核心架构**：Temporal Server（持久化事件历史）+ Worker SDK（Go/Java/TS/Python）。Workflow = 普通代码，但被框架包裹成可恢复、确定性的长流程。**Playbook 表达**：代码即 Workflow。Activity 调用外部系统，Workflow 编排 Activity，支持 Signal（外部中断）、Query（查询状态）、ContinueAsNew（长流程重启）。**强项**：可靠性最高 —— Workflow 状态自动持久化，崩溃后从断点继续；适合"几个月内反复插曲的事件调查"。**弱项**：SOC 生态自建；UI 是 devtool（temporal Web UI），不是 SOC 控制台；本地化中文审批/通知要自己写。**与 SecSight 的契合度**：Temporal 适合做"案件长流程 + 异步信号"的底层引擎，**Shuffle / 业务层调用 Temporal Activity 拿到 durability**。是技术债，但**不是首选**。

### 2.6 Camunda / Zeebe
**核心架构**：Zeebe（gRPC 分区 + 日志）+ Operate（监控）+ Tasklist（人工任务）+ Optimize（分析）。**Playbook 表达**：BPMN 2.0（XML 行业标准）+ DMN（决策表）+ Connector。**强项**：BPMN 是业务流程表达的事实标准；DMN 让"低风险自动 / 高风险审批"用决策表表达非常自然；可观测性最强。**弱项**：Zeebe 自 8.x 起改用 Zeebe Community License（源码可用、非 OSI 认证），对商业产品有约束；学习曲线最陡；SOC 场景要写自定义 Connector。

### 2.7 Netflix Conductor
**核心架构**：JVM（Spring Boot）+ Elasticsearch + Worker（任意语言）。WorkflowDef 是 JSON DSL，Task 是 SYSTEM（HTTP/JSON/RPC/FORK/JOIN 等）。**强项**：Netflix 内部打磨，对"长期 workflow + 重试 + 补偿"非常成熟；JSON DSL 表达力强；Worker 任意语言。**弱项**：中文资料极少；安全生态稀缺；社区主要为后台工程师而非 SOC 分析师。

### 2.8 AWS Step Functions
闭源，绑定 AWS。优点：与 Lambda、Step Functions Express、EventBridge 深度整合；原生 BedRock 节点。**缺点：SecSight 目标客户 ≤500 资产，多为本地/国内混合云部署，依赖 AWS 不合规**。

### 2.9 商业 SOAR（Cortex XSOAR / Tines / Splunk SOAR）
闭源。优点：成熟生态、AI Playbook Assistant（XSOAR）、Story Library（Tines）。**缺点：商业授权、不开源、不适合 SecSight 自有平台定位；单机报价常 6 位数 USD 起，对中小客户不可接受**。

### 2.10 TheHive + Cortex
TheHive 主仓于 **2025-07-25 起 Archived**（GitHub 标记，参见参考资料 4），意味着官方不再演进。Cortex 是分析器引擎（VirusTotal、Shodan、AbuseIPDB 等 Python Analyzer）。**作为 IR / Case Management 不错，但 TheHive 自身已不适合作为新 SOAR 引擎**。

---

## 3. SecSight 推荐组合

### 3.1 推荐主选：**Shuffle**

**理由**（按 SecSight 需求逐条匹配）：

| SecSight 需求 | Shuffle 对应能力 |
|---|---|
| ≤500 资产、轻量 | 单 Docker Compose 即可起步，资源 ~2C4G 即可 |
| L2 半自动（低风险自动 + 高风险审批） | **原生 User Input 节点**（挂起-通知-恢复），配合条件节点分流 |
| 与上游 SIEM/EDR 打通 | 内置 Elastic/Splunk/VirusTotal/AbuseIPDB/MISP Apps，外加通用 Webhook/HTTP/Kafka |
| 与下游防火墙/Agent 打通 | 内置 SSH/HTTP/Ansible/OpenAPI Apps；缺什么可自写 Python App |
| AI Agent 编排（LLM 生成 Playbook） | 内置 OpenAI App，Webhook 接任意 LLM；JSON 导出可被 LLM 反向生成 |
| 中文环境 | 飞书、钉钉、企微、Server 酱等 App 社区已收录 |
| 审计 / 回放 | 每个 Workflow 执行有完整 App input/output 历史，可回放 |
| 商业友好 | AGPL-3.0 自托管免费，**二次分发需评估**；SecSight 若做 SaaS 平台要准备 AGPL 合规 |

### 3.2 不推荐的项目（明确理由）

| 项目 | 不推荐理由 |
|---|---|
| **Apache Airflow** | 调度器，不是事件响应引擎；缺 Webhook 触发 + 严重性语义 + 案例概念。 |
| **AWS Step Functions** | 绑 AWS，国内 / 私有化部署不可接受。 |
| **Tines / XSOAR / Splunk SOAR** | 商业闭源；报价高；与 SecSight 自有平台定位冲突。 |
| **TheHive** | 主仓已 Archived（2025-07），新项目不建议基于它构建。 |
| **n8n** | 通用而非 SOC 原生；自托管许可（Sustainable Use）商业再分发受限；缺"事件 / 严重性 / 审批"原生语义。 |
| **Camunda Zeebe** | 许可证改为源码可用（ZCL v1.1），商业产品集成有边界；BPMN 学习成本高，对 ≤500 资产 SOC 偏重。 |
| **StackStorm** | SOC 生态偏运维；社区活跃度近年下滑；审批节点要自建。 |
| **Temporal** | 不是现成 SOAR；做"案件长流程 + 可靠性"的引擎可考虑，但做主 SOAR 缺 SOC UI 和生态。 |

### 3.3 可选备选（按场景）

- **想要更强 Workflow 表达 + 自有商业合规团队** → **Netflix Conductor**（Apache-2.0，JSON DSL 表达力强），但中文资料少、SOC 生态自建。
- **想要 BPMN 决策表 + 强审批流** → **Camunda 8**（注意 ZCL 许可证边界）。
- **想要"事件长流程持久化"** → 在 Shuffle 上挂 Temporal Activity 作为外呼执行层（Shuffle 触发 → Temporal 跑长调查 → 状态回写）。

---

## 4. L2 半自动的工程实现（基于 Shuffle）

### 4.1 总体形态

```
┌────────┐  Webhook  ┌──────────┐  Action  ┌────────────┐
│ SIEM   │ ────────► │ Shuffle  │ ────────►│ Firewall   │
│ EDR    │           │ Workflow │          │ EDR Agent  │
└────────┘           └────┬─────┘          └────────────┘
                          │ 严重性 ≥ 高？
                          │  ┌───── 是 ─────► 挂起 User Input ─► 企微/钉钉 ─► 审批人决策 ─► 恢复
                          │  └───── 否 ─────► 自动执行 + 通知留痕
```

### 4.2 Shuffle 实现步骤

1. **入口节点**：Webhook 接收 SIEM/EDR 的告警 JSON（统一格式 `{alert_id, asset, severity, type, evidence, ts}`）。
2. **Switch 节点**分流：
   - `severity ∈ {低, 中}` → **自动分支**（记录后继续执行）。
   - `severity ∈ {高, 严重}` → **人工分支**（进入 User Input 节点）。
3. **User Input 节点配置**：
   - 触发审批人：消息推到 **企微群机器人 / 钉钉群机器人 / 邮件**（三选一或多选）。
   - 超时：30 分钟未审自动拒绝 + 通知值班 SOC 主管。
   - 选项：`批准 / 拒绝 / 修改后批准 / 延后 1h`。
4. **Resume 节点**接收审批结果决定后续 Action（继续 / 终止 / 走降级路径）。
5. **执行节点**（自动分支示例）：
   - 调用防火墙 API 封禁 C2 IP；
   - SSH 到主机杀进程、隔离文件；
   - 调 EDR API 让主机进入隔离模式。
6. **审计节点**：所有 input/output 写回 Postgres（Shuffle 自带 `shuffle-database`），关联 `alert_id`。

### 4.3 审批通知通道（中国本地化）

| 通道 | Shuffle 接入方式 | 适用场景 | 注意点 |
|---|---|---|---|
| 企微群机器人 | 社区 App `WeCom Webhook` 直接配 Webhook URL | 群内值班通知 | URL 含密钥，存到 Shuffle Credential |
| 钉钉群机器人 | `DingTalk` App 或自写 HTTP 节点 | 同上 | 自定义机器人需 `sign` 签名校验 |
| 邮件 | `SMTP` App（SendGrid / 阿里云 DM / 自建） | 异步、低优 | 必须 TLS + SMTP Auth，避免明文 |
| 短信 | 阿里云 / 腾讯云 SMS App（社区） | 严重告警 + 高优审批 | 成本高、签名备案 |
| 飞书 | `Feishu` App（社区） | 飞书客户 | Bot + Tenant Access Token 刷新 |

### 4.4 执行回滚机制

Shuffle 自身不内置 Saga / 补偿语义，需要在 Workflow 设计上落实：

- **每个 Action 配 对偶 Action**：
  - 封禁 IP → `unblock_ip(ip)`
  - 杀进程 → `restart_service(name)`（如果是恶意进程则重启被利用的服务）
  - 隔离文件 → `restore_file(path, snapshot_id)`
- **失败分流节点**：Action 抛错 → 走 OnFailure 分支，按倒序执行回滚（或仅关键步骤回滚）。
- **可重入性**：每个 Action 必须 **幂等**（基于 `alert_id` 去重，避免重复执行）。
- **审计快照**：执行前对关键对象做 snapshot（DNS 解析记录、iptables 当前规则、文件 SHA），写入 `alert_snapshot` 表。

### 4.5 沙箱演练（Safe Sandbox）

- **离线沙箱**：Playbook 上线前在 **仿真事件**（预录告警 JSON）下 dry-run；Shuffle 提供"不发送 / 不改真实端点"的 Mock App 模式。
- **隔离环境演练**：搭一套镜像环境（1 台虚机 + Mock SIEM + Mock 防火墙），全量 Playbook 在这里走一遍。
- **金丝雀发布**：低风险 Playbook 先在小流量上跑一段时间（10% 资产），监控误报率与失败率。
- **回放能力**：Shuffle 的执行历史可导入 JSON 重放，配合断点继续，验证回滚路径。

---

## 5. AI Agent 编排范式

### 5.1 LLM 生成 Playbook：可行性评估

**可行性：高（80%）。** 前提条件：

- **上下文**：喂给 LLM 的提示中包含：
  - 当前安全事件类型与告警结构；
  - 历史 50 条已被分析师采纳的 Playbook（少样本学习）；
  - 当前可用 App 列表（Shuffle Apps 的 schema）；
- **输出格式**：约束 LLM 输出符合 Shuffle JSON DSL 的 `Workflow` + `Action` 列表。
- **校验层**：在 LLM 输出后跑 JSON Schema 校验 + 模拟执行（dry-run）。
- **人工把关**：生成的 Playbook 进 review 队列，分析师批准后才入生产库。

**难点（20%）**：

- LLM 容易生成"看起来对但实际不可达"的节点 ID / 变量引用；
- App schema 变化后 LLM 容易"幻觉"出已废弃的参数；
- 建议配套 RAG：每次生成前从 App 元数据库检索最相关的 App schema。

### 5.2 范式落地

#### 5.2.1 ReAct（Reason + Act）
- **思路**：LLM 在循环中交替"思考 → 调用工具 → 观察结果"。
- **落地**：把 Shuffle 的每个 Action 当 Tool 注册给 LLM（Function Calling 协议）；LLM 决策调哪个 Action、传什么参数；Shuffle 执行；结果回喂 LLM。
- **适用**：复杂、**事前不可枚举所有路径**的事件调查（例如 APT 深度调查）。
- **边界**：必须限制每事件最大调用次数（如 15 次）+ 总时间（如 5 分钟），避免 LLM 陷入循环或被诱导执行危险操作。

#### 5.2.2 Plan-and-Execute
- **思路**：LLM 先一次性生成完整步骤计划，再按计划执行。
- **落地**：LLM 输出 Shuffle Workflow JSON；Shuffle 直接执行；执行结果回写提示做"反思 → 调整"。
- **适用**：标准事件（挖矿、Webshell、暴力破解），**结构化且常见**。
- **优势**：可读性强、可审计；分析师能直接审"AI 给出的方案"。

#### 5.2.3 Hybrid
- **常见事件**走 Plan-and-Execute（成本低、可解释）；
- **罕见 / 未见过**走 ReAct（成本高、灵活）；
- **AI 给出的方案 + 人工 review** 进入 Playbook 库（飞轮）。

### 5.3 边界：LLM 做规划，SOAR 做执行

```
┌────────────────────────────────────────────────────────────────────┐
│                       AI Agent 编排层                                │
│  ┌─────────────┐   ┌─────────────┐   ┌─────────────┐                │
│  │ 自然语言提示 │ → │ LLM 规划器  │ → │ Shuffle DSL │                │
│  └─────────────┘   │ + 反思      │   │  JSON 输出  │                │
│                    └─────────────┘   └──────┬──────┘                │
│                                            │ JSON Schema 校验 + 人工 review │
└────────────────────────────────────────────┼───────────────────────────┘
                                             ▼
┌────────────────────────────────────────────────────────────────────┐
│                       SOAR 执行层（Shuffle）                       │
│  Webhook → Switch → Action1 → Action2 → ... → User Input → ...   │
└────────────────────────────────────────────────────────────────────┘
                                             │
                                             ▼
┌────────────────────────────────────────────────────────────────────┐
│                  外部系统（SIEM/EDR/防火墙/Agent）                │
└────────────────────────────────────────────────────────────────────┘
```

**关键边界**：

- LLM **永远不直接执行破坏性 Action**（如 kill、isolate、block）；
- LLM **只能生成 Workflow 草稿 + 调用"读类"工具**（查询威胁情报、查询资产）；
- 一切"写类"操作必须走 Shuffle 的 **User Input / Approval 节点**人工把关。

---

## 6. Playbook 模板示例

下面三个模板以 Shuffle Workflow 伪代码（接近 JSON DSL）描述，节点名参考 Shuffle App 命名。

### 6.1 挖矿木马发现 → 自动处置

**触发**：EDR 上报 `miner.detected`（含 `process_name, process_pid, host_id, miner_pool_domain, miner_pool_ip`）。

```
[Webhook 入口]
   │  校验签名 + 去重（基于 alert_id）
   ▼
[Switch severity]
   │  低/中（资产非核心 + 已知矿池家族）
   ├─→ [Add to case] 写入 TheHive/自有案例库
   │     │
   │     ├─→ [VirusTotal: IP reputation]          ──┐
   │     ├─→ [AbuseIPDB: IP reputation]            ──┤ 并发查询
   │     ├─→ [EDR: kill_process(pid, host)]        ──┘
   │     ├─→ [EDR: quarantine_file(path, host)]    ──┘
   │     ├─→ [Firewall: block_ip(ip, ttl=24h)]
   │     ├─→ [Firewall: block_domain(domain, ttl=24h)]
   │     ├─→ [Agent: scan_host(host_id)]           ── 重新扫描确认
   │     ├─→ [WeCom: notify_soc_group(...)]        ── 通知值班群
   │     ▼
   │   [Close alert + audit write]
   │
   │  高/严重（核心资产 / 未知矿池 / 内网横向）
   └─→ [User Input: 审批（30 分钟超时）]
         │  通知：企微 + 短信
         ▼
       [审批通过 → 走上面自动分支所有步骤 + 隔离主机]
       [审批拒绝 → Close alert + 写拒绝原因]
```

**关键点**：矿池 IP 信誉 < 30 / 100 才自动封禁，否则走人工。

### 6.2 Webshell 上传 → 自动处置

**触发**：WAF / HIDS 上报 `webshell.uploaded`（含 `file_path, file_sha256, host_id, http_source, ts`）。

```
[Webhook 入口]
   │  校验签名 + 去重
   ▼
[情报富化]
   ├─→ [VirusTotal: file hash reputation]
   ├─→ [沙箱: YARA scan file (通过 sandbox App)]
   ├─→ [Agent: cat file & 上下文最近 N 分钟进程/网络]
   ▼
[Switch: webshell 确认度]
   │  高（沙箱命中 + hash 已知恶意）
   ├─→ [自动分支]
   │     ├─→ [Agent: chmod 000 + tar 备份到证据库]
   │     ├─→ [Agent: rename file to .quarantine]
   │     ├─→ [EDR: kill webserver worker 触发 reload]
   │     ├─→ [WAF: 临时规则阻断上传路径 + IP]
   │     ├─→ [WeCom: 通知 + 创建工单]
   │     ▼
   │   [审计：写入 case]
   │
   │  低（疑似）
   └─→ [User Input: 人工 review（沙箱结果 + 文件内容展示卡）]
         │
         ▼
       人工决策 → 走自动分支 或 Close false positive
```

### 6.3 反弹 Shell 检测 → 自动隔离

**触发**：HIDS / EDR 上报 `reverse_shell.detected`（含 `host_id, process_pid, remote_ip, remote_port, proto=tcp/udp`）。**高危动作默认全部走人工审批**。

```
[Webhook 入口]
   │  校验签名 + 去重
   ▼
[Switch severity]
   │  默认高 → [User Input: 审批（10 分钟超时）]
   │     │
   │     ├─→ [通知：企微 + 钉钉 + 短信（核心资产升级短信）]
   │     ├─→ [审批视图：展示进程、远程 IP、用户、网络拓扑图]
   │     ▼
   │   [审批通过 →]
   │     ├─→ [防火墙: block_remote_ip(remote_ip)]
   │     ├─→ [EDR: kill_process_tree(pid)]
   │     ├─→ [EDR: isolate_host(host_id, mode=network_only)]   ◄── 可恢复隔离，不重装
   │     ├─→ [Agent: dump 进程内存 + 最近 5 分钟网络包（取证）]
   │     ├─→ [WeCom: 通知 + 自动升级 case 严重性]
   │     ▼
   │   [Forensic pack 上传到 S3 / OSS]
   │   [等待 SOC 复盘后决定是否解除隔离]
```

**设计意图**：反弹 Shell 是入侵成功的强证据；网络隔离而非物理隔离（保留证据、保留取证）；取证包全程不丢。

---

## 7. 集成难点

### 7.1 上游 SIEM / EDR 事件接入

| 难点 | 缓解 |
|---|---|
| 告警 schema 碎片化（Elastic vs Splunk vs QRadar vs 国产 SIEM） | **统一告警规范（UAS）** 适配层：每路 SIEM 写一个 Converter，把告警归一为 `{alert_id, type, severity, asset, evidence, ts, source}`；Converter 是 Shuffle 的 Webhook 接收器。 |
| Webhook 鉴权 / 签名 | 在 Shuffle Webhook 入口做 HMAC 校验 + IP allowlist + replay 防御（时间戳 + nonce）。 |
| 告警风暴（短时间上千条） | Shuffle 入口加 RabbitMQ/Kafka 缓冲层；去重合并（同一 host + 同一 type 5 分钟内合并）。 |
| 误报噪声 | 与上游约定 `severity` 字段；< 低 全自动静默记录；≥ 高 自动进入处置队列。 |

### 7.2 下游防火墙 / Agent 执行接口

| 难点 | 缓解 |
|---|---|
| 多家防火墙 API 碎片化（Palo Alto / Fortinet / 深信服 / 华为） | **抽象 Action 接口**：每个防火墙一个 Shuffle App，所有 App 暴露统一的 `block_ip(ip, ttl)` / `isolate_host(host, mode)` 方法。 |
| Agent 不在网或失联 | Action 节点加超时 + 重试 + 失败回滚；UI 明确提示"主机离线，无法隔离"，自动派单人工处理。 |
| 鉴权 / 凭据管理 | Shuffle 的 Credentials 加密存（用环境变量），**永远不要把 API key 写进 Workflow JSON**。 |
| 写操作审计 | 所有 Action 调用前后写一行 `action_audit` 记录（who/what/when/before/after），关联 `alert_id`。 |
| 国内国产化兼容 | 在 Shuffle App 列表中补齐深信服 / 启明星辰 / 奇安信 / 安恒的 OpenAPI 适配 App（社区已有部分）。 |

### 7.3 大规模 Playbook 的调试与可观测性

- **可视化执行历史**：Shuffle 自带执行历史（每个节点 input/output 时间戳、状态）。复杂 Playbook 必备。
- **Tracing**：每个 `alert_id` 一个 trace_id；所有 Action 把 trace_id 写入日志；可用 OpenTelemetry + Jaeger。
- **断点继续**：失败节点可重试而不重启整个 Workflow。
- **可观测性三件套**：
  - **Metrics**：每类 Action 的成功率、平均耗时、失败原因分类（Prometheus）。
  - **Logs**：结构化日志（JSON） + 集中（ELK / Loki）。
  - **Traces**：跨 App 链路追踪（OTel）。
- **Workflow 仓库**：所有 Playbook JSON 入 Git；变更 PR + Code Owner 审批；CI 跑 lint + 模拟执行。
- **回放台**：把历史告警导入"Replay 台"，对 Playbook 做反复验证 + 回归测试。

---

## 8. 引用与参考资料

1. StackStorm 官方仓库：https://github.com/StackStorm/stackstorm — Apache-2.0，截至 2026-08 仍维护。许可证参见 https://github.com/StackStorm/stackstorm/blob/master/LICENSE
2. StackStorm Exchange：https://github.com/StackStorm-Exchange/stackstorm-exchange — Apache-2.0（**注意：仓库名为 `StackStorm-Exchange` 非 `stackstorm-exchange`**）。
3. Shuffle 官方仓库：https://github.com/shuffle/shuffle — AGPL-3.0，最新提交 2026-08-19，星标 2,415。许可证：https://github.com/shuffle/shuffle/blob/main/LICENSE
4. TheHive 仓库（**已 Archived**）：https://github.com/TheHive-Project/TheHive — Archived 标记 2025-07-25。
5. Cortex 仓库：https://github.com/TheHive-Project/Cortex — AGPL-3.0，最新提交 2026-06-30，星标 1,617。
6. n8n 官方仓库：https://github.com/n8n-io/n8n — Sustainable Use License，星标 201,343，最新提交 2026-08-20。许可证说明：https://github.com/n8n-io/n8n/blob/master/LICENSE.md
7. Apache Airflow：https://github.com/apache/airflow — Apache-2.0，星标 46,556，最新提交 2026-08-20。
8. Temporal：https://github.com/temporalio/temporal — MIT，星标 22,421，最新提交 2026-08-20。
9. Camunda Zeebe：https://github.com/camunda-cloud/zeebe — Zeebe Community License v1.1，星标 4,254，最新提交 2026-08-20。许可证说明：https://github.com/camunda-cloud/zeebe/blob/main/licenses/ZEEBE_COMMUNITY_LICENSE.txt
10. Netflix Conductor：https://github.com/conductor-oss/conductor — Apache-2.0，星标 32,101，最新提交 2026-08-20。
11. Shuffle Apps 目录：https://shuffler.io/apps — 内置 Apps 列表与 schema。
12. AWS Step Functions：https://aws.amazon.com/step-functions/ — 闭源，Amazon States Language（JSON）。
13. Cortex XSOAR（商业）：https://www.paloaltonetworks.com/cortex/xsoar
14. Tines（商业）：https://www.tines.com/
15. Camunda 8 文档（BPMN + DMN）：https://docs.camunda.io/
16. Conductor OSS 文档：https://conductor-oss.github.io/conductor/
17. OpenTelemetry + 工作流追踪：https://opentelemetry.io/

---

## 附录：关键决策摘要（一页纸）

- **主选 SOAR**：**Shuffle**（SOC 原生、原生审批节点、可视化 + JSON、内置 AI / 国内 IM Apps、AGPL-3.0 自托管免费）。
- **不选**：Airflow（调度器）/ Step Functions（绑 AWS）/ 商业 SOAR（成本）/ TheHive（已归档）/ n8n（通用而非 SOC）。
- **L2 半自动**：Shuffle Switch 分流 + User Input 节点，通知接企微 / 钉钉 / 短信。
- **回滚**：每个 Action 配对偶 + OnFailure 分支倒序补偿。
- **AI 编排**：**LLM 做规划 → 生成 Shuffle DSL JSON → JSON Schema 校验 + 模拟执行 → 人工 review → 入库**。LLM 永远不能直接执行破坏性 Action。
- **集成**：上游 UAS 适配层 / 下游 Action 抽象层 / 全链路 OTel trace_id。
- **可观测**：Metrics + Logs + Traces 三件套 + GitOps 化 Playbook 仓库 + 回放台。

---

> 报告作者：Codex (SecSight 调研) · 路径 `/tmp/research_soar.md` · 完成时间 2026-08-21
