# SecSight 平台 — 整体架构与实施规划

> **文档版本**: v1.0 (初版)
> **编制日期**: 2026-08-21
> **基于**: 7 份子领域调研报告（共 218 KB / 3,734 行，详见 [docs/research/](research/) 目录）
> **目标读者**: 安全工程师 / 项目经理 / 投资人 / 内部架构评审委员会

---

## 0. TL;DR — 一句话讲清楚

**SecSight** 是一个面向中小型企业（≤500 资产）的 **AI 驱动安全运维平台**，通过集成 7 层开源技术栈（Wazuh + Suricata + OpenSearch + OpenCTI + Shuffle + Nuclei/Trivy + LangChain/Qwen2.5），把传统 SOC 的“采集→告警→人工分析→处置”流程压缩为 **“采集→AI 研判→半自动响应”**，覆盖挖矿/勒索/反弹 Shell/横向移动/Web 攻击/云原生/内部威胁 7 大场景。

**关键决策**：**不重新发明轮子**——核心检测、SIEM、SOAR、漏洞扫描全部用成熟开源项目，SecSight 自身只做 **AI 研判编排 + 场景化 Playbook + 统一事件总线** 这层“胶水+大脑”。

---

## 1. 项目定位与目标

### 1.1 用户场景

| 维度 | 目标用户 | 规模 |
|---|---|---|
| **企业规模** | 中小型（IT 资产 50-500 台，混合云或纯内网） | 50-500 端点 |
| **团队规模** | 1-5 人 SOC 团队 / CISO + 1-2 安全工程师 | 1-5 人 |
| **行业** | 金融科技、互联网、医疗、政企、教育、电商 | — |
| **当前痛点** | 买了防火墙/漏扫却没人盯告警；半夜告警轰炸无法响应；出事只能事后翻日志 | — |

### 1.2 核心价值

| 价值 | 量化指标 |
|---|---|
| **降噪** | 告警量从日均 10,000+ 条聚合为 10-50 条研判事件（降噪比 > 200:1） |
| **响应提速** | 挖矿/Webshell 等典型场景从发现到处置 < 5 分钟（含 L2 审批） |
| **场景覆盖** | 7 大类高发安全场景开箱即用，无须从零编写规则 |
| **私有化** | 全部组件可离线部署，敏感告警日志不出内网 |
| **AI 三合一** | 研判分析 + 编排执行 + 知识检索共用一套 LLM + RAG，知识沉淀复用 |

### 1.3 非目标（明确不做的事）

- ❌ 不做商业 SIEM 替代（不与 Splunk/IBM QRadar 正面竞争）
- ❌ 不做大型企业市场（≥5000 资产暂不在 v1 范围）
- ❌ 不做硬件安全设备（不与深信服/奇安信等网安厂商竞争）
- ❌ 不做主动渗透测试（被动检测 + 半自动响应为边界）
- ❌ 不强制替代已有 EDR/WAF（可作为它们的“AI 上层”）

---

## 2. 推荐技术栈（7 层 + 选型依据）

### 2.1 主力技术栈一览

| 层 | 选型 | 许可证 | 评分 | 不选谁 |
|---|---|---|---|---|
| **L1 主机 EDR** | **Wazuh** + Sysmon-Modular + Falco | GPL-2.0/MIT/Apache-2.0 | 9.5/8.0/8.5 | OSQuery 单独/Velociraptor(AGPL) |
| **L2 网络检测** | **Suricata** + Arkime + Coraza WAF + CrowdSec | GPL-2.0/Apache-2.0 | 9/9/8.5/9 | Snort 3/ModSecurity v3 |
| **L3 SIEM/日志** | **OpenSearch** | Apache-2.0 | 9 | Elasticsearch(SSPL商用受限)/Metron(已弃) |
| **L4 威胁情报** | **OpenCTI** CE + 微步 API + 奇安信 API | Apache-2.0/商业 | 9/9/8 | MISP(AGPL)/CRITS(停更) |
| **L5 SOAR 编排** | **Shuffle** | AGPL-3.0(自托管免费) | 9 | n8n(缺SOC语义)/Airflow(调度非响应) |
| **L6 漏洞/攻击面** | **Nuclei + Trivy** + KubeHound + Nmap | MIT/Apache-2.0/AGPL-3.0/NPSL | 9/9/8/8 | OpenVAS(重)/Clair(被替代) |
| **L7 AI 核心** | **LangChain+LangGraph** + vLLM + Qwen2.5-32B-AWQ + Qdrant | MIT/Apache-2.0/商用模型/Apache-2.0 | 9/9/9/9 | AutoGen(偏研究)/Dify(弱实时) |

### 2.2 选型核心原则

| 原则 | 体现 |
|---|---|
| **优先成熟而非新颖** | Wazuh/Suricata/OpenSearch 都有 10 年+ 社区沉淀 |
| **优先 Apache-2.0/MIT** | 商用友好，避免 GPL/AGPL 污染 |
| **优先中文友好** | Qwen2.5 中文原生、Trivy 中文文档完善 |
| **优先 OpenAI 兼容 API** | vLLM/Xinference 兼容，模型切换无锁定 |
| **优先数据本地化** | 全部组件可纯内网部署 |

### 2.3 警示与 License 合规

| 项目 | License 风险 | 合规建议 |
|---|---|---|
| **Wazuh** | GPL-2.0 | 自托管 OK；SaaS 需开源衍生 |
| **Shuffle** | AGPL-3.0 | 自托管 OK；SaaS 需开源 SecSight |
| **Velociraptor** | AGPL-3.0 | 商业用途需购买 License |
| **KubeHound** | AGPL-3.0 | 同上 |
| **ELK/Graylog** | SSPL-1.0 | 中大型商用触发开源义务 |
| **n8n** | Sustainable Use | 商业 SaaS 受限，自托管 OK |

---

## 3. 整体架构（一张图）

```
┌─────────────────────────────────────────────────────────────────────┐
│              ① 数据采集层 (Assets / Logs / Flows)                    │
│  Wazuh Agent  Suricata  Sysmon-Modular  Filebeat/Vector              │
│         ↓             ↓                ↓             ↓                │
└─────────┼─────────────┼────────────────┼─────────────┼──────────────┘
          │  Syslog/EVE JSON            Win Events     │
          ▼             ▼                ▼              ▼
┌─────────────────────────────────────────────────────────────────────┐
│         ② 数据归一化与丰富层 (Normalize + Enrich)                    │
│  Vector.dev → OpenSearch (复用 Wazuh Indexer)                        │
│  + OpenCTI 上下文增强 (IoC / ATT&CK / Threat Actor)                  │
└────────────────────────────────┬────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────────┐
│       ③ 事件聚合与告警层 (SIEM + Correlation)                        │
│  OpenSearch Dashboards + 自研关联规则 (Sigma Rules 兼容)              │
│  输出: 结构化 Event (含 src_ip / user / asset / ttp / ioc)            │
└────────────────────────────────┬────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────────┐
│              ④ 🧠 SecSight AI 核心层 (本次自研核心)                   │
│  ┌────────────────────────────────────────────────────────────┐     │
│  │  LangGraph StateGraph (研判 + 编排 + 检索 三角色)            │     │
│  │  研判分析 (Qwen2.5) → 编排执行 (LLM+工具) → 知识检索 (RAG) │     │
│  │         ↕ Shared Case Context (Checkpoint Store)            │     │
│  └────────────────────────────────────────────────────────────┘     │
│  L2 审批 Gate  ←→  飞书/企微/钉钉 (人工审批通知)                       │
└────────────────────────────────┬────────────────────────────────────┘
                                 │ (执行 Action 列表)
                                 ▼
┌─────────────────────────────────────────────────────────────────────┐
│              ⑤ SOAR 编排层 (Playbook Execution)                      │
│  Shuffle (Workflow = 节点 + 边的 DAG, 内置 User Input 节点)         │
│  Apps: Wazuh API / Suricata / CrowdSec / Firewall / SSH               │
└────────────────────────────────┬────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────────┐
│              ⑥ 响应执行层 (Active Response)                          │
│  Wazuh Agent AR | iptables/nft | CrowdSec Bouncer | VirusTotal       │
│  通报群 | 创建工单 | 富化查询                                         │
└────────────────────────────────┬────────────────────────────────────┘
                                 ▲
                                 │
┌─────────────────────────────────────────────────────────────────────┐
│            ⑦ 主动检测层 (Vulnerability + Attack Surface)              │
│  Nuclei / Trivy / KubeHound / Nmap (定时任务调度)                    │
└─────────────────────────────────────────────────────────────────────┘
```

**箭头说明**：
- 自上而下：事件流（告警 → 研判 → 处置）
- 自下而上：响应回写与主动检测

---

## 4. 事件数据流（以挖矿木马为例）

```
[1] Wazuh Agent 检测到 xmrig 进程
    ↓
[2] Wazuh Manager 关联 + Forward to OpenSearch
    ↓
[3] OpenSearch 触发 Sigma Rule + 调用 OpenCTI 富化
    ↓
[4] Webhook → SecSight AI Core (LangGraph)
    ├─ Step 1: RAG → ATT&CK T1496 (资源劫持)
    ├─ Step 2: 研判 → severity=critical, ttps=[T1496,T1059]
    └─ Step 3: 编排 → 生成 Playbook
    ↓
[5] L2 审批 Gate (飞书推送 → 等待人工 click)
    ↓
[6] Shuffle Workflow 执行:
    ├─ Wazuh Active Response: kill xmrig + 隔离文件
    ├─ CrowdSec Bouncer: 封禁矿池域名
    ├─ iptables: 阻断出口流量
    └─ 飞书通知群 + 创建工单
    ↓
[7] 写回 OpenSearch: status=resolved, tttr=4m23s
```

**TTTR (Time-To-Triage-Respond)**：从告警触发到响应完成 = **4-5 分钟**（含人工审批 2-3 分钟）。

---

## 5. 三合一 AI 的工程实现

### 5.1 三个角色的边界

| 角色 | 输入 | 输出 | 延迟 | 工具调用 |
|---|---|---|---|---|
| **研判分析型** | N 条原始告警 + 资产上下文 | 结构化研判报告 (JSON) | 5-30 秒 | 否 |
| **编排执行型** | 高危事件 + Context | Playbook 执行计划 + Action 列表 | 1-5 秒 | **是（核心）** |
| **知识检索型** | 用户自然语言查询 | 答案 + 引用 | 2-10 秒 | 是（检索工具） |

### 5.2 共享 Context（LangGraph StateGraph）

```python
state = {
    "case_id": "uuid",
    "raw_alerts": [...],        # 原始告警
    "enriched_context": {...},  # 富化上下文
    "rag_chunks": [...],        # 知识检索写入
    "judgment": {...},          # 研判分析写入
    "playbook_plan": {...},     # 编排执行写入
    "approval_status": "pending",  # L2 gate 写入
    "execution_log": [...]
}
# Checkpoint Store: Redis (短) + Postgres (长)
```

### 5.3 L2 审批 Gate 设计

| 等级 | 动作类型 | 是否审批 |
|---|---|---|
| **L1 自动** | 标记告警/富化查询/创建工单/通知推送 | ❌ 无需审批 |
| **L1 自动** | 进程白名单补充/配置快照 | ❌ 无需审批 |
| **L2 半自动** | 封禁单 IP / 隔离单文件 / 暂停单容器 / 阻止单 URL | ✅ 默认需审批（可设阈值免审） |
| **L2 半自动** | 强制重置密码 / 锁定账号 | ✅ 必须审批 |
| **L3 全自动** | 整机隔离 / 全网段封禁 / 关闭业务端口 | ✅ 多重审批（必须 2 人） |

### 5.4 三层防幻觉机制

| 层 | 机制 |
|---|---|
| **Prompt 层** | 强制 JSON 输出格式 + Few-shot 真实示例 + “不确定就回答 unknown” |
| **检索层** | RAG 强制 grounding，所有结论必须引用 ATT&CK ID / CVE 编号 |
| **执行层** | LLM 只能生成 Plan，不直接执行；Plan 必须通过 Shuffle 沙箱 dry-run |

---

## 6. 安全场景覆盖矩阵

按“发生概率 × 危害性”排序，覆盖 7 大类、25+ 子场景：

| 场景 | 检测源 | 研判提示词 | L2 默认动作 | MTTR |
|---|---|---|---|---|
| **挖矿木马** | Wazuh + Falco + Suricata | xmrig/minerd 检测 + 矿池域名 | 杀进程 + 隔离文件 + 封矿池 | < 5min |
| **反弹 Shell** | Wazuh + Falco syscall + Suricata | bash -i /dev/tcp 模式 | 杀进程 + 封 dst IP + 隔离主机 | < 3min |
| **Webshell** | Wazuh + Coraza WAF + Arkime | 文件变动 + 流量异常 | 隔离文件 + 封 IP + 创建取证任务 | < 5min |
| **勒索病毒** | Wazuh + Sysmon-Modular | 大量文件改名 + 加密后缀 | 隔离主机 + 冻结账号 + 告警 CISO | < 2min |
| **横向移动** | Wazuh + Sysmon + Suricata | Pass-the-Hash / SMB 枚举 | 阻断 SMB + 强制改密 + 隔离源 | < 5min |
| **Web 攻击 (SQLi/XSS/SSRF)** | Coraza WAF + Suricata + Arkime | 模式匹配 + 异常 UA | 封 IP (临时) + 通知研发 | < 1min |
| **容器逃逸** | Falco + Trivy | 特权容器 + 异常 cap | 暂停 Pod + 告警 SRE | < 3min |
| **API 滥用** | Coraza + Arkime | 高频调用 + 异常参数 | 限流 + 临时封号 | < 1min |
| **内部威胁** | SIEM UEBA (Sigma) | 大量下载 + 异常时段 | 锁定账号 + 通知 HR | < 10min |
| **钓鱼邮件** | 邮件网关 syslog + OCR | 可疑附件 + 异常发件人 | 隔离邮件 + 拉黑发件域 | < 2min |
| **0day 探测** | Suricata + Nuclei + OpenCTI | 新 PoC 公开特征 | 推送临时 WAF 规则 + 阻断利用 IP | < 10min |
| **APT 持久化** | SIEM 关联 + ATT&CK mapping | Cron/服务异常 + ATT&CK T1053 | 隔离主机 + 触发 IR 流程 | < 30min |

---

## 7. 部署架构

### 7.1 中小规模（≤500 资产）推荐部署

### 7.2 硬件预算（单台高配 vs 多台分布）

| 部署形态 | 配置 | 总成本 (元) | 适用 |
|---|---|---|---|
| **单台高配** | GPU 服务器: 1× RTX 4090 (24GB) / 128GB RAM / 4TB SSD | 8-12 万 | ≤200 资产 |
| **中配分离** | AI: 1× RTX 4090 / 32GB; 控制: 64GB; 数据: 32GB+8TB | 15-20 万 | ≤500 资产 |
| **国产化** | 华为 Atlas 300I (24GB) / 海光 CPU / 麒麟 OS | 25-35 万 | 信创要求 |

### 7.3 网络与高可用

- **采集层**：所有 Agent 通过 TLS (Wazuh) / 加密 syslog 上报
- **核心层**：OpenSearch + Shuffle + AI Core 三副本（轻量集群）
- **LLM 层**：单节点即可（vLLM 吞吐足够），故障时降级到 Ollama 7B 备机
- **网络**：所有内部通信 mTLS；外部情报 API 走单向出站

---

## 8. 实施路径 (Roadmap)

### 8.1 MVP（0-3 个月）— “能跑起来”

**目标**：完成最小闭环（采集→告警→AI 研判→人工审批→执行）

| 月份 | 任务 | 验收 |
|---|---|---|
| **M1** | 部署 Wazuh + OpenSearch + Shuffle，集成 Wazuh → Shuffle 触发 | 100 台 Agent 上线，告警可视化 |
| **M2** | 部署 vLLM + Qwen2.5-32B-AWQ，搭建 SecSight AI Core (LangGraph) | 5 类场景 LLM 研判准确率 > 70% |
| **M3** | 接入微步/奇安信情报；3 类 Playbook（挖矿/Webshell/反弹 Shell）；L2 审批 | TTTR < 10 分钟 |

**人力**：2-3 人（1 安全工程师 + 1 后端 + 0.5 LLM）

### 8.2 完整版（3-6 个月）— “能用起来”

| 月份 | 任务 |
|---|---|
| **M4** | Suricata + Arkime 部署；Coraza WAF；Nuclei 接入 |
| **M5** | OpenCTI 部署 + ATT&CK 完整映射；Trivy 镜像扫描 |
| **M6** | 7 大场景 Playbook 全部上线；自研 Sigma 规则 100+ 条 |

**人力**：3-5 人（增加 1 前端 + 1 测试）

### 8.3 增强版（6-12 个月）— “用得好”

| 阶段 | 内容 |
|---|---|
| **M7-9** | 多租户 / 权限分离 / 审计合规；UEBA 异常行为基线 |
| **M10-12** | RAG 知识库自动更新（每日增量 ATT&CK/CVE）；自研 SOC 评估指标 |

**人力**：5-8 人

### 8.4 关键里程碑

```
Month 0     Month 3         Month 6          Month 12
  │           │               │                │
  ▼           ▼               ▼                ▼
调研→设计  MVP 上线        完整版发布       v1.0 GA
           (3 场景)        (7 场景)         (10+ 场景)
           TTTR < 10min    TTTR < 5min      TTTR < 3min
           100 资产        300 资产         500 资产
```

---

## 9. 风险与对策

| 风险 | 等级 | 影响 | 对策 |
|---|---|---|---|
| **LLM 幻觉** | 高 | 误判/误执行 | 三层防幻觉 + 强制 grounding + L2 审批 gate |
| **告警风暴** | 中 | 系统过载 | OpenSearch 限流 + LLM 异步队列 + 告警去重 |
| **开源 License 污染** | 中 | 商用受限 | 主力栈全 Apache-2.0/MIT；AGPL 仅自托管 |
| **数据合规** | 中 | 监管风险 | 全部私有化；API 出站需审批；本地 LLM 不出内网 |
| **AI 人才稀缺** | 高 | 进度风险 | 用 LangChain 等成熟框架降低 AI 工程门槛 |
| **国产化合规** | 低 | 信创客户受阻 | 主力栈全部有国产替代 |
| **零日漏洞** | 中 | 漏检 | Nuclei 模板每日同步 + RAG 注入 ATT&CK 最新 TTP |

---

## 10. 下一步行动（Today / This Week）

### 10.1 立即可做（今天）

- [x] ✅ 完成 7 份调研报告（218 KB）
- [x] ✅ 输出整体架构设计
- [ ] 创建项目仓库骨架（`F:\codex\SecSight`）
- [ ] 初始化 Git 仓库 + .gitignore + README.md
- [ ] 创建 `docs/research/` 子目录（已完成）

### 10.2 本周完成

- [ ] 启动 MVP 阶段：
  - [ ] 用 docker-compose 部署 Wazuh + OpenSearch + Shuffle 三件套
  - [ ] 在 1-2 台测试机安装 Wazuh Agent + Sysmon-Modular
  - [ ] 写 1 个最小 Playbook（如 SSH 暴力破解自动封禁）
  - [ ] 部署 vLLM + Qwen2.5-7B（先用 7B 验证流程，后续换 32B）
- [ ] 输出 **MVP 接口设计文档**（API + 数据结构）

### 10.3 第一个月交付物

- [ ] **SecSight v0.1 (MVP)**：
  - 100 资产以下部署包
  - 3 类 Playbook（挖矿/Webshell/反弹 Shell）
  - L2 审批飞书/企微集成
  - 基础 Dashboard
- [ ] **完整 README + 部署文档**

---

## 11. 文档索引

| 文档 | 路径 | 描述 |
|---|---|---|
| **本架构文档** | `docs/ARCHITECTURE.md` | 整体架构（你正在看的） |
| 主机 EDR 调研 | `docs/research/host_edr.md` | Wazuh/Sysmon/Falco/OSQuery 26KB |
| 网络检测调研 | `docs/research/network_ids.md` | Suricata/Arkime/Coraza/CrowdSec 32KB |
| SIEM 调研 | `docs/research/siem.md` | OpenSearch/Graylog/Loki 30KB |
| 威胁情报调研 | `docs/research/threat_intel.md` | OpenCTI/MISP/微步/奇安信 24KB |
| SOAR 调研 | `docs/research/soar.md` | Shuffle/StackStorm/n8n 31KB |
| 漏洞扫描调研 | `docs/research/vuln.md` | Nuclei/Trivy/KubeHound/Nmap 33KB |
| AI/LLM 调研 | `docs/research/ai_llm.md` | LangChain/vLLM/Qwen2.5/Qdrant 43KB |

---

## 12. 附录：术语表

| 术语 | 含义 |
|---|---|
| **EDR** | Endpoint Detection and Response，端点检测与响应 |
| **SIEM** | Security Information and Event Management，安全信息与事件管理 |
| **SOAR** | Security Orchestration, Automation and Response，安全编排自动化与响应 |
| **ATT&CK** | MITRE 攻击者战术技术公共知识库 |
| **RAG** | Retrieval-Augmented Generation，检索增强生成 |
| **L2 半自动** | 低风险动作自动执行，高风险动作需人审批 |
| **TTTR** | Time-To-Triage-Respond，从告警到处置的耗时 |
| **IoC** | Indicator of Compromise，失陷指标 |
| **PCAP** | Packet Capture，网络包捕获 |
| **UEBA** | User and Entity Behavior Analytics，用户实体行为分析 |

---

> **下一步**：确认本架构后，我会立即启动 MVP 开发。先用 docker-compose 部署 Wazuh + OpenSearch + Shuffle 三件套，1-2 台测试机验证最小闭环。
> **你只需要告诉我：是否接受本架构？或者哪些部分需要调整？**