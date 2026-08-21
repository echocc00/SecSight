# SecSight 选型裁决记录 (Decision Record)

> **版本**: v1.1 (收敛版)
> **日期**: 2026-08-21
> **v1.1 变更**: ① LLM 改为云端多厂商(LiteLLM 网关 + DeepSeek/MiniMax 为主,本地 vLLM 降为敏感场景备选);② 情报源改为免费优先 + 预留付费接口(很长一段时间不接付费);③ 补充 license 隔离开发量评估(增量约5-10%,非额外功能);④ **V1(ASP)/V3(DFIR-IRIS) 已核实**:ASP 真实但无正式 LICENSE 文件→仅借鉴设计不 fork;DFIR-IRIS 主本体 LGPL-3.0 可商用,但3个模块仓库 AGPL 需避开。
> **前置**: [ARCHITECTURE.md](ARCHITECTURE.md) (A体系) + [02-design.md](02-design.md) (B体系) + [doubao-安全运营.md](doubao-安全运营.md) (C体系) + [research/](research/)×7
> **裁决原则**: 以有调研支撑的 A 体系选型为技术底座；保留 B 体系的概念框架(22剧本/5级自主性/4层知识库)作为产品骨架；弃用 C 体系未核实项。
> **产品前提**: 先自用、后续考虑商业化 → 按"产品化"标准提前做 license 隔离，AGPL/GPL 组件必须隔离层处理。

---

## 0. 裁决方法

每个冲突点按统一结构裁决：

| 项 | 内容 |
|---|---|
| **冲突现状** | 三体系各自主张 |
| **选项** | A / B / C 的具体方案 |
| **裁决** | 采纳哪个 + 修正 |
| **理由** | 一句话核心依据 |
| **影响** | 落地代价 / 返工风险 |

**裁决优先级权重**:
1. 有 research 调研支撑 > 无调研
2. license 商用友好 > 有传染风险(产品化前提)
3. 可核实项目 > 无法核实
4. 社区活跃/成熟 > 小众/新项目

---

## 1. 前提确认(已定 / 待定)

### 1.1 已定前提

| # | 前提 | 取值 | 影响 |
|---|---|---|---|
| **P1** | 产品形态 | **先自用 + 后续商业化** | AGPL/GPL 必须隔离层处理;编排基座选自研为主 |
| **P2** | 裁决基线 | **以 A 体系(ARCHITECTURE + research)为技术底座** | 选型有调研依据 |
| **P3** | 概念框架来源 | **保留 B 体系骨架** | 22剧本/5级自主性/4层知识库作为产品结构 |
| **P4** | 弃用 C 体系 | **doubao 文档降级为参考** | Vigil SOC/CyberNest 等未核实项目不进入选型 |

### 1.2 待你拍板前提(裁决前必须确认 2 项)

| # | 前提 | 选项 | 默认建议 | 为何必须先定 |
|---|---|---|---|---|
| **P5** | 合规要求 | 等保2.0二级 / **三级** / 关基 / 金融行业规范 | **等保2.0三级** | 决定剧本优先级(勒索/日志合规置顶)和日志保留策略(≥6个月) |
| **P6** | 部署环境 | 物理机 / 虚拟机 / **容器(Docker Compose)** / 国产化平台 | **容器起步 + 预留国产化CPU兼容** | 决定部署拓扑和硬件预算 |

> P5/P6 建议采用默认值推进;如需调整请直接告知,以下裁决已按默认值展开。

---

## 2. 三体系路线冲突总览

| 维度 | A (ARCHITECTURE) | B (02-design) | C (doubao) | **裁决** |
|---|---|---|---|---|
| 编排基座 | LangGraph 自研 | Fork ASP + Wazuh-Autopilot | 对标 Vigil SOC | **LangGraph 自研** (见3.1) |
| SOAR 引擎 | Shuffle | w5国产 + Shuffle | 自研+Shuffle | **Shuffle(隔离层)** (见3.2) |
| LLM 部署 | vLLM | Ollama | Foundation-Sec-8B | **LiteLLM 网关 + 云端为主 + 本地备选** (见3.3) |
| 主力模型 | Qwen2.5-32B-AWQ | Qwen2.5+DeepSeek | Foundation-Sec-8B+SecGPT | **DeepSeek-V3 + MiniMax (云端,境内合规)** (见3.3) |
| Agent 角色 | 3角色(研判/编排/检索) | 11角色 | 7角色 | **3角色起步→渐进到7** (见3.4) |
| 自主性分级 | 3级(L1/L2/L3) | 5级(L1-L5) | 置信度6级 | **5级(L1-L5)** (见3.4) |
| 威胁情报 | OpenCTI | MISP | OpenCTI+MISP | **OpenCTI 为主 + MISP 监管共享** (见3.5) |
| 案件管理 | 未提 | 未提 | DFIR-IRIS | **DFIR-IRIS** (见3.6) |
| 知识库 | 单层 | 4层(L0-L3) | RAG | **4层(L0-L3)** (见3.7) |
| 剧本体系 | 7场景 | 22剧本 | ATT&CK战术覆盖 | **22剧本框架,Phase1做6个** (见3.8) |
| 工具协议 | 未明确 | MCP | 未明确 | **MCP** (见3.9) |
| 采集归一化 | Vector+OpenSearch | 未明确 | ECS | **ECS schema + Vector** (见3.10) |

---

## 3. 逐项裁决

### 3.1 编排基座(AI 大脑)

| 项 | 内容 |
|---|---|
| **冲突现状** | A: LangGraph 自研三角色 StateGraph;B: Fork ASP(Django) + 集成 Wazuh-Autopilot 11角色范式;C: 对标 Vigil SOC |
| **选项A** | LangGraph 自研 — 有 research/ai_llm.md 评分 8.5,生态最厚,内置 interrupt 做 L2 审批 |
| **选项B** | Fork ASP — 02-design 声称 1150⭐ MIT Django,但 research/×7 **从未调研 ASP**,Wazuh-Autopilot 47⭐ 项目作为"已验证"论据强度不足 |
| **选项C** | 对标 Vigil SOC — doubao 文档引入,项目真实性**无法核实**,不采纳 |
| **裁决** | **采纳 A: LangGraph 自研编排** |
| **理由** | 有调研支撑 + license 干净(MIT) + 与 vLLM/Qdrant/OpenSearch 原生集成 + interrupt_before 原生支持 L2 审批 gate |
| **影响** | 放弃 ASP 的 Django 前端底座;需自建 Web Dashboard。但 02-design 的"案件/告警/剧本/Agent"领域模型概念仍保留借鉴(自行实现,不复制代码) |
| **待办(已核实)** | ASP 真实存在,1151⭐,活跃,技术栈/领域模型属实。但**无 LICENSE 文件**(license 状态不正式)→ **不 fork、不 import 其代码**,仅借鉴领域模型设计。详见 §6.3 |

### 3.2 SOAR 引擎(执行层)

| 项 | 内容 |
|---|---|
| **冲突现状** | A: Shuffle;B: w5国产 + Shuffle 双轨;C: 自研+Shuffle |
| **选项A** | Shuffle — research/soar.md 评分 9,SOC 原生,内置 User Input 审批节点,飞书/钉钉 App |
| **选项B** | w5 国产 SOAR — 02-design 列为兜底,但 research/soar.md **对比矩阵无 w5**,无调研依据 |
| **选项C** | 自研 — 成本高 |
| **裁决** | **采纳 A: Shuffle 作为执行层**,但必须做隔离 |
| **理由** | 唯一有调研支撑的 SOC 原生 SOAR + 原生审批节点 + 国内 IM 集成 |
| **影响(License)** | Shuffle 是 **AGPL-3.0**。产品化前提下必须隔离:SecSight 主进程不链接 Shuffle 代码,仅通过 **Webhook + REST API** 调用 Shuffle Workflow;Shuffle 作为独立进程部署。这样 SecSight 主体不触发 AGPL 传染 |
| **弃用** | w5 国产 SOAR — 无调研依据,不进入选型;如未来国产化硬性要求再补调研 |

### 3.3 LLM 部署与模型

| 项 | 内容 |
|---|---|
| **冲突现状** | A: vLLM + Qwen2.5-32B-AWQ;B: Ollama + Qwen2.5+DeepSeek;C: Foundation-Sec-8B + SecGPT |
| **选项A** | vLLM 本地 — research/ai_llm.md 评分 9.0,吞吐领先,但需 GPU 硬件(8-18万一次性) |
| **选项B** | Ollama — 评分 7.5,仅 PoC |
| **选项C** | Foundation-Sec-8B/SecGPT — research 明确不构成主力 |
| **新增选项D** | **云端多厂商 LLM + LiteLLM 统一网关** — 无 GPU 硬件成本,按 token 付费,境内厂商合规 |
| **裁决** | **采纳 D: LiteLLM 网关 + 云端为主 + 本地 vLLM 敏感场景备选** |
| **理由** | 用户明确要求多厂商云端 LLM(MiniMax/DeepSeek 等);LiteLLM(MIT)是事实标准,一个 OpenAI 兼容端点路由多厂商,模型切换零代码改动;省 GPU 硬件成本 |
| **主力模型分工** | 简单分诊: MiniMax / Qwen-Plus(快、便宜);复杂调查推理: **DeepSeek-V3 / DeepSeek-R1**(推理强、中文好、价格极低);代码/剧本生成: DeepSeek-Coder;高风险决策审计: Claude Sonnet(仅脱敏后备选) |
| **数据合规约束** | DeepSeek/MiniMax/Qwen = 境内厂商、ICP备案、数据不出境 ✅;Claude/GPT = 境外,**违反等保2.0三级**,仅作脱敏后人工复核备选,不进生产研判主链路 ❌ |
| **本地备选** | vLLM + Qwen2.5-32B-AWQ 降为**敏感场景/离线需求备选**(极敏感告警或网络隔离环境),非默认 |
| **成本对比** | 云端: 无硬件,中小 SOC 月成本约 2000-8000 元;本地: 一次性 GPU + 运维,数据不出网。**混合最优**: 日常云端,敏感/离线本地兜底 |
| **影响** | 主力栈 L7 加 LiteLLM(MIT);D4 硬件预算从"必配 GPU"改为"可选 GPU(敏感场景)";弃用 B 的 Ollama 默认和 C 的网安专用模型 |

### 3.4 Agent 角色与自主性分级

| 项 | 内容 |
|---|---|
| **冲突现状** | A: 3角色(研判/编排/检索);B: 11角色(7reactive+4proactive)+5级自主性;C: 7角色+置信度6级 |
| **选项A** | 3角色 — 最简,但 proactive 主动防御缺失 |
| **选项B** | 11角色+5级 — 最完整,有学术框架(Mohsin et al. 2025)支撑 |
| **选项C** | 7角色+置信度6级 — Vigil SOC 范式,项目真实性存疑 |
| **裁决** | **角色: Phase1 实现 A 的3角色(Triage/Investigation/Containment),Phase2-3 渐进到 B 的7角色(加DFIR/IR Lead/Compliance/SOC Manager),Phase4 补4个 Proactive;自主性: 采纳 B 的 5 级(L1-L5)框架** |
| **理由** | 3角色起步降低 MVP 风险;5级自主性有学术依据且每动作标注 autonomy_level 比"置信度阈值"更可审计 |
| **影响** | 保留 B 的 autonomy_level 字段设计;LangGraph StateGraph 按5级在 plan_actions→human_approve→execute 节点路由 |
| **弃用** | C 的置信度6级 — 与5级自主性重复,5级更结构化 |

### 3.5 威胁情报

| 项 | 内容 |
|---|---|
| **冲突现状** | A: OpenCTI;B: MISP;C: OpenCTI+MISP |
| **选项A** | OpenCTI — research/threat_intel.md 评分 9,STIX2.1原生,GraphQL 对 LLM 友好 |
| **选项B** | MISP — 评分 7,非STIX原生,LLM 需手拼上下文 |
| **裁决** | **采纳 A+修正: OpenCTI CE 为主力情报存储 + 免费 IoC 源为数据源;付费厂商(微步/奇安信/360)预留接口,很长一段时间不接入** |
| **理由** | OpenCTI 关系图天然适配 RAG;research 明确推荐 OpenCTI 为主;用户决策:免费优先,付费延后但需留接口 |
| **影响** | 与 B 的"MISP富化"冲突 → 统一改为 OpenCTI 富化;MISP 降为可选组件 |
| **License** | OpenCTI CE = Apache-2.0(商用友好);免费源均无 license 风险 |

#### 3.5.1 情报源接入策略(免费优先 + 预留付费接口)

**架构原则**: 情报层抽象为统一 `ThreatIntelProvider` 接口,免费源是当前实现,付费源是未来适配器,接入时零改动上层代码。

```python
# 抽象接口(Phase1 实现)
class ThreatIntelProvider(ABC):
    @abstractmethod
    def query_ip(self, ip: str) -> IntelResult: ...
    @abstractmethod
    def query_domain(self, domain: str) -> IntelResult: ...
    @abstractmethod
    def query_file_hash(self, hash: str) -> IntelResult: ...
    @abstractmethod
    def query_url(self, url: str) -> IntelResult: ...

# Phase1 免费源实现
class AbuseIPDBProvider(ThreatIntelProvider): ...   # 免费,IP 信誉
class OTXProvider(ThreatIntelProvider): ...          # 免费,TAXII 2.1 拉取
class MISPCommunityProvider(ThreatIntelProvider): ... # 免费,社区 feed

# 预留付费适配器(很长一段时间不实现,接口已定义)
class ThreatBookProvider(ThreatIntelProvider): ...   # 微步,付费
class QianxinProvider(ThreatIntelProvider): ...      # 奇安信,付费
class Qihu360Provider(ThreatIntelProvider): ...      # 360,付费
```

**置信度合成(免费源局限的缓解)**:
- 单免费源置信度低 → **多免费源交叉验证**:AbuseIPDB + OTX + MISP 三源命中 → 置信度 0.7;仅单源 → 0.4 标黄人工复核
- 免费源覆盖面不足 → **降低自动处置阈值**:免费源场景下,封禁类动作默认走 L2 审批(不自动封),避免误伤业务
- 后续接付费源 → 提升 confidence,可解锁 L4 自动处置

**Phase 路线**:

| 阶段 | 情报方案 | 成本 | 自动处置权限 |
|---|---|---|---|
| **Phase1-3(当前)** | OpenCTI + 免费源(AbuseIPDB/OTX/MISP社区) | 0 | 仅富化+标黄,封禁走 L2 审批 |
| **未来(按需)** | 接入1个付费基础包(微步或360) | ~1-5万/年 | 提升 confidence,部分 L4 自动 |
| **更远(合规硬需求)** | 微步+奇安信双源 | ~20万+/年 | 高置信度自动封禁 + 合规报送 |

**预留接口的工程要求**:
- `ThreatIntelProvider` 抽象 + 配置化注册(yaml 声明启用哪些 provider)
- 置信度合成器独立模块,新增 provider 不改上层
- 付费 provider 的 key/配额管理走统一 Credential Store(与 Shuffle Credentials 复用)

### 3.6 案件管理

| 项 | 内容 |
|---|---|
| **冲突现状** | A/B 均未提;C: DFIR-IRIS |
| **裁决** | **采纳 C: DFIR-IRIS** 作案件/证据/时间线管理 |
| **理由** | TheHive 已 Archived(research/soar.md 确认),DFIR-IRIS 是全开源替代;案件管理是 SOC 必备但 A/B 遗漏 |
| **影响** | 新增一个组件;**license 已核实为 LGPL-3.0**(v1.1),弱 copyleft,独立进程 + API 调用可商用,不传染 SecSight 主体 |
| **License 约束** | 主本体 iris-web=LGPL-3.0 ✅ 可用;**禁止引入** iris-skeleton-module/iris-mwdb-module/iris-intelowl-module(AGPL-3.0,见 §6.3) |

### 3.7 知识库架构

| 项 | 内容 |
|---|---|
| **冲突现状** | A: 单层 RAG;B: 4层(L0框架/L1战术/L2剧本/L3案例);C: RAG |
| **裁决** | **采纳 B: 4层分层架构** |
| **理由** | 4层比单层 RAG 更结构化,L0复用 MITRE/等保(不造轮子),L3运行时沉淀形成飞轮;这是 B 体系最有价值的贡献 |
| **影响** | 保留 B 的 L0-L3 目录结构;向量库用 Qdrant(A体系推荐)或 pgvector(若已有 Postgres) |
| **弃用** | B 提到的 "Anthropic Cybersecurity Skills 30206⭐/817技能" — **数字与项目真实性待核实**,不作为知识库支柱;若核实存在且活跃,仅作 L1 战术层补充导入 |

### 3.8 剧本体系

| 项 | 内容 |
|---|---|
| **冲突现状** | A: 7场景;B: 22剧本按业务系统分组;C: ATT&CK战术覆盖 |
| **裁决** | **采纳 B: 22剧本框架,Phase1 优先做6个P0剧本(勒索/挖矿/持久化/暴力破解/日志合规/服务崩溃)** |
| **理由** | 22剧本按业务系统分组对应 CMDB 和团队分工,可落地;勒索置顶的业务影响论证(02-design §9.8)成立 |
| **影响** | 保留 B 的 playbooks/ 目录结构和 YAML 模板(含 autonomy_level 字段);Phase 路线按 B 的4阶段 |
| **修正** | A 的7场景作为22剧本的检测源映射参考,不另立体系 |

### 3.9 工具协议

| 项 | 内容 |
|---|---|
| **冲突现状** | A: 未明确;B: MCP;C: 未明确 |
| **裁决** | **采纳 B: MCP 协议** |
| **理由** | 2026事实标准,已有大量现成安全 MCP server;LangGraph Tool 可封装为 MCP;避免为每个工具定制集成 |
| **影响** | 保留 B 的 mcp_servers/ 目录;Wazuh/Suricata/osquery/VT/MISP/firewall 各封装 MCP server |

### 3.10 数据采集归一化

| 项 | 内容 |
|---|---|
| **冲突现状** | A: Vector→OpenSearch;B: 未明确;C: ECS schema |
| **裁决** | **采纳 A+C: Vector 作采集管道 + ECS(Elastic Common Schema) 作统一字段标准 → OpenSearch** |
| **理由** | research/siem.md 推荐 OpenSearch(评分8) + Vector(轻量采集);ECS 是生态公共 schema,OpenSearch Dashboards 原生读 |
| **影响** | 所有上游(Wazuh/Suricata/Sysmon/国产设备 syslog)经 Vector 转 ECS 入 OpenSearch;中文分词用 IK analyzer |

---

## 4. 收敛后的最终技术栈

### 4.1 主力栈(裁决后)

| 层 | 选型 | License | 商用隔离要求 |
|---|---|---|---|
| **L1 主机EDR** | Wazuh + Sysmon-Modular + Falco | GPL-2.0 / MIT / Apache-2.0 | Wazuh 经 API 转换层隔离,不直接 forward |
| **L2 网络检测** | Suricata + Arkime + Coraza + CrowdSec | GPL-2.0 / Apache-2.0 / Apache-2.0 / MIT | 无特殊要求 |
| **L3 SIEM/日志** | OpenSearch + Vector | Apache-2.0 / MPL-2.0 | 无特殊要求 |
| **L4 威胁情报** | OpenCTI CE + 免费源(AbuseIPDB/OTX/MISP社区);付费厂商预留接口 | Apache-2.0 / 免费 | 无特殊要求;付费 provider 走 Credential Store |
| **L5 SOAR执行** | **Shuffle(隔离部署)** | **AGPL-3.0** | **独立进程,仅 Webhook/REST 调用,不链接代码** |
| **L6 漏洞/攻击面** | Nuclei + Trivy + KubeHound + kube-bench + Nmap | MIT / Apache-2.0 / AGPL-3.0 / Apache-2.0 / NPSL | KubeHound(AGPL)同 Shuffle 隔离 |
| **L7 AI核心** | LangGraph + **LiteLLM 网关** + 云端LLM(DeepSeek/MiniMax) + 本地vLLM(备选) + Qdrant | MIT / MIT / 商业API / Apache-2.0 / Apache-2.0 | 云端API仅境内厂商;境外API仅脱敏后备选 |
| **L8 案件管理** | DFIR-IRIS | 待核实 | 部署前必须核实 license |
| **L9 工具协议** | MCP | — | — |
| **L10 采集归一化** | Vector + ECS schema | MPL-2.0 | — |
| **前端** | 自建(Vite+Antd 或 React+shadcn) | MIT | 不依赖 ASP |

> **License 隔离开发量评估**: 进程隔离 + API 调用是 SOC 平台标准做法,非额外功能。增量约 5-10%,仅体现在每个 AGPL/GPL 组件写一个客户端封装类(10-30行/个,共约100-200行)。MCP server 封装本就必需(无论隔不隔离)。收益是 SecSight 主体可闭源商业化,避免被 AGPL 强制开源或购买商业 license(数万美元/年)。

### 4.2 License 隔离架构(产品化前提)

```
┌─────────────────────────────────────────────┐
│  SecSight 主体 (Apache-2.0 可闭源)           │
│  LangGraph 编排 + LLM网关 + Web Dashboard    │
│  ← 通过 Webhook/REST 调用,不链接以下代码 →   │
└──────────┬──────────────┬───────────────────┘
           │              │
   ┌───────▼──────┐  ┌────▼─────────┐  ┌──────────────┐
   │ Shuffle      │  │ Wazuh Manager│  │ KubeHound    │
   │ (AGPL,独立)  │  │ (GPL,独立)   │  │ (AGPL,独立)  │
   └──────────────┘  └──────────────┘  └──────────────┘
   ↑ 进程隔离 + API 调用,不触发 copyleft 传染
```

**规则**:
- SecSight 主体进程**不 import** 任何 AGPL/GPL 项目的代码
- 所有 AGPL/GPL 组件作为**独立进程**部署,仅通过 HTTP/Webhook/MCP 交互
- Velociraptor(AGPL)按需触发,不常驻、不对外暴露端口

---

## 5. 保留自 B 体系的概念框架

以下 B 体系设计**保留**(填 A 的技术肌肉):

| 概念 | 保留内容 | 技术实现(填A) |
|---|---|---|
| **22剧本** | 按业务系统分组 + P0/P1/P2 优先级 + Phase1做6个 | YAML 剧本 + autonomy_level 字段 + Shuffle 执行 |
| **5级自主性** | L1-L5 + 每动作标注 + L2强制双签 | LangGraph interrupt_before 节点 + 飞书/钉钉审批 |
| **4层知识库** | L0框架/L1战术/L2剧本/L3案例 | L0=MITRE STIX导入;L1=7类业务系统知识;L2=22剧本YAML;L3=案件运行时沉淀(Qdrant向量化) |
| **MCP工具协议** | mcp_servers/ 目录 | Wazuh/Suricata/osquery/VT/防火墙 各封装 MCP |
| **数据流5层** | L1采集→L2关联→L3剧本→L4智能→L5交互 | 对应 A 的技术栈映射 |
| **Evidence Pack** | 每案件完整留痕 | LangGraph checkpoint(Postgres) + 审计日志 |
| **知识反向注入** | L3案例→L1战术优化检测规则 | Detection Engineering Agent(Phase4) |

---

## 6. 弃用 / 待核实清单

### 6.1 明确弃用

| 项 | 来源 | 弃用理由 |
|---|---|---|
| **w5 国产 SOAR** | B | research/soar.md 无调研;国产化硬性要求时再补 |
| **Ollama 作生产默认** | B | research 明确仅 PoC 备选 |
| **SecGPT / Foundation-Sec-8B 作主力** | C | research 评分低,不构成主力 |
| **MISP 作主力情报** | B | research 推荐 OpenCTI 为主;MISP 降为可选共享节点 |
| **Vigil SOC / CyberNest / SynapCores / SecOS** | C | 项目真实性无法核实,不进入选型 |
| **置信度6级自主性** | C | 与5级重复,5级更结构化 |
| **Fork ASP 作核心编排** | B | 无调研支撑;47⭐ Autopilot 论据强度不足 |
| **TheHive** | C | 已 Archived(research/soar.md 确认) |

### 6.2 待核实(裁决前必须验证)

| # | 项 | 核实内容 | 核实结论(v1.1) | 阻塞状态 |
|---|---|---|---|---|
| **V1** | ASP (FunnyWolf/agentic-soc-platform) | 真实 stars / 活跃度 / license | **真实存在,1151⭐,活跃(2026-08-05 push),Django+Vite/Antd+案件/告警/剧本模型均属实。但无 LICENSE 文件,GitHub 元数据 license=null,仅 README 文字提及 MIT → license 状态不正式** | ✅ 已核实 |
| **V2** | Anthropic Cybersecurity Skills | 817技能/30206⭐ 数字真实性 | 待核实(Phase2 前) | ⏸ 延后 |
| **V3** | DFIR-IRIS | license + 活跃度 | **真实存在,主仓 dfir-iris/iris-web,1541⭐,活跃(2026-07 push,2026-08 release),Airbus 发起。license=LGPL-3.0(弱 copyleft,可商用,API/独立进程集成不传染)。⚠️ 注意:组织下3个模块仓库(iris-skeleton-module/iris-mwdb-module/iris-intelowl-module)是 AGPL-3.0,引入会传染,必须避开** | ✅ 已核实 |
| **V4** | Wazuh-Autopilot (gensecaihq) | 真实存在性 | 待核实(非阻塞,仅范式参考) | ⏸ 非阻塞 |
| **V5** | 微步/奇安信/360 API | 接口规格预读(为预留适配器),报价暂不确认 | 待核实(付费延后,仅读接口规格) | ⏸ 非阻塞 |

> V1/V3 已核实通过。V2/V4/V5 非阻塞。V1 的 license 不正式风险和 V3 的 AGPL 模块规避已纳入 §6.3 处置。

### 6.3 V1/V3 核实后的处置决定

**V1 (ASP) 处置**:
- license 状态不正式(无 LICENSE 文件)→ **不 fork、不 import 其代码**(避免引入未明确 license 的代码)
- 但其**领域模型(案件/告警/剧本/Artifact)和目录结构**作为参考设计借鉴,自行实现(不复制代码)
- 前端技术栈(Vite+React+Antd)与 D3 裁决一致,可参考其 UI 布局思路,代码自写
- 若后续 FunnyWolf 补齐正式 LICENSE 文件且确认 MIT,可重新评估是否直接借鉴代码

**V3 (DFIR-IRIS) 处置**:
- 主本体 iris-web = LGPL-3.0,**采纳作案件管理**,独立进程部署 + API 调用,不传染 SecSight 主体
- **禁止引入** iris-skeleton-module / iris-mwdb-module / iris-intelowl-module(均为 AGPL-3.0)
- 自研 IOC 富化模块时,不走 IRIS module 接口(避免触发 AGPL 模块传染),改为 SecSight 侧独立实现后通过 API 写入 IRIS

---

## 7. 待你拍板清单

### 7.1 必须确认(影响代码架构)

| # | 项 | 裁决建议 | 你的决策 |
|---|---|---|---|
| **D1** | 合规要求(P5) | 等保2.0三级 | ☐ 同意 ☐ 改为___ |
| **D2** | 部署环境(P6) | Docker Compose + 预留国产化 | ☐ 同意 ☐ 改为___ |
| **D3** | 前端技术栈 | Vite+Antd(沿用 ASP 风格自建) | ☐ 同意 ☐ React+shadcn ☐ 其他 |
| **D4** | LLM 方案 | **云端多厂商(LiteLLM网关 + DeepSeek/MiniMax)**,本地vLLM作敏感场景备选 | ☐ 同意 ☐ 纯本地 ☐ 混合 |
| **D5** | Phase1 范围 | 6个P0剧本(勒索/挖矿/持久化/暴破/日志合规/服务崩溃) | ☐ 同意 ☐ 精简为3个 ☐ 其他 |
| **D6** | 情报源接入 | **免费源优先(AbuseIPDB/OTX/MISP社区)+ 付费接口预留(很长一段时间不接入)** | ☐ 同意 ☐ 其他 |

### 7.2 可后调(不阻塞启动)

| # | 项 | 默认建议 |
|---|---|---|
| D7 | 运维规模 | Phase1 100主机验证,Phase4 评估伸缩 |
| D8 | 国产设备集成 | Phase2 优先奇安信态势感知日志接入 |
| D9 | 高危动作白名单 | Phase1 启动前提供"高危业务主机清单" |
| D10 | LLM 输出审计 | Phase1 全量审计(合规优先) |
| D11 | 案件保留时长 | 90天热 + 归档 |
| D12 | 告警降噪 | Phase1 阈值+同源合并,Phase2 加 LLM 智能合并 |

---

## 8. 收敛后的 Phase1 路线(裁决版)

> 基于 D5 默认(6个P0剧本)

| 周次 | 任务 | 验收 |
|---|---|---|
| **W1-2** | 核实 V1/V3(ASP/DFIR-IRIS);Docker Compose 部署 Wazuh+OpenSearch+Shuffle(隔离);部署 LiteLLM 网关 + 接入 DeepSeek/MiniMax 云端 API | 三件套上线,告警可视化,LLM 可调通 |
| **W3-4** | LangGraph 编排骨架(3角色 StateGraph);MCP server 封装 Wazuh API;Tier1 分诊 Agent | 告警→Case→分诊流程跑通 |
| **W5-7** | 6个剧本 YAML(含 autonomy_level);L0框架层(MITRE ATT&CK STIX导入);L1战术层(7类业务系统) | 剧本可匹配+知识库可检索 |
| **W8-9** | Tier2 调查 Agent;情报层(OpenCTI + 免费 AbuseIPDB/OTX provider + 付费 provider 接口预留);LiteLLM 路由分诊用 MiniMax/推理用 DeepSeek | LLM 推理给出有意义处置建议;情报富化可用 |
| **W10-11** | Shuffle L2双签审批(飞书/钉钉);Containment Agent(隔离/封禁/kill,免费源场景封禁默认走审批);Evidence Pack + Dashboard | 审批闭环+处置执行 |
| **W12** | 6场景测试验证(可控勒索样本/xmrig mock/SSH撞库/日志失败/kill服务/可疑进程);README+demo | 6场景跑通,TTTR<10min |

**人力**: 2-3人(1安全工程师 + 1后端 + 0.5 LLM)

---

## 9. 下一步

1. **你确认 §7.1 的 D1-D6** (必填) 和 §1.2 的 P5/P6
2. **我核实 V1/V3** (ASP / DFIR-IRIS 的真实性与 license)
3. 确认后输出 **Phase1 详细实施计划** + 初始化项目仓库骨架

> 若 D1-D6 有调整,裁决对应章节会同步修订。本裁决记录是选型基线,后续变更走版本号(v1.1/v1.2)。
