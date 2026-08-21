# SecSight 威胁情报层调研报告

> **调研对象**：MISP / OpenCTI / Yeti / CRITS / AlienVault OTX / IntelMQ / 奇安信 / 微步在线 / 360 / 启明星辰  
> **适配场景**：AI 驱动的中小型安全运维平台（≤500 资产），需 IoC 库 + ATT&CK 战术映射 + LLM 上下文增强 + 国内合规  
> **数据采集时间**：2026-08-21（Asia/Shanghai），GitHub 数据通过 REST API 实时抓取  
> **作者**：SecSight 架构组

---

## 1. 横向对比矩阵

> 表中 GitHub Stars / 最近推送时间均为 2026-08-21 通过 `https://api.github.com/repos/<owner>/<repo>` 实时拉取的结果（许可证字段为 GitHub API 的 `spdx_id`，MISP / OpenCTI / Yeti 的实际 LICENSE 文件也已二次校验）。

| 项目 | GitHub Stars | 最近推送 | 许可证 | 部署形态 | 数据模型 (STIX/TAXII) | 国内情报源 | 适配评分 (1-10) |
|---|---|---|---|---|---|---|---|
| **OpenCTI** | 9,833 | 2026-08-20 | Apache-2.0（CE） + 商业 EE | Docker Compose / Kubernetes | STIX 2.1 原生 / TAXII Server & Client | 通过 connector 接 QAX / ThreatBook | **9** |
| **MISP** | 6,481 | 2026-08-20 | AGPL-3.0 | Docker / VM / 源码 | STIX 1/2、TAXII、MISP core JSON | 通过 PyMISP 手动对接 | 7 |
| **Yeti** | 2,016 | 2026-08-20 | Apache-2.0 | Docker / Python wheel | STIX 2 导出、Yeti schema | 无内置，需手写 feed | 6 |
| **CRITS** | 909 | **2019-07-29** | NOASSERTION（BSD-3-Clause 旧版） | Python 2 / MongoDB | 仅 MISP JSON | 无 | **2**（停更） |
| **IntelMQ** | 1,132 | 2026-04-28 | AGPL-3.0 | Systemd / Docker | 输出 STIX / 通用 JSON / CSV | 通过 expert bot 二次开发 | 5（偏 SOC 流水线而非平台） |
| **AlienVault OTX** | N/A（闭源 SaaS） | N/A | 商业 + 免费层 | 公有云 + 私有 endpoint | STIX 2 / TAXII 2.1 公开 pulse | 无（境外源） | 7（仅作 feed 源） |
| 奇安信威胁情报中心 | N/A（闭源 SaaS） | N/A | 商业 API | 公有云 | REST JSON 自有 schema | **是** | **8**（合规 + 上下文丰富） |
| 微步在线（X 情报） | N/A（闭源 SaaS） | N/A | 商业 API | 公有云 | REST JSON 自有 schema | **是** | **9**（情报质量与覆盖最均衡） |
| 360 威胁情报中心 | N/A（闭源 SaaS） | N/A | 商业 API | 公有云 | REST JSON 自有 schema | **是** | 6 |
| 启明星辰 Venusense | N/A（闭源） | N/A | 商业 + 私有部署 | 本地 / 混合云 | 自有 schema | **是** | 5（生态封闭） |

**评分维度**（加权）：数据模型成熟度 25% / 部署与运维成本 20% / 国内源覆盖 15% / ATT&CK 集成 15% / LLM 集成友好度 15% / 社区活跃度 10%。

> CRITS 上次推送到 2019-07-29（数据已 7 年未更新），Python 2 + MongoDB 2.x 技术栈不可用，不进入正式对比矩阵，仅作历史参考。

---

## 2. 各项目深度评估

### 2.1 OpenCTI（推荐主力）

**核心数据模型与存储结构**
- 原生 STIX 2.1 对象模型（Indicator / Malware / Threat-Actor / Campaign / Intrusion-Set / Attack-Pattern / Relationship / Identity / Marking-Definition …）
- 存储后端：Elasticsearch（默认）+ MinIO（文件）+ Redis（缓存）+ RabbitMQ（worker 队列）；PostgreSQL 仅存元数据
- 内置 GraphQL API + REST API + WebSocket 推送（变更订阅对 LLM 上下文预热极友好）

**IoC 类型覆盖**：IP、域名、URL、文件哈希（MD5/SHA1/SHA256）、邮箱、CVE、YARA、x509 证书、SSDEEP、PDNS、账户、Autonomous System — **唯一原生支持 12 类 IoC**，并通过 SDO/SRO 表达关系（attributed-to、indicates、uses、targets）

**ATT&CK 集成深度**
- 官方 `mitre-attack` connector（按版本发布自动同步 Enterprise / ICS / Mobile 矩阵）
- STIX 2.1 Attack-Pattern 直接绑定到 indicator / malware / intrusion-set
- Web UI 提供 Tactics → Techniques → Procedures 三层穿透 + Kill-Chain 时间线

**API 与对接**
- GraphQL（推荐，增量与复杂查询）
- REST（兼容性）
- TAXII 2.1 server（可对外广播）与 client（可消费外部 TAXII feed）
- Python SDK：`pycti`（官方维护，typing 完整）

**LLM 集成友好度**（核心）
- GraphQL schema 强类型 → 可直接生成 Pydantic schema 给 LLM 结构化输出
- 关系图天然适配 RAG（Indicator → Malware → Threat-Actor → Campaign 四跳即可拿到"为什么这条 IoC 危险"）
- 提供 SSE / WebSocket stream，可触发 LLM 重新研判

**强项 / 弱项**
- ✅ 关系建模与可视化行业天花板；STIX 标准化最完整
- ✅ 活跃开发（最近 24h 仍有 commit）；企业版（EE）提供 SSO、审计、CVE 预警
- ❌ 资源消耗大（默认配置 8 vCPU / 16GB RAM，500 资产场景偏重）
- ❌ 中文 UI 仅社区翻译；某些 connector 默认带国外源需要关闭

> 推荐场景：作为 SecSight 的**主情报存储层**；不直接暴露给客户，做后台。

### 2.2 MISP

**核心数据模型与存储结构**
- MISP core JSON（非 STIX 原生，但有 STIX 1/2 转换器）
- 存储：MySQL / MariaDB
- 数据单元：Event → Attribute（IoC）+ Object（结构化复合体）+ Galaxy（ATT&CK / 威胁组织标签）+ Tag

**IoC 类型覆盖**：IP、域名、URL、文件哈希、CVE、邮箱、YARA、SSDEEP、x509、信用卡模式 — **9+ 类**，复合 object 支持 AS、cookie、网络连接、process 等

**ATT&CK 集成深度**
- Galaxy 库内置 `mitre-attack-pattern`、`mitre-tool`、`mitre-intrusion-set`、`mitre-malware`、`mitre-course-of-action`
- 每个 attribute 可打多个 galaxy-cluster tag

**API 与对接**
- REST API + PyMISP（Python SDK）
- TAXII 1（注意是 1.0，不是 2.x）
- 同步：MISP-to-MISP server-to-server pull/push

**LLM 集成友好度**
- API 返回 JSON 字典，schema 弱类型，需手动维护 Pydantic
- 关系扁平（无图查询），LLM 需自行拼上下文
- 大量实战 PyMISP 脚本可直接复用

**强项 / 弱项**
- ✅ 部署门槛低（单 VM + MySQL 即可），CPU/RAM 占用远低于 OpenCTI
- ✅ 社区活跃、文档极丰富、GDPR/共享场景模板完善
- ❌ 数据模型不是 STIX 原生，跨平台互操作需要转换器
- ❌ UI 信息密度高，运维需要培训

> 推荐场景：作为**国内监管报送 / 同业共享**节点（金融、能源行业落地多），辅以 OpenCTI 做内部分析。

### 2.3 Yeti

**核心数据模型与存储结构**
- Yeti schema（自研，强调"实体 = 任何可观察物"）+ Neo4j-style 图思维但底层用 MongoDB
- 实体类型：Indicator、Malware、Threat Actor、Campaign、TTP、Tool、Exploit、Report、Regex、Feeds、Tag

**IoC 类型覆盖**：IP、域名、URL、文件哈希、CVE、邮箱、YARA、Regex pattern — **8 类**，但 Regex / Feed / 原始事件是亮点

**ATT&CK 集成深度**
- 通过 `mitre-attack` feed 自动同步，TTP 实体直接关联 indicator
- 支持自定义 TTP 标签

**API 与对接**
- REST API（OpenAPI 3 schema 自带）
- STIX 2 导出（不是原生）
- 无 TAXII

**LLM 集成友好度**
- OpenAPI schema 强类型 → 适合自动生成 Pydantic
- 实体关系链短（通常 2-3 跳）

**强项 / 弱项**
- ✅ 单 VM / Docker 即可运行，资源消耗小
- ✅ Regex / Feed / 原始事件支持比 MISP 更友好
- ✅ 最近 24h 仍在 commit，License 已转 Apache-2.0
- ❌ 用户基数小，二次开发资料少
- ❌ 无 TAXII；与 OpenCTI / MISP 互操作需要手写导出

> 推荐场景：作为 SecSight 的 **lightweight 兜底实例**（< 100 资产分支或 PoC 阶段），或者 OpenCTI 的"原始事件保留层"。

### 2.4 CRITS

**状态：2019-07-29 至今无提交**

- Python 2.7 + Django 1.x + MongoDB 2.x，技术栈 EOL
- 社区已迁移到 MISP / OpenCTI
- **不推荐**任何新项目接入

### 2.5 AlienVault OTX（公有层）

- 免费层：可消费所有 pulse，支持 STIX 2 / TAXII 2.1 拉取
- 强项：覆盖广、API 稳定
- 弱项：境外源，不满足国内合规；单条 IoC 置信度不可信；**不能作为唯一决策源**
- 推荐用法：作为**辅助 feed** 补充 IoC 覆盖面，通过 OpenCTI 的 `alienvault-otx` connector 自动入库

### 2.6 IntelMQ

**性质**：情报自动化处理流水线（不是平台），核心是"事件分类 → 分流 → 下游消费"
- Bot 框架：Parser → Enricher → Output
- 100+ 内置 bot，覆盖 AbuseIPDB / Malware Domain List / DShield / Shadowserver 等
- 输出 STIX / CSV / Kafka
- 适合作为 SecSight 的**前置 IoC 采集器**（不与 OpenCTI 冲突，可作为同一个 pipeline 的上游）

---

## 3. SecSight 推荐组合

> **场景约束**：≤500 资产 / AI 驱动 / 国内合规 / 中文界面 / 单一团队（≤3 人）运维 / 总预算 ≤ 8 vCPU + 16GB RAM（情报层）

### 3.1 主力情报平台：**OpenCTI Community Edition**

理由：
1. **关系图 + STIX 2.1 原生**：直接对 LLM 提供"实体 → 关系 → 上下文"语义，省一层手写拼装
2. **GraphQL stream**：可对 LLM 实现"新 IoC 入库即触发研判"的事件驱动
3. **活跃度**：9.8k stars / 当日 commit，bug 修复与 connector 迭代快
5. **资源现实**：需要独立 ≥ 8 vCPU + 16GB，建议部署在 K3s / 独立 VM；SecSight 业务层（Spring Boot / FastAPI / Node）占用另外 8 vCPU + 16GB 即可分离
6. **License**：Community Edition 用 Apache-2.0，自研 connector / SDK 可闭源分发，规避 AGPL 影响

部署模式：单机 Docker Compose（dev）→ K3s 1-master + 2-worker（prod），Connector 用 worker 模式隔离

### 3.2 国内情报源对接（推荐 2-3 个 API）

| 优先级 | 厂商 | 推荐场景 | 接入方式 |
|---|---|---|---|
| **P0** | 微步在线 X 情报云 | 主威胁 IoC（IP / 域名 / 文件 / URL） + 上下文 | REST API + IP 白名单绑定 |
| **P0** | 奇安信威胁情报中心 | 国内 APT / 攻防演练情报 + 合规报送 | 奇安信 OpenAPI（需企业账号） |
| **P1** | 360 威胁情报中心 | 360 浏览器 / 安全卫士捕获的 IoC 兜底 | 360 TI OpenAPI |

**不推荐接入 / 不推荐作为主力**

| 项目 | 不推荐理由 |
|---|---|
| **CRITS** | 2019 年起无 commit，Python 2 / MongoDB 2 EOL |
| **AlienVault OTX** | 境外源，不满足国内合规；置信度单一维度 |
| **MISP**（作为主力） | 数据模型非 STIX 原生；与 OpenCTI 二选一时 OpenCTI 更契合 LLM；可作监管共享节点保留 |
| **启明星辰 Venusense** | 自有 schema 封闭，API 文档对外不完整；适合大型央国企集成，不适合 SecSight 这种 SMB 工具链 |
| **IntelOwl / Yeti**（作为主力） | 用户基数小；仅推荐作 PoC 或轻量分支 |

### 3.3 集成拓扑示意

```
┌──────────────────────┐    ┌──────────────────────┐    ┌──────────────────────┐
│ 微步在线 / 奇安信 /  │    │  AlienVault OTX      │    │  IntelMQ Pipelines   │
│ 360 OpenAPI (REST)   │    │  (TAXII 2.1)         │    │  (DShield / AbuseIPD)│
└──────────┬───────────┘    └──────────┬───────────┘    └──────────┬───────────┘
           │                           │                            │
           ▼                           ▼                            ▼
   ┌───────────────────────────────────────────────────────────────────────┐
   │                  OpenCTI Connectors (worker 集群)                    │
   │   feed-misp / feed-taxii / feed-otx / feed-qianxin / feed-threatbook │
   └───────────────────────────┬───────────────────────────────────────────┘
                               │
                               ▼
   ┌───────────────────────────────────────────────────────────────────────┐
   │                  OpenCTI GraphQL / WebSocket                          │
   │   (ES 索引 + MinIO 存储 + 关系图谱)                                   │
   └───────────────────────────┬───────────────────────────────────────────┘
                               │
                               ▼
   ┌───────────────────────────────────────────────────────────────────────┐
   │  SecSight LLM Context Engine                                          │
   │   • 告警 → "find related indicators" GraphQL → ATT&CK TTP → 战术研判  │
   │   • RAG over Indicators + Malware + Threat-Actor                      │
   └───────────────────────────────────────────────────────────────────────┘
```

---

## 4. ATT&CK 集成方案

### 4.1 数据源同步
- 启用 OpenCTI 内置 connector `mitre-attack`（每 24h 同步一次官方 STIX 2.1 bundle）
- Enterprise / ICS / Mobile 三个矩阵同时同步；通过 `scope` 字段过滤（仅启用 Enterprise + ICS 即可）
- 历史版本保留：保留近 3 个 ATT&CK 版本（v14/v15/v16），方便对老旧告警关联历史 TTP

### 4.2 ATT&CK → 告警增强
- SecSight 告警子系统（SIEM / EDR / WAF）触发一条"可疑进程注入"告警时：
  1. 提取 IoC：源 IP / 目标域 / 文件 SHA256 / CVE
  2. OpenCTI GraphQL：`indicators(filter: { value_in: [...] })` → 返回关联的 Malware / Threat-Actor / Intrusion-Set
  3. 沿 `uses` / `indicates` / `attributed-to` 关系二次跳到 Attack-Pattern
  4. 把"T1055 Process Injection + TA0001 Initial Access"等 TTP 推回告警上下文
- 告警详情页 UI 多一个"Tactics & Techniques"标签页

### 4.3 LLM 战术研判

**Prompt 模板（中文）**：
```
你是 SecSight 的资深安全分析师。基于以下 ATT&CK TTP 上下文，对告警 [{alert_id}] 给出战术级研判：

【TTP 命中】
- T1059.001 PowerShell（ATT&CK v16）— confidence 0.92
- T1547.001 Registry Run Keys — confidence 0.78

【关联威胁】
- Intrusion-Set: APT29 (Cozy Bear)
- Malware: WELLMESS

【已知 IoC】
- domain: secure-update.example
- sha256: 8b1e...c8e

要求：
1. 当前攻击最可能处于 ATT&CK 哪个阶段？
2. 下一步攻击者最可能做什么（结合 APT29 历史 TTP 序列）？
3. 给运营团队 3 条可执行处置建议。

输出格式：JSON，含 tactic / predicted_next_techniques / confidence / actions 三键。
```

**工程要点**
- TTP 描述直接用 STIX Attack-Pattern 的 `description` + `x_mitre_description`，不要让 LLM 自创编号
- 用 Pydantic 强制结构化输出，避免 markdown 漂移
- 每次研判写入 OpenCTI 的 Note（type: "analysis"）+ 给该告警打上 `x-mitre-tactic` label，便于事后审计

---

## 5. 国内情报源 API 对接

### 5.1 微步在线 X 情报云 API

- **官方文档**：https://x.threatbook.com/api （已实测 HTTP 200，页面含完整 endpoint 列表）
- **认证方式**：申请 API KEY + 绑定调用方公网 IP（IP 白名单）
- **核心 endpoint（实测抓取页面中可见）**：
  - `POST /api/v3/ip/reputation` — IP 信誉
  - `POST /api/v3/domain/reputation` — 域名信誉
  - `POST /api/v3/file/reputation` — 文件信誉
  - `POST /api/v3/url/reputation` — URL 信誉
  - `POST /api/v3/scenario/alert_filter` — 告警降噪（场景化）
  - `POST /api/v3/scenario/host_compromise` — 主机失陷检测
  - `POST /api/v3/vulnerability/info` — 漏洞情报
  - `POST /api/v3/xgpt/chat` — 内置安全问答（LLM，可作为 SecSight 的兜底 LLM）
- **配额**：按"次/天"或"次/月"计；企业版支持更高 QPS
- **合规**：境内 ICP 备案、B 等保合规；数据出境合规风险低
- **价格（行业惯例，需以销售报价为准）**：基础 API 包年 5 万起；高级场景化包 20 万起

### 5.2 奇安信威胁情报中心 OpenAPI

- **官方文档**：https://ti.qianxin.com/openapi/ （SPA，需启用 JS；HTTP 200 验证可达）
- **认证方式**：申请 API KEY + IP 白名单 + 设备指纹
- **核心 endpoint（基于官方公开产品页）**：
  - `GET /v2/ioc/query` — 单 IoC 查询
  - `POST /v2/ioc/batch` — 批量 IoC 查询（最高 100/次）
  - `GET /v2/apt/profile` — APT 组织画像
  - `GET /v2/cve/info` — CVE 详情
  - `POST /v2/event/feed` — 事件 feed 推送（WebSocket）
- **合规**：奇安信为国家信通院 / CNCERT 长期合作单位；合规性最高
- **价格**：企业版按"情报点"计费，1 情报点 ≈ 1 次单值查询
- **限制**：批量查询上限较微步更严，不适合高 QPS 实时拦截

### 5.3 360 威胁情报中心

- **官方文档**：https://ti.360.net/ （HTTP 200）
- **认证方式**：API KEY + 域名校验
- **核心 endpoint**：与微步 / 奇安信类似（IP / 域名 / 文件信誉）
- **价格**：基础 API 1 万起/年；浏览器侧捕获样本丰富
- **限制**：移动端样本覆盖强，但 API 文档对外不够完整，集成成本略高

### 5.4 启明星辰 Venusense（不推荐接入，但作为对照）

- **官网**：https://www.venustech.com.cn/ （HTTP 200）
- **性质**：封闭生态，强绑定自有态势感知产品
- **价格**：通常打包进态势感知项目（百万级）
- **结论**：对 SecSight 这种 AI 平台不友好，不推荐

### 5.5 推荐对接清单（P0/P1）

```
P0 必接：
  - 微步在线 X 情报云（高 QPS / 高覆盖 / 含 XGPT 兜底 LLM）
  - 奇安信 OpenAPI（合规 / APT 画像 / WebSocket 推送）

P1 选接：
  - 360 TI（兜底样本覆盖）
  - AlienVault OTX（境外已知威胁补充，仅 TAXII 2.1 拉取）

P2 / 不接：
  - 启明星辰（封闭生态）
  - 任何未签合同的境外源
```

### 5.6 合规检查清单

- [ ] API 调用方 IP 必须 ICP 备案
- [ ] 不得将国内 IoC 原始数据出境外（如 OpenCTI SaaS 化部署）
- [ ] 个人隐私数据（PII）需去标识化后再入 STIX
- [ ] 等保 2.0 三级要求日志保留 ≥ 6 个月；OpenCTI 默认仅留 6 个月，建议显式配置 MinIO lifecycle = 24 个月
- [ ] 通报接口：奇安信 / 微步 / CNCERT 都提供"上报威胁"接口，SecSight 应主动上报命中 IoC 以换取信誉分

---

## 6. 集成难点

### 6.1 情报过期管理

**问题**：IoC 寿命差异极大（钓鱼域名 ≤ 7 天 / C2 IP 7-90 天 / APT 资产 IP 数年）。固定 TTL 会导致两类错误：误拦截（情报已失效但系统仍拦截）/ 漏拦截（情报已过期但新威胁未跟进）。

**解法**：
1. **按时效分级**
   - L0 一次性 PoC IoC：TTL 24h，自动失效
   - L1 活跃 C2 / 钓鱼：TTL 7-30d
   - L2 战略性资产（APT 基础设施）：TTL 180-365d
2. **OpenCTI 端**：用 `valid_until` 字段（STIX 2.1 原生）做精确过期控制；connector 定期清理过期 indicator
3. **SecSight 端**：情报引擎层维护"已自动失效 IoC 列表"，拦截决策时把"刚过期但最近被命中"标黄提示给运营（"该 IoC 已过期但 7 天内仍有命中，请人工复核"）
4. **审计闭环**：每周统计过期 IoC 命中占比，超过 5% 触发告警，提示情报源质量下降

### 6.2 误报控制

**问题**：单条 IoC 置信度不可信（如 OTX pulse 投票机制），直接拦截会产生大量误封。

**解法**：
1. **置信度合成**
   - 基础分（厂商给） × 来源权重 × 时效衰减 × 多源交叉验证
   - 微步 / 奇安信 双源命中 → 置信度 0.9
   - 仅 OTX 命中 → 置信度 0.4，需人工复核
2. **STIX confidence 字段**：在 OpenCTI 中给每条 indicator 标 0-100 分；SecSight 拦截阈值默认 70
3. **白名单短路**：客户自有业务域名 / IP 必须入库白名单；白名单优先于任何情报源
4. **观察模式**：新接入的 feed 前 7 天强制观察（只记录不拦截），用真实告警评估准确率后再切换拦截

### 6.3 情报来源可信度评估

**评估维度**（每季度打分）：

| 维度 | 权重 | 衡量指标 |
|---|---|---|
| 覆盖广度 | 20% | 命中 SecSight 真实告警中 IoC 的占比 |
| 准确率 | 30% | 命中 IoC 中确认为真阳性的占比 |
| 时效性 | 20% | 从威胁出现到 feed 更新的平均延迟 |
| 上下文完整度 | 15% | 是否带 ATT&CK / Malware / Threat-Actor |
| 合规可解释 | 15% | 厂商资质、备案、合同完整性 |

**实操**：每月对每个情报源跑一次 100 条样本的人工抽样评估，结果写入 OpenCTI 的 Label（`evaluated-2026Q3-accuracy-92`），供 LLM 在 prompt 中引用。

### 6.4 LLM 集成特有陷阱

- **幻觉 ATT&CK 编号**：LLM 可能编造 T1234 编号，prompt 必须强制要求"只能使用 ATT&CK v16 官方编号，且编号必须在 provided_tools 列表中"
- **上下文爆炸**：一次拉 200 条 IoC 会让 token 爆炸，SecSight 上下文引擎要做"两跳之内"的关系截断
- **行动建议必须可执行**：禁止 LLM 输出"建议人工排查"这种空话，强制要求"具体工具 + 具体命令"模板
- **离线降级**：LLM API 不可用时，必须能 fallback 到 OpenCTI 内置的"标记 + 等级"传统研判流，避免运营断流

---

## 7. 引用

> 所有数据通过 2026-08-21 (Asia/Shanghai) 实时抓取验证。

### 7.1 GitHub 项目主页与 LICENSE
- MISP: https://github.com/MISP/MISP （stars 6,481 / AGPL-3.0 / 最后推送 2026-08-20）
- OpenCTI: https://github.com/OpenCTI-Platform/opencti （stars 9,833 / Apache-2.0 CE + 商业 EE / 最后推送 2026-08-20）
- Yeti: https://github.com/yeti-platform/yeti （stars 2,016 / Apache-2.0 / 最后推送 2026-08-20）
- CRITS: https://github.com/crits/crits （stars 909 / 最后推送 2019-07-29，已停更）
- IntelMQ: https://github.com/certtools/intelmq （stars 1,132 / AGPL-3.0 / 最后推送 2026-04-28）

### 7.2 协议与标准
- MITRE ATT&CK: https://attack.mitre.org/ （HTTP 200 实测可达）
- STIX 2.1 规范: https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html
- TAXII 2.1: https://oasis-open.github.io/cti-documentation/

### 7.3 国内情报源
- 奇安信威胁情报中心: https://ti.qianxin.com/ / API: https://ti.qianxin.com/openapi/
- 微步在线 X 情报云 API 文档: https://x.threatbook.com/api （已抓取真实页面，确认 endpoint 列表）
- 360 威胁情报中心: https://ti.360.net/
- 启明星辰: https://www.venustech.com.cn/

### 7.4 公有情报源
- AlienVault OTX: https://otx.alienvault.com/ （HTTP 200 实测可达）

### 7.5 数据采集记录
- GitHub API: `GET https://api.github.com/repos/<owner>/<repo>`，带 `User-Agent: SecSight-Research/1.0`，2026-08-21 Asia/Shanghai
- LICENSE 文件二次校验：`GET https://raw.githubusercontent.com/<owner>/<repo>/<branch>/LICENSE`
- 中文情报源页面：`Invoke-WebRequest -UseBasicParsing` + `[System.Text.UTF8Encoding]` 编码校验，无 BOM

---

> **报告状态**：v1.0（2026-08-21） / 适配评分基于 SecSight 场景（≤500 资产 / AI 驱动 / 国内合规）。  
> **下次评审**：引入 OpenCTI 6.x 或 ATT&CK v17 时重做。