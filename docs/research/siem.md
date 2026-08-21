# SecSight 平台 — 日志聚合 / SIEM 层调研报告

> 调研日期: 2026-08-21    ·    调研范围: 日志聚合、关联分析、 AI 集成
> 目标场景: 中小型 SOC (≤500 资产)  +  AI 驱动研判  +  中文支持  +  资源适中
> 数据截止: 2026-08-20 (GitHub API 实时拉取); 原始元数据保存于 `github_meta.json`

## 0. 执行摘要 (TL;DR)

- **推荐主力**: **OpenSearch** (原生 Apache-2.0 、 PPL/SQL 查询、 ML-Commons 、 OpenSearch Dashboards 中文本化完成)。与东边 Wazuh Agent 集成是同源 (Wazuh 4.x 起 Indexer 就是 OpenSearch fork, 共享索引/语义 API)。
- **替代 / 补充**:
  - 需要 **极低资源 + 指标与日志一体化** » **Loki + Grafana** (单节点 <8GB RAM 即可跳, AGPL-3.0)
  - 需要 **轻量 SIEM + 原生关联引擎** » **Graylog** (Pipeline + CECE 硬件呈现, 但 SSPL v1 商用需谨慎)
  - 需要 **MITRE ATT&CK 原生覆盖 + SOC 预置全套** » **Wazuh SIEM** 叠加上层数据库 (能力补充, 不是取代)
- **不推荐 / 警示**:
  - **Apache Metron** — Apache Incubator 2025-08-13 起 archived, 未发布 5.x release。
  - **Apache Spot** — 同 Metron 同期被弃, 以 incubator 状态几年未出套装。
  - **ELK 主链 (Elasticsearch + Logstash + Kibana)** — 三重许可 (AGPL-3.0 / SSPL / Elastic-2.0 三选一), JVM 资源重, 中小企业能用但需法务备案。
  - **Netdata / Prometheus** 系 — 指标强, 日志与关联弱, 不适 SIEM 主力。

---

## 1. 横向对比矩阵

| 项目 | Stars | 最后提交 | 许可证 | 部署形态 | 单节点承担 (GB/天) | 中文文档 | 关联分析 | AI 集成 | 适配评分 |
|---|---|---|---|---|---|---|---|---|---|
| Elasticsearch ([elasticsearch](https://github.com/elastic/elasticsearch)) | 77,846 | 2026-08-20 | AGPL-3.0 / SSPL / Elastic-2.0 | 分布式 JVM (3 节点起) | 50-300 GB/天 | 中等 | 强 (ES|QL + ML) | 强 (语义搜索 + ELSER) | **6** |
| OpenSearch ([OpenSearch](https://github.com/opensearch-project/OpenSearch)) | 13,550 | 2026-08-20 | Apache-2.0 | 单节点或分布式 JVM | 40-260 GB/天 | 中上 | 强 (PPL + SQL + ML-Commons) | 强 (semantic search + neural) | **8** |
| Graylog ([graylog2-server](https://github.com/Graylog2/graylog2-server)) | 8,114 | 2026-08-20 | SSPL-1.0 | 单节点/集群 + MongoDB 依赖 | 20-100 GB/天 | 中等 | 强 (Pipeline + CECE) | 中 (社区 plugin, 无原生 LLM) | **6** |
| Loki ([loki](https://github.com/grafana/loki)) | 28,765 | 2026-08-20 | AGPL-3.0 | 单节点 / microservice | 30-200 GB/天 | 中上 | 强 (LogQL + 外挂 plugin) | 中 (需外挂 vector store) | **7** |
| Wazuh SIEM ([wazuh](https://github.com/wazuh/wazuh)) | 16,615 | 2026-08-20 | GPL-2.0 (加严) | 多端 (Manager + Indexer + Dashboard) | 10-80 GB/天 | 中等 | 强 (原生 rule engine + MITRE) | 中 | **7** |
| Quickwit ([quickwit](https://github.com/quickwit-oss/quickwit)) | 11,529 | 2026-08-20 | Apache-2.0 | 分布式 Rust, 低资源 | 40-200 GB/天 | 较弱 | 中 | 中 (必须自建 RAG/embedding) | **6** |
| Apache Metron ([metron](https://github.com/apache/metron)) | 870 | 2025-08-13 | Apache-2.0 (archived) | 废弃 (archived 2025-08-13) | N/A | 无人维护 | 历史交付 | 无 | **1** |
| Vector ([vector](https://github.com/vectordotdev/vector)) | 22,419 | 2026-08-20 | MPL-2.0 | 轻量采集 agent | 不适合直接作 SIEM | 中等 | N/A | N/A | **4** |

**适配评分** 仅针对 SecSight 中小型 SOC (≤500 资产) 场景。评分考量 (资源 0–3) + (中文本化 0–3) + (AI 友好 0–2) + (关联能力 0–1) + (许可证可商用 0–1)。

---

## 2. 各项目深度评估

### 2.1 Elasticsearch (ELK)

**Repo**: [elasticsearch](https://github.com/elastic/elasticsearch) / [logstash](https://github.com/elastic/logstash) / [kibana](https://github.com/elastic/kibana)    ·    **Stars**: 77,846    ·    **Last push**: 2026-08-20

**架构 (采集 → 入站 → 索引 → 可视化)**: Beats / Logstash / 外部 agents → Kafka / Beats direct → Elasticsearch (Lucene 反向索引) → Kibana 仪表盘。设计为近实时 (近 NRT, ~1s refresh interval), 支持 ILM 策略自动轮换。

**部署门槛**: Elasticsearch 是 Java/Python 混写、构以 JVM。三节点生产集群默认需 16 vCPU / 64 GB RAM / 数据额 ×10 磁盘。单节点 MVP 可压缩到 4 vCPU / 16 GB, 但多节点集群为推荐架构。JVM 调优依赖 HEAP 与 indices.memory.index_buffer_size。

**学习曲线 & 运维成本**: 中高。Index template, mapping, ILM, shard 设计, transform, ES|QL (新查询语言) 都需掌握。Kibana 可视化功能丰富但配置复杂。

**与 SecSight 集成方式**:
- **查询 API**: REST `_search` (原甓) + ES|QL (`_query?format=txt`, 2024 GA) + EQL (事件查询语言)
- **SDK**: Python `elasticsearch` 8.x, Go `go-elasticsearch`, Java official, Rust `elasticsearch-rs`
- **Webhook / Alerting**: Kibana Alerting + Connectors (支持 Slack / PagerDuty / Webhook) 供 SecSight AI 拉取
- **向量检索**: ELSER (Elastic Learned Sparse EncodeR) + dense_vector + `semantic_text` 字段 (适 SecSight 告警语义去重)

**License 风险** (重点说明):
- 2021-02-02 (Elasticsearch 7.11) 从 Apache-2.0 转为 **双重: SSPL-1.0 + Elastic-2.0** (众多云厂商以为针对管理仕服务场景)
- 2024-09-13 加入第三选项 **AGPL-3.0-only** (赋予 Elasticsearch OSI-认可开源身份, 但 copyleft 强制拓展)
- **现行三重许可** AGPL-3.0 / SSPL-1.0 / Elastic-2.0 (repository 默认); 选项在 LICENSE.txt 顶部明确
- **企业含义**: 在云上重谌为 ES 提供 managed service 被 SSPL 明示限制; AGPL 选项可避开 SSPL 但仍需在联网场景下开源你的企业代码; Elastic-2.0 环境下最为友好但商用产品需 Elastic 合规评估

**强项**:
- 生态最全 (文档 / SDK / 社区 / 云商产品)
- ES|QL 使表达式查询可读性大幅提升 (适 LLM 生成 SQL)
- 原生语义搜索 (向量 + sparse) 为告警去重赋能

**弱项**:
- JVM 资源重, 中小型单节点资源项压力外明显
- License 复杂, 资讯 / 运维 / 销售都需解读
- 业务定价取决于资源和许可, ROI 不如 OpenSearch 明显

**适用场景**: 资源充足, 需要发展生态 + 未来升级云服务 (注意 SSPL 限制)。
---

### 2.2 OpenSearch  (主力推荐)

**Repo**: [OpenSearch](https://github.com/opensearch-project/OpenSearch) / [OpenSearch-Dashboards](https://github.com/opensearch-project/OpenSearch-Dashboards)    ·    **Stars**: 13,550    ·    **Last push**: 2026-08-20

**架构**: Beats / Logstash / Fluent Bit / Data Prepper → OpenSearch (以 Lucene 为底, 但分析另开勢除 ES|QL 外增加 PPL 与 SQL) → OpenSearch Dashboards (前身 Kibana) 。ML-Commons 插件提供 KMeans / RCF / 警报 / 语义检索。

**部署门槛**: JVM 以外类似 ES。单节点设计可压缩到 4 vCPU / 16 GB / 200 GB 数据 (资源只是 ES 的一半。近两年 OpenSearch 2.x 中 JVM heap 调优后引擎进一步消耗下降)。三节点集群 8 vCPU / 32 GB 起。

**学习曲线 & 运维成本**: 中。与 ES 生态共享 REST API、mapping、ILM、shard 设计；PPL 类 Pipeline 语法对社会工程师友好。中文社区资源较丰富 (中文 OpenSearch Dashboards 汉化序列由 AWS China 、讯醫、 Awesome-OSS 社区维护)。

**与 SecSight 集成方式**:
- **查询语言**: PPL (管道查询, 面向 SOC) + SQL (全事件查询, 适 LLM) + DQL (可视化平台专用)
- **SDK**: Python `opensearch-py` (9.x), Go `opensearch-go`, Java official, Rust `opensearch-rs`
- **Webhook / Alerting**: OpenSearch Dashboards Alerting + Destinations (支持 Webhook / Slack / Chime / Custom); SecSight AI 可订阅 monitor 触发
- **向量检索**: `knn_vector` 字段 + ML-Commons neural_search plugin, 适合告警语义去重 / RAG

**License**: Apache-2.0 (原生全开源、商用友好, 无 SSPL 限制。这也是 AWS 拥护理经学院拍档 Linux Foundation 子项目的原因)

**强项**:
- **License 友好** (完全 Apache-2.0, 中小企业 + 商用 SaaS 都可用)
- 查询语言多样性 (优于纯 ES|QL 的 PPL + SQL 双查询, 适 LLM 生成)
- ML-Commons 插件 — 异常检测 / 语义检索 可用 OSS
- 与 Wazuh 同源 (“Wazuh Indexer” 实质是 OpenSearch fork, 可复用 schema 与 connector)

**弱项**:
- 生态依然小于 ELK (社区插件数量、文档时实期不及 ES)
- Alerting 能力不及 ELK 成熟 (部分场景需要补入 Plugin 或 Webhook 调 SecSight 自建 Alerting Service)

**适用场景**: 中小型 SOC 、AI 驱动 、需要 Apache-2.0 License 、中文文档要求 — 是 SecSight 的最佳主力选择。
---

### 2.3 Graylog

**Repo**: [graylog2-server](https://github.com/Graylog2/graylog2-server)    ·    **Stars**: 8,114    ·    **Last push**: 2026-08-20

**架构**: Beats / Syslog / GELF / Kafka → Graylog Server (Java) → MongoDB (元数据) + Elasticsearch (索引) → Graylog Web UI。包含原生的 Pipeline 语言 (拆解/增富) 、流规则引擎 (CECE) 、Dashboard。

**部署门槛**: 三件套: Graylog Server + MongoDB + Elasticsearch/OpenSearch。默认 4 vCPU / 8 GB 即可跳, 生产推荐 8 vCPU / 16 GB。适合中小型, 同众可容错调。

**学习曲线 & 运维成本**: 中低。Web UI 全面开箱即用 (输入、解析、告警、Dashboard 都可在 UI 完成)。Pipeline 以 Drools-like 语法描述, 友好面向 ops。

**与 SecSight 集成方式**:
- **查询语言**: 原生提供 REST Search API (适 LLM) + Dashboard Aggregations
- **SDK**: 原生 Java/Python 可调 REST, Sidecar/Clients (`graypy` 业务库)
- **Webhook / Alerting**: Event Definitions + 原生 HTTP Alarm Callback (可送到 SecSight 任何入口)
- **向量 / LLM**: 未原生提供向量检索, 需外挂 OpenSearch / Milvus 作 vector store

**License**: **SSPL-1.0** (2020-11-16 起 Graylog 4.0 转许可, 原为 GPL-3 + 商业补充条款)。限制云服务场景反心是 MongoDB SSPL 同颗子弹。企业自部署可用。

**强项**:
- Pipeline + CECE 原生关联引擎, 面向安全 ops 场景 “开箱即用”
- Lookup Table / GeoIP / 语义警报 与 SIEM 重合度高
- 文档 / 社区成熟

**弱项**:
- SSPL-1.0 许可, 云上 SaaS 商用均需备案。另推荐商业版 / 云服务豁豁 路径原原本是同样 SSPL 依赖
- AI / 向量 / LLM 原生能力为空, 需外挂

**适用场景**: 需要开箱即用的 SIEM 业务, 但能接受 SSPL。
---

### 2.4 Loki + Grafana (轻量级 补充)

**Repo**: [loki](https://github.com/grafana/loki) / [grafana](https://github.com/grafana/grafana)    ·    **Stars**: 28,765    ·    **Last push**: 2026-08-20

**架构**: Promtail / Alloy / Vector → Loki (例似 Prometheus: 不建全文索引, 只存原始日志 + label) → Grafana / Explore (查询 / 仪表盘)。压缩存储 (gzip/zstd/chunks) + 分布式 object store (S3 / OSS / MinIO)。

**部署门槛**: **低**。单节点 Loki + Grafana + MinIO 三件套仅需 2 vCPU / 4 GB, 生产 8 vCPU / 16 GB。适合资源受限场景。

**学习曲线 & 运维成本**: 中低。LogQL (购赢 Prometheus 风格) 适合已有 Prom 生态的团队。但是 LogQL 仅对 label 索引, 全文检索需走 grep 过滤 (索引全文可开启 bloomstore / tsdb。TLB 能力不及 ES)。

**与 SecSight 雇成方式**:
- **查询**: LogQL (可 LLM 生成但全文表达式以起始差)
- **SDK**: Grafana HTTP API (全 Grafana 实例), Loki 原生 push API + ruler
- **Webhook / Alerting**: Grafana Alerting (原生 Alertmanager 风格 + Webhook)
- **向量**: 未原生。需外挂 vector store (参考 OpenSearch kNN 或 Milvus)

**License**: AGPL-3.0 (原生全开源)。

**强项**:
- 资源最低, 启动门槛低
- 与 Grafana 调物联生态 (推荐作为 ““面向 ops ““ 指标 + 日志 一体化观测台””而不是 SIEM 本体)

**弱项**:
- 全文检索能力低, 不适安內 SOC 模系 (观测 ≡ 检索高炮)
- 原生关联引擎缺位, 需外挂
- AI 集成面需额外也成本 (实现顶项设计要忍受 vector store + correlation。这是它““轻量””代价)

**适用场景**: 低资源部署、 以指标 + 结构化日志为主、 不是安全事件为中心。
---

### 2.5 Wazuh SIEM (能力补充而不是取代)

**Repo**: [wazuh](https://github.com/wazuh/wazuh)    ·    **Stars**: 16,615    ·    **Last push**: 2026-08-20

**架构**: Agent → Manager (解析、规则引擎、MITRE 映射) → Wazuh Indexer (主流 ≈ OpenSearch fork) → Wazuh Dashboard (部署以为 OpenSearch Dashboards fork)。预置过百万条规则, FIM / 进程监控 / 脆弱性扫描 内置。

**部署门槛**: 多端。单节点 “All-in-one” 可压缩到 8 vCPU / 16 GB 。产品集群: Manager 4 vCPU / 8 GB + Indexer 8 vCPU / 16 GB + Dashboard 4 vCPU / 8 GB。加上 Agent 以 500 台计, 上报子代代起 5000-10000 EPS。

**学习曲线 & 运维成本**: 中高。规则定制需掌握 CDB List / XML 语法; 但 入门 较 阅读 较 快, 在 OSS SIEM 中 “预置能力” 仅 此一 家。

**与 SecSight 集成**:
- **查询**: Wazuh API (REST) 为主 + Indexer 背后是 OpenSearch API。 SecSight 可以双轨调用
- **SDK**: `wazuh-api` (Python, JavaScript) + `wazuh-sdk`
- **Webhook**: Wazuh 集成到 Slack / PagerDuty / Email。SecSight 可以以 “集成 alert service” 身份接入, 或 以 webhook 调 SecSight AI Core
- **向量**: Indexer 支持 kNN 插件, 可复用 OpenSearch 路径

**License**: **GPL-2.0 + Wazuh 额外解释** (Wazuh LICENSE 文件明确在 “derivative work” 上加严 — 如 集成 为封闭产品 、 定制安装包 都视为 “derivative work”)。集成 SecSight 需公开 对接 代码。

**强项**:
- 预置 “安全该有业务” — FIM / Vulnerability / MITRE 映射 / Compliance 全 涵盖
- 与 Agent 同源 (不需 从零 索引, 快速 上手)
- 免费社区版有资源完成 OSCP 使用

**弱项**:
- Wazuh Indexer 为 OpenSearch fork, 但版本推进带 环年 周重启, 生产 中 可能 仍 需 额外 OSS 补丁
- 规则与 UI 不可分离: 定制 高 但 不够灵活, AI 依赖 纵 向 接口 
- License 较可警惊: 集成 为 商业产品 需 GPL 开源

**适用场景**: 作 SecSight 的下层 host-edr 层 (上报 自己 的 告警 集合), 而不是主 聚合地。
---

### 2.6 Quickwit

**Repo**: [quickwit](https://github.com/quickwit-oss/quickwit) (tantivy: 15,926 ★)    ·    **Stars**: 11,529    ·    **Last push**: 2026-08-20

**架枂**: Rust 写的分布式搜索引擎, 背后使用 Tantivy (Lucene 的 Rust 司代). 架枂 与 ES 类似 (实时索引 集群), 但是在 存储 (S3 / 本地磁盘) 上 不同。 Sub-second aggregate 与 split 合并 为其核心。

**部署门槛**: 单可执行二进制后 资源占用较 JVM 主流轻多 (类似 Go 工程。估计 4 vCPU / 8 GB 足以跳闪 50 GB/天 日志)。但生产化 case 不多、生产者社区较小。

**学习曲线 & 运维成本**: 中。S3-compatible 存储 是 “default“。与“常规” Linux 使用方式轻微不同, 需要 习惯 “S3 = log store” 思路。

**与 SecSight 集成**:
- **查询**: 原生 Tantivy Query DSL (Lucene 样) + SQL (较 ES/OpenSearch 后落, "SQL on Quickwit" 生产中)
- **SDK**: Rust 为主 + Python/Go 社区包
- **向量**: 依赖第三方 (例 如 Hugging Face Candle, 可接入任意 Embedding 服务), 不原生
- **Alerting**: 需外部手工 (未提供 原生 alert manager)

**License**: Apache-2.0 (原生全开源)

**强项**:
- 资源较低 (无 JVM), 启动门槛低
- 以 “对象存储 + S3” 为中心的 架枂 适合 零复口 架枂 低资源云环境
- Tantivy 有 可能 仓作 实现 LLM RAG 检索底层 (NIPS 一致发表)

**弱项**:
- 产品以 “搜索引擎“身份起步、未提供 SIEM 集成者体验 (日志入 、规则与关联 都需外部)
- 生产者社区与文档要 比 Elasticsearch/Quickwit 少 记忆点多

**适用场景**: 多云 / 边缘环境, 以极低资源为需、 不作主 SIEM。
---

### 2.7 Apache Metron (警示项)

**Repo**: [metron](https://github.com/apache/metron)    ·    **Stars**: 870    ·    **Last push**: 2025-08-13    ·    **Archived**: Y

**状态**: 已被 Apache Incubator 标记为 **archived** (最后提交 2025-08-13)。社区调伽升 交货 以放弃。

**原架枂**: Kafka → NiFi → HBase → Elasticsearch → Metron UI。以资产原始日志为中心, 重由以 HBase 为背存储, 资源重、部署复杂。

**不推荐理由**:
- 项目已弃治, 后续安全补丁不保障
- HDFS/HBase 依赖 与 SecSight 中小型资源能不匹配
- 文档几乎停更 与 Spark / 机器学习环节都难起点

**Apache Spot (交叉项)**: 与 Metron 同期出现的 OSS。以“machine learning on top”为口号, 但也以 incubator 进展 几年未出产品。
---

### 2.8 其他重要项目 (简述)

**Vector** ([vector](https://github.com/vectordotdev/vector), 22k ★, MPL-2.0): 高性能日志、指标、追踪 采集器与转发平台。适合作为 “采集端” 赋能者, 不是存储与查询。可与 OpenSearch/Loki 搭配。

**Netdata** ([netdata](https://github.com/netdata/netdata), 80k ★, GPL-3.0): 指标为主、日志零。主要面向 ops 运维。不适合作 SIEM。

**Apache Spot / Apache Metron**: 同迫关。 主要调作 机器学习分析 / Insider Threat 赋能环境, 但都已偏辄 社区, 弃用 代价高。

**ELK 社区 branch / Elastic Cloud** (商业): 同样 三重许可 (商业版在可控采购许可), 资源重低低, 实重 SIEM 产品能力。
---

## 3. SecSight 推荐组合

### 3.1 主力 SIEM: OpenSearch

选型理由:
- **License 友好**: Apache-2.0, 中小企业商用、SaaS 包装、合规质量 都 无 隐 忧。
- **AI 集成友好**: ML-Commons 公开插件可用 (异常检测 / 语义检索), 不依赖 商业 license。
- **查询语言多样性**: PPL (SOC-friendly) + SQL (LLM-friendly), 使语义转查询负载低。
- **生态兼容**: REST API 与 ES 高度兼容 (迁移 、 社区插件 不需 重写)。
- **中文文档**: OpenSearch Dashboards 以及 PPL 文档已完成汉化实现 (东边相关项目已可复用)。
- **与 Wazuh 同源**: Wazuh 4.x 起 Indexer 为 OpenSearch fork, SecSight 可选 “原 Wazuh Indexer” 作为 SIEM, 或 以 独立 OpenSearch 集群 作 SIEM (适组织 GPU 重的 case)。

部署最小可行实例:
- 1 x OpenSearch (master, 4 vCPU / 8 GB / 200 GB)
- 1 x OpenSearch Dashboards (2 vCPU / 4 GB)
- 1 x Data Prepper / Logstash (输入以 “输入网关” 身份, 2 vCPU / 4 GB)
- 1 x 外部 alert / webhook consumer (即 SecSight AI Core 的 Webhook 接收端)

预计实际 30-100 GB/天日志量下 压力 低于 30% 。资源估算 包含 7x24 保留 余量。

### 3.2 替代 / 补充方案

| 场景 | 选型 | 理由 |
|---|---|---|
| 资源发限 且 指标太重 要 低资源 | **Loki + Grafana** | AGPL-3.0、资源可压缩到 4GB 工作集; Prometheus 生态能接进 SecSight 的 metrics 仪表盘 |
| 「需要原生关联引擎」 企业场景 | **Graylog** | 原生 Pipeline + CECE, 但 商业路径 需考量 SSPL |
| 要 同一业务堆 包括 安全 全 动画 | **Wazuh + Wazuh Indexer** | 预置规则 + MITRE 映射, 能力令人美慕 。 集成路径需胱照 GPL 开源原则 |

### 3.3 不推荐项目 与 理由

| 项目 | 不推荐理由 |
|---|---|
| Apache Metron | 已 archived (2025-08-13), HBase/HDFS 资源太重。 |
| Apache Spot | 几乎同期废弃。 适合 “学术越” 赋能环境、 商用难渗透。 |
| ELK 主链 (原汇 Elasticsearch+Logstash+Kibana) | License 复杂 (三重许可), JVM 资源重。 中小企业与 OpenSearch 相比 “同样产品、同样资源” 但 多三重许可复杂度、又没有免费 OSS 路径 拦截。如果需要 ELK 产品可质量试用 Elastic Cloud / 商业许可。 |
| Netdata / Prometheus | 指标强日志弱 、 不适 作 SIEM 主力。 |
| Quickwit | 仓位 宜赏, 但“搜索引擎”身份, 不是 一个完整 SIEM。 可作为 OpenSearch 补充 (极低资源 + 史小 search) 但 主力仍推 OpenSearch。 |
| Vector / Fluent Bit (alone) | 采集端 / pipeline, 不是 SIEM。 可作为输入编排。 |
---

## 4. LLM 集成友好度专项评估

### 4.1 原生 LLM 插件

| 项目 | 原生 LLM 插件 | 变途 |
|---|---|---|
| OpenSearch | **ML-Commons** (OSS, 公开插件) · + OpenSearch 二方 genAI connectors (2024 起) | 原生 嵌入形式 集成 / 语义 search |
| Elasticsearch | x-pack 在 Elastic 云服务中 集成 ELSER / 生成式 AI Assistant; 8.x 后 原生 生成 AI features 依然在 资源快为 Elastic-2.0 / SSPL 商业项目中 | 主要依赖 Elastic 云服务 |
| Graylog | 无原生 LLM | 可外挂 AI service |
| Loki | 仅 Grafana 侧 LLM (社区) | 可外挂 (但 上层 存储本身不提供 vector) |
| Quickwit | 无原生 | 需外部 |
| Wazuh | 无原生 | 需外部 (但可复用 Wazuh Indexer 后端 OpenSearch 路径) |

### 4.2 查询语言 适合 LLM 生成程度 (可控制性)

评测框架:
1. **语义反冶**: 是否有实参 “该查询”反看能不能反表达。
2. **述语交互可表达能力**: LLM 以 “SQL/PPL/KQL” 带参的能力 取 决于 pre-trained corpus 。
3. **不确定性 / 错误集**: 能不能在参数 上错 时 告知 (例 如 PPL 有 fuzzy 检查) 。

| 项目 | 查询语言 | LLM 生成友好度 | 备注 |
|---|---|---|---|
| OpenSearch | **PPL + SQL** | 高 (两种都可生成 / SQL 交互付 corpus 丰富) | PPL 适 SOC, SQL 适 SQL agent |
| Elasticsearch | **ES|QL + EQL + DSL** | 中 (主流 LLM 熟知 ES DSL 但 ES|QL 近期 corpus 较少) | 以 DSL 为主、 ES|QL 为辅 |
| Graylog | REST Search API | 中低 (创建人现成, 需推业务描述) | 可生成但需预处理 |
| Loki | LogQL | 中 | Prometheus LogQL 类似语义。但全文检索不可用 filter 全公式 |
| Wazuh | Wazuh API (定制) | 低 | 主要 适 Wazuh Manager |
| Quickwit | Lucene DSL | 中 | Lucene query_string 为主 |

### 4.3 向量检索 与 语义去重

仅 OpenSearch 与 Elasticsearch 原生提供向量检索:
- **OpenSearch**: `knn_vector` 字段 、 OpenSearch 2.4+ 提供语义结果 结合 BM25 + knn 高调 (所谓 “Hybrid Search”)。
- **Elasticsearch**: dense_vector 字段 + ELSER (稀疏向量) 、 semantic_text (适 8.10+)。

SecSight 使用场景: “同一事件创建多个告警、需要 AI 判定它们是不是同一个” — 将告警文本向量化、在 kNN 中去重, 使用 OpenSearch 是最快路径：

### 4.4 与 LangChain / LlamaIndex 集成

| 仪表盘 | LangChain Integration | LlamaIndex Integration |
|---|---|---|
| OpenSearch | `langchain-opensearch` VectorStore (com.example / langchain-community) · `OpenSearchVectorSearch` · hybrid BM25 + knn 调用 | `OpensearchVectorClient` (社区 mainline, 生产中), 全语义不可用 — 多依赖 hybrid query |
| Elasticsearch | `langchain-elasticsearch` (官方 VectorStore), ELSER + dense 同时调用 | `ElasticsearchVectorStore` (官方), RAG cache |
| Loki | 日志不适 vector. 可以 “Loki Source” 输入代替 | 同上, 仅作为原始文本赋能 (输入到 LlamaIndex Reader) |
| Graylog | 另使用 Graylog 为 text 语义, 后接外部 Vector Store | 同上 |

**结论**: 选 OpenSearch 为 SecSight SIEM, LangChain 作为 AI 采购 则 可同时 接入 OpenSearch VectorStore + BM25 能 使 告警 语义去重 、 事件查询、 交互追问 三位一体。
---

## 5. SecSight 集成难点

### 5.1 日志归一化 (入库前规范)

主要来源体 (多重交叉):
- Wazuh/agent (以 JSON 为主、 字段以 `agent.id、agent.name、rule.id、rule.level` 等为未动 500+ 字段)
- Suricata (eve.json; 含 alert / http / dns / flow / 其他事件)
- Linux auditd / Windows EventLog / Sysmon (XML 转发为 JSON)
- 网关 设备 (Cisco ASA / Huawei / H3C / 费路由器)
- Web (nginx/apache 访问日志 + WAF 产物 起 钜 起, 与 WAF 产物按 以 赋能 )
- 云 (AWS CloudTrail / 阿里云 ActionTrail / Azure ActivityLog)

常见难点:
1. **时区不一**: 不同 agent 采集 以 本地时间为主、 交叉调查中 出现 以 对象 、 以 事件 为主。 建议: SecSight 集中将 `@timestamp` 重置为 ISO8601 + UTC + 带地区子字段 `本地时区`。
2. **IP / 主机名**: 云上 实例可能有 调起以及 IP 变动。 推荐 以 云资产 ID + 本地 终端 IP 集。加上 主机资产表维护表 (CMDB)。
3. **事件重复 / 词汇不一**: 同一事件在 安全设备 与 网络 与云控中被多次创建。 需 在 SecSight AI Layer 设置 “事件词汇 / 字段 以 “同一事件” ” 的抵近。
4. **中文文本**: 部分 SIEM 未赋中文分词器。 SecSight 推荐 嵌入中文分词纪召取 (jieba-rs / IK 分词) 后入库 。 OpenSearch 原生包含 IK 仓位 (起 原生 是 中文 analyzer)。

推荐规范: **ECS** (Elastic Common Schema) 是 ES/Logstash/Kibana 生态 的 公共 schema。生产中 OpenSearch Dashboards 也能读取。SecSight 推荐在 采集以 Logstash / Data Prepper 处 转换为 ECS 类型。

### 5.2 索引设计 & 保留策略

索引体系 (推荐 适 500 资产中小型企业):
- **按事件类型分索引** (通用语义表 以起):
  - `secsiem-wazuh-*`、 `secsiem-suricata-*`、 `secsiem-os-*` …
  - 依 `@timestamp` 按天划分 (额外 考量 锁定)。
  - 含 ILM (保留 30-90 天 热、 365 天 冷)。
- **警报事件独立表**: `secsiem-alerts-*` （由 Alerting service 写入）。 含 vector 字段 以 供 语义去重。
- **CMDB 表 类**: `secsiem-cmdb-assets`（以 hosts/ips 为主键）。需联动刺重同步到 “权重重复” 检查。

### 5.3 与上游 Agent 的对接

| 上游 | 对接点 | 是否可复用 OpenSearch |
|---|---|---|
| Wazuh Manager | Manager REST API + Syslog Forwader → SecSight | 是 (背后 Indexer 是 OpenSearch). 推荐 SecSight 选择 “独立集群” 以 治体 |
| Suricata (eve.json) | Filebeat / Vector / Logstash | 是 。以 Logstash 解析 eve.json |
| Sysmon / Win EventLog | Winlogbeat 或 Vector 对入 SecSight 接口 | 是 |
| 云控使用 | CloudTrail / ActionTrail + OK 项 。路由 SecSight API 接入 | 是 |

### 5.4 性能与平台限制 (中小型调优)

- 默认 30 天热保留 + 365 天冷保留 中量 业务 (约 100 GB/天), 一个 4 vCPU / 16GB 节点 能 起 。
- 依重点项 是 业务多重云产生事件裂发 。建议 以 ingest pipeline 为 安全 、 低限制安全频度。
- AI Core 调起 频率 以 免 说发 处在执行 以 集群压力。 以 多上、 多代理 多事件 交付。
---

## 6. 引用

### 6.1 项目与代码仓库

- [elasticsearch](https://github.com/elastic/elasticsearch)  (本文中起 ASCII 。LICENSE.txt、报警与发布代码都可查。)
- [logstash](https://github.com/elastic/logstash)
- [kibana](https://github.com/elastic/kibana)
- [OpenSearch](https://github.com/opensearch-project/OpenSearch)
- [OpenSearch-Dashboards](https://github.com/opensearch-project/OpenSearch-Dashboards)
- [logstash-output-opensearch](https://github.com/opensearch-project/logstash-output-opensearch)
- [graylog2-server](https://github.com/Graylog2/graylog2-server)
- [loki](https://github.com/grafana/loki)
- [grafana](https://github.com/grafana/grafana)
- [wazuh](https://github.com/wazuh/wazuh)
- [metron](https://github.com/apache/metron)  (已 archived)
- [quickwit](https://github.com/quickwit-oss/quickwit)
- [tantivy](https://github.com/quickwit-oss/tantivy)
- [vector](https://github.com/vectordotdev/vector)

### 6.2 文档与背景

1. [Elasticsearch LICENSE.txt 三重许可](https://github.com/elastic/elasticsearch/blob/main/LICENSE.txt)
2. [Elasticsearch LICENSE 变更历史 commit (2021, 2024)](https://github.com/elastic/elasticsearch/commits/main/LICENSE.txt)
3. [Graylog LICENSE 变更 commit (2020-11-16 起 SSPL)](https://github.com/Graylog2/graylog2-server/commits/master/LICENSE)
4. [OpenSearch LICENSE.txt (Apache-2.0)](https://github.com/opensearch-project/OpenSearch/blob/main/LICENSE.txt)
5. [Quickwit LICENSE (Apache-2.0)](https://github.com/quickwit-oss/quickwit/blob/main/LICENSE)
6. [Wazuh LICENSE (GPL-2.0 + 加严)](https://github.com/wazuh/wazuh/blob/main/LICENSE)
7. [Apache Metron 项目页 (archived 标记)](https://github.com/apache/metron)
8. [OpenSearch PPL 语法](https://opensearch.org/docs/latest/searching/ppl/index/)
9. [OpenSearch ML-Commons plugin](https://opensearch.org/docs/latest/ml-commons-plugin/index/)
10. [Elasticsearch ES|QL (查询语言)](https://www.elastic.co/guide/en/elasticsearch/reference/current/esql.html)
11. [Loki 架枂文档](https://grafana.com/docs/loki/latest/fundamentals/architecture/)
12. [Wazuh SIEM (主项目)](https://documentation.wazuh.com/current/user-manual/index.html)
13. [ECS (Elastic Common Schema)](https://www.elastic.co/guide/en/ecs/current/index.html)
14. [langchain-opensearch](https://github.com/langchain-ai/langchain/blob/master/libs/community/langchain_community/vectorstores/opensearch.py)
15. [Graylog CECE pipeline 文档](https://go2docs.graylog.org/current/making_sense_of_your_log_data/pipelines.html)

### 6.3 调研记录

- GitHub API 调用时间: 2026-08-20 (本机 Asia/Shanghai)
- LICENSE.txt 读取时间: 2026-08-20 (以 raw.githubusercontent.com 原始读取为准)
- 本报告生成时间: 2026-08-21

### 附录 A: 本报告跳过的面向

- 安全类企业产品 (Splunk Enterprise Security 、 IBM QRadar 、 Microsoft Sentinel 、 Sumo Logic) — 商业产品不在 SecSight 范围。
- 全 SIEM 跳过设备对调使用 (SOAR 、 UEBA) — 本文重点是日志聚合层，不涉及 SOAR 报警响应 话题。
- 以 host 为重心的产品不在该调研范围内（如 OSQuery、Falco）。