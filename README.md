# SecSight — AI 驱动的安全运维平台

> AI 辅助的 SecOps Copilot + 自动处置 SOAR 引擎。
> 监控业务系统 → AI 研判 → 半自动应急响应 → 知识沉淀。

> 💼 **商业授权 / Commercial licensing**
>
> 本项目以开源协议发布(详见 [LICENSE](./LICENSE)),你可自由用于个人/企业内部项目。
> 若你希望用于**对外商业产品 / SaaS / 销售**并需要:
> - 作者署名可移除 / 不想被认出来源
> - 闭源分发 / 不公开修改
> - 长期维护支持 / 私有定制
> - 法律意见 / 合规背书
>
> 请通过以下方式联系作者协商**独立商业授权**:
> - GitHub: [@echocc00](https://github.com/echocc00)
> - 项目主页 Issues / Discussions(按项目)
>
> 大部分项目 24 小时内响应,首次咨询免费。
>
> *(本说明不构成法律意见,具体权利义务以 [LICENSE](./LICENSE) 文本为准。)*

---


## 核心定位

面向中小型企业(≤500 资产)的 AI 安全运维平台,通过集成成熟开源组件 + 自研 AI 编排大脑,把传统 SOC 的"采集→告警→人工分析→处置"压缩为"采集→AI研判→半自动响应"。

**关键决策**: 不重新发明轮子——检测/SIEM/SOAR/漏洞扫描全部用成熟开源项目,SecSight 自身只做 AI 研判编排 + 场景化剧本 + 统一事件总线。

## 技术栈

| 层 | 选型 |
|---|---|
| 主机 EDR | Wazuh + Sysmon-Modular + Falco |
| 网络检测 | Suricata + Arkime + Coraza + CrowdSec |
| SIEM/日志 | OpenSearch + Vector (ECS schema) |
| 威胁情报 | OpenCTI CE + 免费源(付费接口预留) |
| SOAR 执行 | Shuffle (AGPL 隔离部署) |
| 漏洞/攻击面 | Nuclei + Trivy + KubeHound + Nmap |
| AI 核心 | LangGraph + LiteLLM 网关 + 云端 LLM(DeepSeek/MiniMax) + Qdrant |
| 案件管理 | DFIR-IRIS (LGPL-3.0) |
| 工具协议 | MCP |
| 后端/前端 | FastAPI + Vite/React/Antd |

## 核心特性

- **22 个真实企业剧本**(按业务系统分组),Phase1 优先 6 个 P0(勒索/挖矿/持久化/暴破/日志合规/服务崩溃)
- **5 级自主性**(L1-L5),每动作标注 autonomy_level,高危处置 L2 强制双签
- **4 层知识库**(L0 框架/L1 战术/L2 剧本/L3 案例),运行时沉淀形成飞轮
- **私有化优先**,AGPL/GPL 组件进程隔离,主体可闭源商业化
- **国产化适配**,境内 LLM + 等保 2.0 合规

## 文档

| 文档 | 说明 |
|---|---|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | 整体架构(A 体系) |
| [docs/02-design.md](docs/02-design.md) | 详细设计(B 体系,概念框架来源) |
| [docs/03-selection-arbitration.md](docs/03-selection-arbitration.md) | 选型裁决记录(v1.1,收敛版) |
| [docs/04-implementation-phase1.md](docs/04-implementation-phase1.md) | Phase1 实施计划 |
| [docs/research/](docs/research/) | 7 份子领域调研报告 |

## 快速开始

```bash
# 1. 配置环境变量
cp deploy/.env.example deploy/.env
# 编辑 .env: 填入 DeepSeek/MiniMax API key、Wazuh/OpenSearch 密码等

# 2. 启动基础设施(分组建议)
cd deploy
docker compose up -d postgres qdrant litellm opensearch vector
docker compose up -d wazuh-manager wazuh-indexer wazuh-dashboard
docker compose up -d shuffle opencti dfir-iris

# 3. 启动 SecSight 主体
docker compose up -d secsight-backend secsight-frontend

# 4. 访问
# SecSight Dashboard:  http://localhost:8080
# Wazuh Dashboard:     http://localhost:5601
# OpenSearch Dashboards: http://localhost:5602
# Shuffle:             http://localhost:3001
# OpenCTI:             http://localhost:8080
# DFIR-IRIS:           http://localhost:8000
```

> 详细部署见 [docs/04-implementation-phase1.md](docs/04-implementation-phase1.md)。

## License

SecSight 主体代码: Apache-2.0 (可闭源商业化)。
集成组件遵循各自 License,AGPL/GPL 组件(Shuffle/Wazuh/KubeHound)进程隔离部署,不链接代码。

## 状态

🚀 v0.4.0 — 真实部署验证: Wazuh webhook + Shuffle SOAR 真实执行。12 剧本 + 5 真实组件 + 生产化加固。234 测试,覆盖率 87.8%。

**v0.4 新增 (真实部署链路)**:
- Wazuh webhook 接收器: 实时接收 Wazuh 推送告警 (替代 mock 注入),TTTR 更低
- 真实 Shuffle SOAR 执行器: REST API 触发 Workflow,故障降级 mock
- 部署验证脚本 + Wazuh/Shuffle 配置文档
- docker-compose 7 组件全栈 + 健康检查 + 资源限制

**Phase2 新增**:
- 生产化加固: JWT 认证 + 4 角色 (admin/analyst/approver/viewer) + 权限矩阵
- 监控: Prometheus 指标 (/metrics) + Grafana SOC KPI 面板 + 扩展健康检查
- 安全: slowapi 速率限制 + PII 脱敏 + CORS 收紧 + 密钥校验
- 合规: 等保 2.0 三级报告自动生成 (HTML/Markdown,Jinja2 模板)
- +6 P1 剧本: Web攻击/数据外泄/横向移动/提权/C2/钓鱼
- docker-compose 全栈生产化: 7 组件 + 健康检查 + 资源限制 + 网络隔离
- CI: license 隔离检查 + 测试覆盖率门槛 80%

**LLM 接入** (mock_mode=false):
- 真 LLM 主: MiniMax (OpenAI 兼容直连),研判由真实推理生成
- 故障降级: LLM 调用/解析失败自动回退 mock,闭环不断
- 健壮解析: schema 驱动枚举约束 + 归一化器 (severity 大小写/true_positive 布尔/kill_chain_phase list/置信度/截断 JSON)
- 组件解耦: LLM/检索/执行各自独立开关 (SECSIGHT_MOCK_MODE / ENABLE_QDRANT / ENABLE_SHUFFLE)

**威胁情报接入** (ENABLE_THREAT_INTEL=true):
- 免费源: AbuseIPDB (IP 信誉) + OTX (IP/域名/hash/url,无 key 也可用)
- 多源聚合: 并行查询 + 置信度合成 (多源命中 0.7+,单源 0.4)
- IoC 自动提取: 从告警提取 IP/域名/hash,内网 IP/API 域名过滤
- 故障降级: 真实 API 失败自动回退 mock
- workflow 接入: enrich_ioc 节点 (retrieve→enrich→analyze),情报进 LLM prompt

**真实组件接入** (各自独立开关):
- Qdrant RAG (ENABLE_QDRANT): numpy TF-IDF embedding + HNSW 向量检索,知识入库脚本
- Shuffle SOAR (ENABLE_SHUFFLE): REST API 触发 Workflow,AGPL 隔离,action_type→workflow_id 映射
- Wazuh 告警 (POST /api/alerts/wazuh/poll): API 查 /security/events 或读 alerts.json,归一化为 Alert→Case

**已验证剧本** (mock 端到端):
| 剧本 | MITRE | L2 审批 | 自动闭环 |
|---|---|---|---|
| 挖矿病毒 | T1496 | ✓ | — |
| 勒索病毒 | T1486 | ✓ | — |
| 持久化清除 | T1053.003 | ✓ | — |
| SSH 暴破 | T1110 | ✓ | — |
| 日志合规 | T1562 | — | ✓ (无 L2 自动执行) |
| 服务崩溃 | T1489 | ✓ | — |
