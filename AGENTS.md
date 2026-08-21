# AI 开发规则 — SecSight

> 本文件给所有参与 SecSight 开发的 AI 助手(Claude Code 等)阅读,约束开发行为。

## 1. License 隔离(最高优先级,不可违反)

SecSight 计划商业化,AGPL/GPL 组件必须进程隔离:

- **禁止**在 SecSight backend/frontend 代码中 `import` 以下任何项目的 SDK/代码:
  - Shuffle (AGPL-3.0)
  - Wazuh (GPL-2.0)
  - KubeHound (AGPL-3.0)
  - Velociraptor (AGPL-3.0)
- 这些组件作为**独立 docker 服务**部署,仅通过 HTTP/Webhook/REST/MCP 调用
- **禁止**安装 DFIR-IRIS 的 AGPL 模块: iris-skeleton-module / iris-mwdb-module / iris-intelowl-module (仅用主本体 iris-web, LGPL-3.0)
- **禁止** fork 或复制 ASP (agentic-soc-platform) 代码(其无正式 LICENSE 文件),仅借鉴领域模型设计

每次新增依赖前,必须检查其 License。AGPL/GPL/SSPL 一律走进程隔离。

## 2. 架构约束

- AI 编排: **LangGraph StateGraph** (非 ASP/AutoGen)
- LLM 调用: 经 **LiteLLM 网关**统一路由,不直接调厂商 SDK
- 工具调用: **MCP 协议**,每个外部系统封装独立 MCP server
- 数据归一化: **ECS schema**,经 Vector 入 OpenSearch
- 自主性: 每个处置动作必须标注 `autonomy_level` (L1-L5),L2 高危强制双签
- LLM 输出: 强制 Pydantic 结构化 + ATT&CK TTP 白名单(RAG 召回才能引用)

## 3. LLM 合规

- 生产研判主链路: **仅境内厂商** (DeepSeek/MiniMax/Qwen),数据不出境
- 境外 API (Claude/GPT): 仅脱敏后人工复核备选,**禁止**进生产研判主链路(等保合规)
- 本地 vLLM/Qwen2.5: 仅敏感场景/离线备选,非默认

## 4. 情报源

- Phase1-3: **仅免费源** (AbuseIPDB/OTX/MISP社区),付费 provider 只定义适配器类不实现
- 免费源场景: 封禁类动作默认走 L2 审批(不自动封,避免误伤业务)
- 新增 provider: 实现 `ThreatIntelProvider` 抽象接口,不改上层

## 5. 代码规范

- 后端: Python 3.11+, FastAPI, 类型注解必填, Pydantic 校验
- 函数 < 50 行, 文件 < 800 行, 避免深嵌套(>4层用早返回)
- 不可变优先, 不原地修改
- 错误显式处理, 不静默吞错
- 测试覆盖 >= 80%

## 6. 目录结构

见仓库根目录。关键:
- `backend/app/agents/` — LangGraph agents
- `backend/app/llm_gateway/` — LiteLLM 集成
- `backend/app/threat_intel/` — 情报抽象 + provider
- `playbooks/phase1/` — 6 个 P0 剧本 YAML
- `mcp_servers/` — MCP 工具 server
- `knowledge/L0-L3` — 4 层知识库
- `policies/` — 自主性/审批规则
- `deploy/` — docker-compose + 配置

## 7. 文档优先

选型决策记录在 `docs/03-selection-arbitration.md`。遇到选型分歧,回退到该文档,不自行臆断。变更走版本号(v1.1/v1.2)。
