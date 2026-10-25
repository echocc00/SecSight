# AI 开发规则 — SecSight

> 本文件给所有参与 SecSight 开发的 AI 助手(Claude Code 等)阅读,约束开发行为。

## 1. License 隔离(最高优先级,不可违反)

SecSight 计划商业化,AGPL/GPL 组件必须进程隔离:

- **禁止**在 SecSight backend/frontend 代码中 `import` 以下任何项目的 SDK/代码:
  - Shuffle (AGPL-3.0)
  - Wazuh (GPL-2.0)
  - KubeHound (AGPL-3.0)
  - Velociraptor (AGPL-3.0)
- 这些组件作为**独立 docker 服务**部署,仅通过 HTTP/Webhook/REST 调用
- **禁止**安装 DFIR-IRIS 的 AGPL 模块: iris-skeleton-module / iris-mwdb-module / iris-intelowl-module (仅用主本体 iris-web, LGPL-3.0)
- **禁止** fork 或复制 ASP (agentic-soc-platform) 代码(其无正式 LICENSE 文件),仅借鉴领域模型设计

每次新增依赖前,必须检查其 License。AGPL/GPL/SSPL 一律走进程隔离。

## 2. 架构约束

- AI 编排: **LangGraph StateGraph** (非 ASP/AutoGen)
- LLM 调用: 经 **LiteLLM 网关**统一路由,不直接调厂商 SDK
- 工具调用: **HTTP/REST 直调** (License 隔离通过网络边界实现,不 import 隔离组件 SDK)
- 数据归一化: **ECS schema**,经 Vector 入 OpenSearch
- 自主性: 每个处置动作必须标注 `autonomy_level` (L1-L5),L2 高危强制双签
- LLM 输出: 强制 Pydantic 结构化 + ATT&CK TTP 白名单(RAG 召回才能引用)

## 3. LLM 合规

- 生产研判主链路: **仅境内厂商** (DeepSeek/MiniMax/Qwen),数据不出境
- 境外 API (Claude/GPT): 仅脱敏后人工复核备选,**禁止**进生产研判主链路(等保合规)
- 本地 vLLM/Qwen2.5: 仅敏感场景/离线备选,非默认

## 4. 情报源

- Phase1-3: **仅免费源** (AbuseIPDB/OTX/MISP社区/OpenCTI),付费 provider 只定义适配器类不实现
- OpenCTI (AGPL) 作为情报源走 HTTP GraphQL,不 import pycti
- 免费源场景: 封禁类动作默认走 L2 审批(不自动封,避免误伤业务)
- 新增 provider: 实现 `ThreatIntelProvider` 抽象接口,不改上层

## 5. 代码规范

- 后端: Python 3.11+, FastAPI, 类型注解必填, Pydantic 校验
- 函数 < 50 行, 文件 < 800 行, 避免深嵌套(>4层用早返回)
- 不可变优先, 不原地修改
- 错误显式处理, 不静默吞错
- 测试覆盖 >= 80%
- **鉴权**: JWT access(短时效)+ refresh token(存 hash、轮换、吊销),refresh 永不能当 access 用
- **路由鉴权基线**: 新增 router 必须显式声明鉴权策略(全局 JWT 依赖或 webhook 共享密钥),不允许默认裸奔;业务端点按权限矩阵挂 `require_permission`(见 `auth/service.py` PERMISSIONS)
- **审批身份**: approver_role/approver_user 只能从 JWT 解出(`APPROVAL_ROLE_MAP` 服务端映射),请求体出现身份字段一律视为漏洞;同一用户同一动作只能签一票
- **回调/webhook 准入**: IM 回调走签名校验(飞书 X-Lark-Signature / 钉钉加签),告警 webhook 走 `X-SecSight-Webhook-Token`;密钥未配置一律 403 fail-closed,不允许"未配置=放行"
- **认证降级**: 认证路径禁止静默降级(生产 DB 异常必须 503),demo 用户仅限显式 mock_mode + 非生产
- **审批判定**: 执行器必须读 `ApprovalRecordModel` 表(record_repo.is_action_approved),不得读 `case.approvals` dict —— 后者已随双真相源清理删除,别再引入类似字段
- **审批终态**: 任一角色 rejected → Case 关闭(resolved),不再吸收签名;已闭环(resolved/closed)案件拒绝新审批
- **处置目标**: action.target 必须从告警解析真实资产(host/ip/pid/domain),playbook parameters 只是静态策略
- **时间戳**: 后端用 naive UTC,前端统一经 `parseUtc()`/`formatDateTime()`(lib/datetime.ts)按 UTC 解析,禁止裸 `dayjs(str)` 按本地时区
- **实时推送**: 审批/告警入 Case/执行步骤走 `broadcaster.publish()`,前端订阅 `onEvent(type)`;加新事件类型同时发 broadcast
- **健康端点**: `/health` 保持无鉴权(docker healthcheck 依赖)但只放组件连通性;执行能力/限流/调度等运维细节放需鉴权的 `/api/status`

## 6. 目录结构

见仓库根目录。关键:
- `backend/app/agents/` — LangGraph agents + 编排节点 (nodes.py)+ Proactive 调度 (scheduler.py)
- `backend/app/llm_gateway/` — LLM 网关 (mock 降级)
- `backend/app/threat_intel/` — 情报抽象 + provider (service.py 聚合)
- `backend/app/realtime/` — WebSocket 事件广播 (broadcast.py)
- `playbooks/phase1/` — 6 个 P0 剧本 YAML
- `backend/app/integrations/` — 外部系统 HTTP 客户端 (wazuh/opensearch/opencti/notify/国产设备)
- `knowledge/L0-L3` — 4 层知识库
- `policies/` — 自主性/审批规则
- `deploy/` — docker-compose + 配置 + alembic 迁移 (migrate.sh)
- `backend/requirements*.lock` — 依赖锁定 (改 pyproject 必须重跑 pip-compile,CI 有校验)

## 7. 文档优先

选型决策记录在 `docs/03-selection-arbitration.md`。遇到选型分歧,回退到该文档,不自行臆断。变更走版本号(v1.1/v1.2)。
