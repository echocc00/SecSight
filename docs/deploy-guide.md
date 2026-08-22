# SecSight 部署指南

> Phase2 生产化全栈部署 (7 组件 + 监控)

## 1. 硬件要求

| 配置 | CPU | 内存 | 磁盘 | 适用 |
|---|---|---|---|---|
| 最小 (验证) | 16C | 32G | 500G | 仅主体 + Wazuh + OpenSearch |
| 推荐 (生产) | 32C | 64G | 1T SSD | 全栈 7 组件 + 监控 |
| 拆分 (大数据量) | 2 台 | 控制面 32G + 数据面 64G | — | > 500 资产 |

**GPU**: 不需要 (云端 LLM)。本地 LLM 场景需 1× RTX 4090/A100。

## 2. 前置准备

```bash
# 1. 克隆
git clone https://github.com/echocc00/SecSight.git
cd SecSight

# 2. 配置环境变量
cd deploy
cp .env.example .env

# 3. 编辑 .env,必填项:
#    - POSTGRES_PASSWORD / OPENSEARCH_PASSWORD (数据库密码)
#    - DEEPSEEK_API_KEY 或 MINIMAX_API_KEY (LLM,二选一)
#    - WAZUH_MANAGER_PASSWORD (Wazuh)
#    - SECSIGHT_MOCK_MODE=false (真实模式)
#    - ENABLE_THREAT_INTEL=true + ABUSEIPDB_API_KEY (情报,可选)
```

## 3. 分步部署 (推荐)

### 3.1 主体组 (SecSight 核心)
```bash
docker compose up -d postgres redis qdrant litellm
docker compose up -d secsight-backend secsight-frontend

# 验证
curl http://localhost:8000/health
curl http://localhost:8080
```

### 3.2 基础设施组 (SIEM/采集)
```bash
docker compose up -d opensearch vector
docker compose up -d wazuh-indexer wazuh-manager wazuh-dashboard

# 验证
curl https://localhost:9201 -u admin:$WAZUH_INDEXER_PASSWORD -k
# Wazuh Dashboard: https://localhost:5601
```

### 3.3 隔离组 (AGPL/GPL,独立网络)
```bash
docker compose up -d shuffle shuffle-db shuffle-redis
docker compose up -d opencti redis-opencti minio rabbitmq-opencti
docker compose up -d dfir-iris

# Shuffle: http://localhost:3001
# OpenCTI: http://localhost:8082
# DFIR-IRIS: http://localhost:8001
```

### 3.4 监控组
```bash
docker compose up -d prometheus grafana
# Prometheus: http://localhost:9090
# Grafana: http://localhost:3000 (admin/见 .env GRAFANA_ADMIN_PASSWORD)
```

### 3.5 一键全栈
```bash
docker compose up -d
# 等待 ~3 分钟 (健康检查 start_period)
docker compose ps   # 确认全绿
```

## 4. 知识库入库 (Qdrant)
```bash
docker compose exec secsight-backend python /app/scripts/ingest_knowledge.py
# 或本地:
cd backend && PYTHONPATH=. python scripts/ingest_knowledge.py
```

## 5. Wazuh Agent 注册 (被监控主机)
```bash
# 在每台被监控主机:
# Linux:
curl -so wazuh-agent.sh https://packages.wazuh.com/4.x/install.sh
sudo WAZUH_MANAGER=<server-ip> WAZUH_REGISTRATION_PASSWORD=<password> bash wazuh-agent.sh
sudo systemctl start wazuh-agent

# Windows: 下载 https://packages.wazuh.com/4.x/windows/ 安装
```

## 5b. Wazuh → SecSight Webhook (实时告警推送)

让 Wazuh 把告警实时推送到 SecSight,而不是 SecSight 轮询 (TTTR 更低):

```bash
# 进入 Wazuh manager 容器
docker compose exec wazuh-manager bash

# 编辑 /var/ossec/etc/ossec.conf,在 <ossec_config> 内加 custom integration:
cat >> /var/ossec/etc/ossec.conf <<'XML'
<integration>
  <name>custom-webhook</name>
  <hook_url>http://secsight-backend:8000/api/alerts/wazuh-webhook</hook_url>
  <rule_id>5710,5712,550,591,31151</rule_id>
  <alert_format>json</alert_format>
</integration>
XML

# 重启 manager
/var/ossec/bin/wazuh-control restart
```

或用 SecSight 轮询模式 (无需改 Wazuh 配置):
```bash
# 定时轮询 Wazuh API
curl -X POST http://localhost:8000/api/alerts/wazuh/poll?limit=20
```

## 5c. Shuffle Workflow 配置 (SOAR 执行)

启用真实 Shuffle 执行 (替代 mock):

1. **创建 Workflow**: 访问 http://localhost:3001,登录后创建以下 Workflow:
   - `isolate_host` — 调防火墙 API 隔离主机
   - `block_ip` — 封禁 IP
   - `kill_process` — Wazuh active response kill 进程
   - 等 (见 SHUFFLE_WORKFLOW_<TYPE>)

2. **填入 Workflow ID**: 在 .env 加
   ```bash
   ENABLE_SHUFFLE=true
   SHUFFLE_WORKFLOW_ISOLATE_HOST=<workflow-id-from-shuffle>
   SHUFFLE_WORKFLOW_BLOCK_IP=<workflow-id>
   # ...
   ```

3. **验证**: 端到端测试
   ```bash
   SECSIGHT_MOCK_MODE=false ENABLE_SHUFFLE=true python scripts/verify_real_deploy.py
   ```

未配置 Workflow 的动作自动降级 mock (不阻塞闭环)。

## 6. 健康检查

```bash
# 全栈健康
docker compose ps --format "table {{.Name}}\t{{.Status}}"

# SecSight 自身健康 (含各组件连通性)
curl http://localhost:8000/health

# 预期: {"status":"ok", "components": {"postgres":"ok", "qdrant":"ok", ...}}
```

## 7. License 隔离验证

部署后必须验证 AGPL/GPL 组件未被代码 import:

```bash
# CI 自动执行,也可手动:
cd backend
grep -rE "import (shuffle|wazuh_sdk|velociraptor|iris_modules)" app/ && echo "❌ 违规" || echo "✅ 隔离正常"

# 确认 DFIR-IRIS 未装 AGPL 模块
docker compose exec dfir-iris ls /app/iris/modules/ 2>/dev/null | grep -E "skeleton|mwdb|intelowl" && echo "❌ AGPL 模块" || echo "✅ 仅主本体"
```

## 8. 常见故障

| 问题 | 原因 | 解决 |
|---|---|---|
| 端口冲突 (8000/5601等) | 其他服务占用 | 改 .env 端口或停冲突服务 |
| OpenSearch 启动失败 | 内存不足 | 增大 vm.max_map_count 或加内存 |
| Wazuh Agent 注册失败 | 密码错/端口不通 | 检查 WAZUH_REGISTRATION_PASSWORD + 1514/1515 端口 |
| LiteLLM 401 | API key 错/过期 | 检查 DEEPSEEK_API_KEY/MINIMAX_API_KEY |
| SecSight backend 500 | DB 连接失败 | 检查 postgres 健康 + DATABASE_URL |
| Qdrant 检索为空 | 未入库 | 执行 §4 知识库入库 |
| Grafana 无数据 | Prometheus 抓取失败 | 检查 prometheus.yml targets + /metrics 可访问 |

### OpenSearch vm.max_map_count (Linux 宿主机)
```bash
sudo sysctl -w vm.max_map_count=262144
# 永久: echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf
```

## 9. 升级流程
```bash
git pull
docker compose build secsight-backend secsight-frontend
docker compose up -d --force-recreate secsight-backend secsight-frontend
# 数据卷保留,无需重新入库
```

## 10. 实跑冒烟验证记录 (2026-08-22)

已验证的真实链路 (docker 容器 + 真实 backend):

| 链路 | 验证结果 |
|---|---|
| OpenSearch 索引+检索 | ✅ 注入告警 → 索引 → 全文搜索命中 |
| Wazuh webhook 接收 | ✅ 真实 Wazuh 格式 JSON → Case + 剧本匹配 |
| 国产设备 webhook | ✅ 奇安信格式 → Case + web_attack 剧本匹配 |
| 双签审批闭环 | ✅ 三签 (isolate_host 需 ciso) + 双签 (kill_process) 正确判定 |
| 完整执行链路 | ✅ resolved, TTTR 51s, 3/3 动作执行, Evidence Pack |
| 合规报告生成 | ✅ Markdown 报告含 8 章节 |

验证命令:
```bash
# 起 OpenSearch 容器
docker run -d --name secsight-os -p 9200:9200 \
  -e discovery.type=single-node -e OPENSEARCH_INITIAL_ADMIN_PASSWORD=SecSightAdmin123 \
  opensearchproject/opensearch:2.13.0

# 起 backend 连 OpenSearch
ENABLE_OPENSEARCH=true OPENSEARCH_URL=https://localhost:9200 \
  OPENSEARCH_USER=admin OPENSEARCH_PASSWORD=SecSightAdmin123 \
  uvicorn app.main:app --port 8001

# 注入 → 搜索
curl -X POST localhost:8001/api/alerts/inject -d '{"alert_type":"xmrig_process"}'
curl 'localhost:8001/api/alerts/search?q=xmrig'
```

待验证 (需完整 docker compose 环境):
- Wazuh Manager custom integration 推送 (需 Wazuh 容器 + ossec.conf 配置)
- Shuffle Workflow 执行 (需 Shuffle UI 创建 workflow)
- Qdrant RAG (需知识入库)
```bash
git pull
docker compose build secsight-backend secsight-frontend
docker compose up -d --force-recreate secsight-backend secsight-frontend
# 数据卷保留,无需重新入库
```

## 11. 资源调优

若内存不足,按优先级降级:
1. 先停 Grafana/Prometheus (非核心)
2. 停 OpenCTI (情报可降级 mock)
3. 停 DFIR-IRIS (案件用本地 Postgres)
4. Wazuh Indexer + OpenSearch 合并 (小规模)

**最小可运行**: postgres + qdrant + litellm + secsight-backend + frontend (5 服务, ~8G 内存)
