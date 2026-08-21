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

## 10. 资源调优

若内存不足,按优先级降级:
1. 先停 Grafana/Prometheus (非核心)
2. 停 OpenCTI (情报可降级 mock)
3. 停 DFIR-IRIS (案件用本地 Postgres)
4. Wazuh Indexer + OpenSearch 合并 (小规模)

**最小可运行**: postgres + qdrant + litellm + secsight-backend + frontend (5 服务, ~8G 内存)
