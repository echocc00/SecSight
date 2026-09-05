# Shuffle Workflow 模板

SecSight 通过 Shuffle REST API 触发处置动作。**Shuffle 是 AGPL-3.0,SecSight 不 import 其代码,仅 HTTP 调用** (License 隔离,见 [AGENTS.md](../../AGENTS.md) §1)。

## 为什么需要手动配置

Shuffle Workflow 的 ID 由 Shuffle 实例生成,无法预先硬编码。**未配置 workflow_id 的动作会自动降级到 MockExecutor** (只打日志+审计,不真实执行)。

启动时后端会显式警告哪些动作走 mock:

```
⚠️ ENABLE_SHUFFLE=true 但以下动作无 workflow_id 配置,将降级 MockExecutor: isolate_host, block_ip, ...
```

也可查 `GET /health` 的 `execution` 字段确认。

## 配置步骤

### 1. 启动 Shuffle

```bash
cd deploy
docker compose up -d shuffle shuffle-db shuffle-redis
# 访问 http://localhost:3001,用 .env 里的 SHUFFLE_DEFAULT_USERNAME/PASSWORD 登录
```

### 2. 导入 Workflow 模板

本目录提供 8 个动作的 Workflow 骨架 (`*.json`)。在 Shuffle UI:

1. Workflows → **Import** → 上传对应 JSON
2. 编辑 Workflow,把占位 App 替换为你的真实执行器:
   - `isolate_host` → 你的 EDR/防火墙 App (如 Wazuh Active Response / 华为防火墙)
   - `block_ip` → 防火墙/WAF App
   - `kill_process` → Wazuh Active Response / osquery
   - `freeze_account` → AD/LDAP App
3. **Save** 后从 URL 或 Workflow 详情复制 workflow ID (UUID 格式)

### 3. 填入配置

**方式 A — 单动作环境变量** (推荐,清晰):

```bash
# deploy/.env
ENABLE_SHUFFLE=true
SHUFFLE_API_KEY=<Shuffle UI → Settings → API key>
SHUFFLE_WORKFLOW_ISOLATE_HOST=3f2a1b4c-5d6e-7f80-9012-3456789abcde
SHUFFLE_WORKFLOW_BLOCK_IP=4a3b2c1d-6e7f-8901-2345-6789abcdef01
SHUFFLE_WORKFLOW_KILL_PROCESS=...
```

**方式 B — JSON 批量**:

```bash
SHUFFLE_WORKFLOW_MAP={"isolate_host":"3f2a1b4c-...","block_ip":"4a3b2c1d-..."}
```

单动作环境变量优先于 JSON。

### 4. 验证

```bash
docker compose restart secsight-backend
curl -s localhost:8000/health | jq .execution
# 期望: {"mode":"shuffle","configured_actions":["isolate_host","block_ip"],"mock_actions":[...]}
```

注入告警后查 Case 的 `execution_log`,真实执行会有 Shuffle 的 `task_id`,降级 mock 会带 `fallback_reason`。

## Workflow 契约

SecSight 调用:

```
POST {SHUFFLE_BASE_URL}/api/v1/workflows/{workflow_id}/execute
Authorization: Bearer {SHUFFLE_API_KEY}
Content-Type: application/json

{
  "execution_argument": "{\"action_type\":\"isolate_host\",\"target\":{\"ip\":\"10.0.1.15\",\"hostname\":\"web-prod-01\"},\"action_id\":\"...\",\"playbook_id\":\"pb_cryptominer_v1\",\"case_id\":\"...\"}"
}
```

Workflow 内用 Shuffle 的 `$exec` 变量解析 `execution_argument`,取 `target` 里的字段传给下游 App。

期望响应含 `execution_id`,SecSight 记为 `task_id` 写入 `execution_log`。

## 动作与 target 字段对照

| action_type | target 字段 | 典型执行器 |
|---|---|---|
| `isolate_host` | `hostname`, `ip` | Wazuh Active Response / EDR / 交换机 ACL |
| `block_ip` | `ip`, `direction` | 防火墙 / WAF / CrowdSec |
| `block_domain` | `domain` | DNS RPZ / 上网行为管理 |
| `kill_process` | `hostname`, `pid`, `process_name` | Wazuh AR / osquery |
| `quarantine_file` | `hostname`, `path`, `hash` | EDR / 杀软 |
| `freeze_account` | `username`, `domain` | AD / LDAP / IAM |
| `notify` | `channel`, `message` | 飞书 / 钉钉 / 邮件 |
| `service_restart` | `hostname`, `service` | Ansible / systemd |

target 具体内容由剧本 YAML 的 `containment_actions[].parameters` 决定,见 `playbooks/`。

## 回滚

高危动作 (`isolate_host` / `block_ip` / `freeze_account`) 建议在 Shuffle 里配对创建回滚 Workflow,剧本 YAML 用 `rollback` 字段引用:

```yaml
containment_actions:
  - id: isolate_host
    rollback: unisolate_host   # 对应 SHUFFLE_WORKFLOW_UNISOLATE_HOST
```

## 不配 Shuffle 怎么办

保持 `ENABLE_SHUFFLE=false`。所有动作走 MockExecutor,完整走完审批+审计+Evidence Pack 闭环,只是不真实下发。适合:

- 演示 / POC
- 剧本逻辑验证
- 测试环境
