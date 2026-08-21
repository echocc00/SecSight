# MCP 工具 server

每个外部系统封装为独立 MCP server,LangGraph Tool 调用。

## Phase1 计划实现

- `wazuh_mcp/` — Wazuh API 封装 (查询告警 / active response / agent 管理)
- `suricata_mcp/` — Suricata EVE 查询 / 规则 reload
- `opencti_mcp/` — OpenCTI GraphQL (IoC / TTP / ThreatActor 关系图)
- `threat_intel_mcp/` — ThreatIntelProvider 统一入口 (免费源 + 预留付费)
- `firewall_mcp/` — 防火墙 API (block_ip / isolate_host)
- `shuffle_mcp/` — Shuffle Workflow 触发 (REST,不 import Shuffle 代码)
- `iris_mcp/` — DFIR-IRIS 案件/证据/时间线 (REST)

## License 隔离约束

MCP server 通过 HTTP 调用外部服务,不 import AGPL/GPL 代码。
Shuffle / Wazuh / KubeHound 的 MCP server 仅封装 REST 调用。
