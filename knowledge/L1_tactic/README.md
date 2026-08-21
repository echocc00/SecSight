# L1 战术层 — 按业务系统分类

7 大类 (对应 02-design §5.2):
- `host/` — 主机/端点 IoC/检测思路/应急要点
- `network/` — 网络 IoC/检测/应急
- `application/` — 应用 IoC/检测/应急
- `data/` — 数据 IoC/检测/应急
- `cloud/` — 云 IoC/检测/应急
- `identity/` — 身份 IoC/检测/应急
- `email/` — 邮件 IoC/检测/应急

每类包含 3 类知识: typical_iocs / detection_thinking / response_essentials

示例见 host/tactic_host.yaml
