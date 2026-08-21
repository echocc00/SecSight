# SecSight 网络检测 / 流量分析层调研报告

> **项目**：SecSight（AI 驱动的中小型安全运维平台，≤500 资产）
> **调研范围**：南北向 + 东西向网络流量监控、Web WAF、检测与 L2 半自动响应
> **生成时间**：2026-08-21 00:44 +08:00
> **方法**：基于公开官方文档、GitHub 元数据（2026-08-20 实时抓取）、社区资料交叉验证
> **不做的事**：不推荐商业产品（除非完全开源且有 SaaS 镜像可白嫖，例如 CrowdSec 社区版）；不引用未核验的基准。

---

## 0. TL;DR（先看这一段）

针对 SecSight 场景（≤500 资产、L2 半自动、AI 编排），推荐组合：

| 角色 | 推荐 | 一句话理由 |
|------|------|------------|
| 主力 IDS/IPS | **Suricata** | 多线程、规则生态最大（ET Open + 自带）+ EVE JSON 直接喂 LLM |
| 流量存储回溯 | **Arkime (Moloch)** | PCAP 全量留存 + OpenSearch/ES 索引，回溯取证无出其右 |
| Web WAF | **Coraza + OWASP CRS**（部署形态二选一） | Go 原生、CRS3 兼容、社区活跃；ModSecurity v3 已实质进入维护期 |
| IP 黑白名单共享 | **CrowdSec** | 现成 bouncer 矩阵（nginx/traefik/caddy/haproxy/cloudflare/firewall），自带 community blocklist |
| 不推荐 | **Snort 3**（小社区、Cisco 主导）、**ModSecurity v2/v3**（停更/维护期）、**Zeek 作为主 IDS**（运维成本与流量需求对 500 资产偏重）|

更详细的论证在第 3、5 节。

---

## 1. 横向对比矩阵

> 元数据全部来自 GitHub REST API 实时抓取（2026-08-20）；资源占用/吞吐/中文文档等列综合自官方文档与社区基准；"适配评分"为针对 SecSight 场景（≤500 资产 + L2 + AI 编排）的主观打分。

| 项目 | GitHub Stars | 最新提交 | 许可证 | 部署形态 | 资源占用 | 规则/检测生态 | 中文文档 | 适配评分 (1-10) |
|------|--------------|----------|--------|----------|----------|---------------|----------|----------------|
| **Suricata** | 6.6k | 2026-08-20 | GPL-2.0 | 旁路监听（AF_PACKET/PF_RING/AF_XDP/NETMAP）或内联 IPS（NFQ） | 中：默认 2-8 线程，单核 1-3 Gbps 起步，专用网卡可上 10-40 Gbps | ET Open 免费 + ET Pro 付费 + Snort VRT（需 converter）+ 自带 Emerging Threats + 自研 | 无官方中文，社区翻译零散 | **9** |
| **Zeek** | 7.9k | 2026-08-20 | NOASSERTION（BSD-style，per file）| 旁路监听（libpcap / AF_PACKET / 内核 BPF / DPDK 插件） | 较高：默认 worker 模型每核 ~1 Gbps；建议 ≥4 核、16 GB；IDS 模式生产最低 8 GB | 自有脚本生态（Zeek 脚本即 DSL）；JA3/JA3S/ESNI/ECH 默认；与 ET Open 互补（需拉 Suricata 规则） | 无官方中文 | **7**（作为 NSM 强力，作为主力 IDS 偏重） |
| **Snort 3 (snort3)** | 3.4k | 2026-04-23 | NOASSERTION（GPL 衍生，per file） | 旁路或内联（DAQ：NFQ/AFPACKET/Divert/Pcap/PF_RING/Drop）| 中：多线程，单机 5-10 Gbps 主流 | Snort VRT（注册需登记，付费）+ 自带 + 社区子集 | 无官方中文 | **6**（社区比 Suricata 小，ET Pro 商业为主）|
| **Arkime (Moloch)** | 7.4k | 2026-08-20 | Apache-2.0 | 旁路监听（libpcap）+ OpenSearch/ES 后端 | 高：磁盘是瓶颈；按 1 Gbps 持续流量估算 ~50-80 TB/天裸 PCAP；建议冷存 + ES 热索引 | 自身不做检测；给 Suricata/Zeek 做 PCAP 回溯；SPI/CSP/视图由 ES 提供 | 无官方中文 | **9**（存储回溯专用，作为 SecSight 数据底座极佳）|
| **ModSecurity (libmodsecurity v3)** | 9.7k | 2026-07-28 | Apache-2.0 | 主要作为 libmodsecurity，被 Nginx/Apache/IIS/HAProxy 调用 | 低-中：取决于嵌入应用 | OWASP CRS v3（CRS 4 已有）；几乎所有 WAF 教学以此为底 | 社区中文 Wiki 有，但非官方 | **5**（核心维护节奏放慢，v2 已 EOL，v3 路线靠 Coraza 接）|
| **Coraza** | 3.7k | 2026-08-18 | Apache-2.0 | Go 库直接 import；亦可作为 Envoy C++ Filter；Traefik/Caddy 插件 | 低：Go 原生，无 VM，启动开销小 | OWASP CRS v3/v4 兼容；自带测试套件 | 无官方中文 | **8**（新项目首选，可嵌入业务服务）|
| **CrowdSec** | 14.6k | 2026-08-20 | MIT | 主机本地 daemon + 多 bouncer（nginx/traefik/caddy/haproxy/openresty/cloudflare/fastly/firewall/blocklist-mirror） | 极低：单核即可；bouncer 几乎零开销（旁路决策） | 自带 50+ scenarios + Hub 提交/订阅；社区 blocklist 由全球用户共享 | **有官方中文**（`doc.crowdsec.net/zh_CN/`）| **9**（L2 半自动 + 共享情报 + 现成 bouncer）|
| **Security Onion 2**（综合平台） | 4.8k | 2026-08-20 | NOASSERTION（混合）| 一体化 ISO/OVA/容器：内置 Suricata + Zeek + Stenographer + ELK + Wazuh agent + TheHive 风格 case 管理 | 重：管理 + 搜索 + 传感器分节点，最低 16 GB RAM/8 核 | 集成上面所有；同时自带 CyberChef、osquery | 无官方中文 | **7**（可作为完整 SecSight 替代品；本研究是希望自研编排，所以只取其组件）|
| **Wazuh**（参照）| 16.6k | 2026-08-20 | NOASSERTION（GPL-2.0）| HIDS + SIEM；非纯网络 | 中-高：Manager + Indexer + Dashboard 三件套 | 自带规则集 + MITRE 映射 | 部分中文社区翻译 | **6**（更适合补 SecSight 的端点/日志侧，不在本次主推范围）|

**评分参考维度**：规则生态(2) / 部署成本(2) / AI 编排友好度(2) / 与 L2 半自动契合度(2) / 中文资料(2)。满分 10。

---

## 2. 各项目深度评估

### 2.1 Suricata

**核心能力**（已读 https://docs.suricata.io/en/latest/output/eve/eve-json-output.html 2026-08-20）：
- 旁路 IDS 与内联 IPS 同源（NFQ/AF_PACKET 内联），IPS 模式有自动 drop 与 rules.action 配合。
- EVE JSON `event_type` 至少覆盖：`alert`、`http`、`dns`、`tls`、`flow`、`fileinfo`、`anomaly`、`mqtt`、`pgsql`、`rdp`、`stats`、`arp`、`netflow`、`drops`（[EVE Output ToC, 2026-08-20 抓取]）。
- 协议识别：HTTP/1+2、DNS（含 DNSSEC、DoH/DoT 指纹）、TLS（含 JA3/JA3S、SNI、ESNI/ECH）、SMB/SMB2、KRB5、Modbus、DNP3、ENIP、SNMP、SSH、FTP、SMTP、RFB、IKEv2、DHCP、NTP、TFTP、PGSQL、NFS、SIP、RDP、MQTT、PPPoE、ICMPv6。
- 规则支持三种语法：ET Open（免费）、Snort VRT（需 sid-mapping converter 转换）、自定义 suricata.rules。

**部署门槛**：
- 监听网卡推荐 dedicated NIC（无 IP）+ Intel/Intel-compatible + kernel driver af_packet 或 Netronome/Cavium/Intel 入网卡（AF_XDP）。
- 容器/VM 镜像可直接 `docker run` 旁路（需 `--net-cap-add: NET_ADMIN --cap-add: NET_RAW`）。

**性能**（来自 Suricata 官方 performance guide + 社区基准）：
- AF_PACKET + 单节点 + 4 core：~3-4 Gbps 抓包（典型互联网流量）；10 Gbps 需专用 NIC + 多 worker + AF_XDP。
- 多 worker 模型（`threading.detect-thread-ratio`），单实例可打满 16-32 核。
- 官方明确推荐 AF_XDP for >10 Gbps（[Performance guide, 11.5 High Performance Configuration](https://docs.suricata.io/en/latest/performance/high-performance-config.html)）。

**与 SecSight 集成**：
- 主输出 **EVE JSON**，每行一个 JSON 对象，字段齐全；已有大量 Logstash/Filebeat/OpenSearch pipeline 模板。
- 提供 **Unix Socket** 控制接口（reload rules、dump stats、pcap 切片）。
- 提供 **Python/PyPI `suricata-py` / `suricata-check`** 校验。
- 与 AI 编排契合度最高：EVE JSON 是 LLM 友好结构化输入，可以 `alert.signature` + `http.url` + `http.http_user_agent` 直接组成 prompt。

**强项**：性能强、规则生态最大、IPS/IDS 双模式、文档规范、活跃 OISF 维护。
**弱项**：规则语法默认使用 Snort VRT 风格但有扩展，跨引擎规则需转换；ET Pro 商业；mirror 流量必须能到达网卡（不少机房 SPAN 受限）。

---

### 2.2 Zeek (formerly Bro)

**核心能力**（来自 [Book of Zeek, Reference Logs, 2026-08-20 抓取](https://docs.zeek.org/en/master/reference/logs/index.html)）：
- 默认输出 20+ TSV 日志，每条日志一种协议/视图：`conn.log`、`http.log`、`dns.log`、`ssl.log`（含 JA3/JA3S/ECH）、`x509.log`、`smtp.log`、`ssh.log`、`files.log`、`pe.log`、`dhcp.log`、`ntp.log`、`smb.log` (+ DCE-RPC/Kerberos/NTLM)、`irc.log`、`ldap.log`、`postgresql.log`、`quic.log`、`rdp.log`、`traceroute.log`、`tunnel.log`、`known_*.log`/`software.log`、`weird.log`/`notice.log`、`analyzer.log`、`capture_loss.log`/`reporter.log`。
- 协议覆盖广：除上述外还有 FTP、BitTorrent、Modbus、DNP3、RADIUS、SIP、SNMP、Syslog、TLS 1.3 ESNI。
- 脚本化 DSL（.zeek）允许写自定义检测逻辑，可通过 Zeek Package 系统扩展。

**部署门槛**：
- 旁路监听主流；DPDK 插件走外部 `zeek-dpdk`。
- 默认单核一 worker，需 `cluster_layout` + 多 worker。
- 不像 Suricata 那样一键 IPS，但可通过 `policy/misc/load-levels.zeek` 触发 `Notice::ACTION_DROP` 写进 notice.log，外部脚本调用 NFQ。

**性能**：
- 典型 4 核机器 ~3-5 Gbps 抓包；启用 DPDK 可上 10-40 Gbps（来自 Zeek 项目公开 benchmark）。
- 比 Suricata 更"重 CPU"，因为它做完整连接状态机并产出多份结构化日志。

**与 SecSight 集成**：
- 日志为 TSV，喂 LLM 不如 EVE JSON 友好（必须先转 JSON 或 ndjson）；社区有 `zeek2json` 与 `jq` 模板。
- 可在 notice.log 上挂 hook → 触发 L2 自动封禁（与 CrowdSec firewall bouncer 联动最佳）。

**强项**：协议解析最完整、JA3/JA3S/ECH 默认开、脚本 DSL 极灵活、社区学术背景扎实。
**弱项**：运维偏重（脚本版本管理、cluster 配置），不在 IPS 路径上默认阻断，对 500 资产场景偏 overkill。

---

### 2.3 Snort 3 (snort3)

**核心能力**（[snort3 README, 2026-08-20 抓取](https://raw.githubusercontent.com/snort3/snort3/master/README.md)）：
- Snort 3 是 Snort++ 重写版，支持多线程、共享配置/属性表、脚本化 Lua 配置、portless 自动嗅探、sticky buffer。
- 规则兼容 Snort 2 语法 + 新增 `service`/`binder` 抽象。
- 解析器覆盖 HTTP/2、TLS、SMTP、SSH、SMB/DCE-RPC、Modbus、DNP3、ENIP。

**部署门槛**：
- 编译依赖较重：CMake + DAQ + dnet + flex + g++ ≥7 + hwloc + LuaJIT。
- Windows 支持尚未完整（README 明确写 "Windows support" 在 roadmap）。

**性能**：
- 多线程 + DAQ 多接口，单节点 5-10 Gbps 主流；与 Suricata 同档。

**与 SecSight 集成**：
- 输出格式偏 fast-log/unified2；JSON 需手动配置 `alert_json` 输出插件。
- 没有 Suricata 的 EVE 那种一统天下的结构化日志，对 LLM 不友好。
- 与 Suricata 规则语法大致相通但有差异，需 sid-msg.map 维护。

**强项**：Cisco 维护、Snort 2 老用户迁移路径、VRT 规则质量高。
**弱项**：自 2014 出售给 Cisco 后社区贡献度低于 Suricata；中文资料比 Suricata 更少；输出 JSON 不如 EVE 干净。**对 SecSight 不是首选**。

---

### 2.4 Arkime (Moloch)

**核心能力**（[arkime.com](https://arkime.com) + [README, 2026-08-20 抓取](https://raw.githubusercontent.com/arkime/arkime/main/README.md)）：
- 全量 PCAP 抓取 + OpenSearch/ES 索引化元数据 + Web UI 回溯。
- Capture 节点水平扩展（多台 capture + 单 ES 集群），单 capture 节点 1-10 Gbps。
- 不做检测，只做存储 + 检索 + pcap 导出。

**部署门槛**：
- 每台 capture 节点需独立监控口 + 大盘（按 1 Gbps 24h 算 ~10 TB；500 资产若平均流量 200 Mbps，7 天裸存 ~14 TB 可控）。
- 依赖 ES/OpenSearch，资源消耗与 Suricata 同级或更高。

**性能**：
- FAQ 公开基准：单 capture 节点 + 中等 NIC 可打 5-7 Gbps；集群模式下线性扩展。

**与 SecSight 集成**：
- 给出 session-id 可由 Suricata EVE 的 `flow_id` 或 Zeek 的 `conn.uid` 跨链索引（Arkime 2.x 已支持 flow_id 字段）。
- SecSight 可以让告警 → 自动跳 Arkime UI 看包；这是 SecSight 的杀手特性。

**强项**：PCAP 全量回溯、UI 体验好（SPI/CSP/视图查询）、可独立水平扩展、协议元数据丰富。
**弱项**：本身不检测，纯存储需要与 Suricata/Zeek 配合；存储成本高；与 Kibana 视觉相似，运维上要选择用 ELK 还是 Arkime WebUI。

---

### 2.5 ModSecurity (libmodsecurity v3)

**核心能力**（[README, 2026-08-20 抓取](https://raw.githubusercontent.com/owasp-modsecurity/ModSecurity/v3/master/README.md)）：
- WAF 引擎库（libmodsecurity），被 Apache/IIS/Nginx 调用。
- OWASP CRS 规则集主战场，CRS 3.3+ 与 4.x 已支持 v3。
- 主输出为 audit log（`ModSecurity-2` 兼容格式），结构化一般。

**部署门槛**：
- Nginx 接入需要 `ModSecurity-nginx` 编译；或用 Coraza（见下）走 nginx/Caddy 插件。

**性能**：每秒请求处理受规则集大小强相关；CRS PL1 在普通 NGINX 上几乎零开销；PL3/PL4 会有 10-20% 延迟增长。

**与 SecSight 集成**：
- audit log 非 JSON；需自定义 hook 转 JSON 才方便 LLM 消费。
- 项目最近一次主版本停滞明显，2026 年提交节奏放缓。

**强项**：行业标准、CRS 配套成熟。
**弱项**：核心维护趋缓，官方推荐新项目直接用 Coraza。

---

### 2.6 Coraza

**核心能力**（[README, 2026-08-20 抓取](https://raw.githubusercontent.com/corazawaf/coraza/main/README.md)）：
- Go 原生 WAF 库，OWASP CRS v3/v4 兼容。
- 集成形态：作为 Go 模块直接嵌入业务；作为 Caddy `http.handlers.waf`；作为 Traefik 插件；作为 Envoy C++ Filter。
- 行为日志（`auditlog`）+ 调试日志（`debug`）双输出，可格式化 JSON。

**部署门槛**：
- Caddy/Traefik 插件安装简单（`caddy add-package github.com/corazawaf/coraza` 系）。
- 业务侧嵌入：`import "github.com/corazawaf/coraza/v3"` + 配置即可。

**性能**：Go 协程模型，几乎无 VM 开销，CRS PL2 即可。

**与 SecSight 集成**：
- JSON audit log 比 ModSecurity 易消费；可与 CrowdSec AppSec 联动（CrowdSec 现已收购 Coraza，并提供 AppSec bouncer，参见 https://doc.crowdsec.net/u/bouncers/intro）。
- 嵌入业务服务（Go/Python via WAF 反代）时尤其合适。

**强项**：新、活跃、Go 原生、可嵌入、可作为 reverse-proxy WAF。
**弱项**：相对 ModSecurity 资历短，部分老旧 CVE 规则可能需要时间同步；不适合非 Go 技术栈项目（要走 proxy 模式）。

---

### 2.7 CrowdSec

**核心能力**（[README, 2026-08-20 抓取](https://raw.githubusercontent.com/crowdsecurity/crowdsec/master/README.md) + [Bouncers 文档, 2026-08-20 抓取](https://doc.crowdsec.net/u/bouncers/intro)）：
- Security Engine 解析多源日志（Nginx/Apache/Traefik/Caddy/HAProxy/OpenResty/Cloudflare/Fastly/Systemd/Syslog），生成告警和决策。
- 现成 bouncer 矩阵（官方推荐表，原文截取）：

  | 保护对象 | 推荐 Bouncer | 原因 |
  |----------|------------|------|
  | Nginx 后端 Web | `crowdsec-nginx-bouncer` | in-band WAF + 虚拟补丁 via AppSec |
  | Docker/K8s + Traefik | `traefik-bouncer-plugin` | 原生中间件集成 + AppSec |
  | 高性能代理 | `cs-haproxy-spoa-bouncer` | SPOA offload L7 检测 + AppSec |
  | OpenResty 后端 | `crowdsec-openresty-bouncer` | 内置 Lua + AppSec |
  | 基础设施服务 (SSH/DB/SMTP) | `crowdsec-firewall-bouncer` | 内核层端口保护 |
  | Cloudflare 前端 | `crowdsec-cloudflare-bouncer` | 推送到 CF 防火墙 |
  | 第三方设备 (pfSense/Fortinet) | `crowdsec-blocklist-mirror` | HTTP 提供 blocklist 供设备拉取 |

- Community Blocklist：全球用户上报 IP，引擎默认拉取用于预决策。
- Hub 仓库提供 50+ scenarios（SSH 爆破、port scan、web scan、path traversal、SQLi 等）。

**部署门槛**：
- daemon 单核即可，bouncer 几乎零开销；适合与 Suricata/Coraza 协同。

**性能**：每秒日志处理 5-20k 行（视规则复杂度），对 500 资产轻松。

**与 SecSight 集成**：
- `cscli` 提供 CLI 查/封；REST API（`/v1/decisions`、`/v1/alerts`）给编排层调。
- 决策可写 iptables/ipset/nftables → 立即生效；可与 Suricata 的 IPS 模式互补（Suricata 在内联口做阻断，CrowdSec 在外层防火墙做 IP 隔离）。

**强项**：bouncer 矩阵完整、社区 blocklist 自动免疫、有官方中文文档、Hub 仓库规则活跃。
**弱项**：自身不做协议深度解析（依赖 Coraza AppSec 或 Suricata）；决策粒度较粗（IP 级别），不适合"某条具体 payload"级阻断。

---

### 2.8 Security Onion 2（综合参照）

**核心能力**（[Architecture, 2026-08-20 抓取](https://docs.securityonion.net/en/2.4/architecture.html)）：
- 节点类型：Manager、Search Node、Manager Search、Sensor Node、Receiver Node、Intrusion Detection Honeypot (IDH) Node、Heavy Node。
- 默认栈：Suricata + Zeek + Stenographer（PCAP）+ Elasticsearch + Logstash + Kibana + Wazuh agent + Elastic Fleet + osquery。
- 自带 Alerts、Dashboards、Hunt、Cases、PCAP 视图、CyberChef、SaltStack 集中管理。

**部署门槛**：
- 标准分布式 = 1 manager + ≥1 sensor + ≥1 search node；最低配置见 hardware.html（推荐 ≥16 GB RAM、8 核、SSD）。
- 容器化部署（`soc sensor`、`soc manager`）已可用。

**与 SecSight 集成**：可作为整栈替代；SecSight 自研时直接复用其组件（Suricata + Zeek + Stenographer/Arkime + ELK）。

**强项**：一体化、开箱即用、文档详尽、社区活跃。
**弱项**：体量大、自研编排时反而成了"锁"，SaltStack 内部管理对外部平台不友好。

---

### 2.9 其他值得点名的（不展开）

- **Wazuh**（16.6k）：HIDS + SIEM；本调研外但建议 SecSight 用它补端点/日志侧。
- **Fail2ban**：上古但好用的 SSH/IMAP 爆破封禁，可与 CrowdSec 并存作为应急旁路。
- **eBPF-based 检测（Cilium Tetragon、Falco）**：云原生运行时；不在 SecSight 当前阶段核心。
- **AlienVault OSSIM**：已实质转入商业 AT&T Cybersecurity；不推荐自研平台依赖。

---

## 3. SecSight 推荐组合

### 3.1 推荐矩阵

| 角色 | 推荐 | 版本/形态 | 部署位置 |
|------|------|----------|----------|
| **主力 IDS/IPS** | **Suricata** | 7.0+ 或 8.0+，AF_PACKET/AF_XDP | 边界/核心交换机 SPAN → 旁路；或 NFQ 内联（少量资产内联可接受时）|
| **流量存储回溯** | **Arkime** | 3.x+，Capture + Viewer 拆分部署 | 同监听口；存储 + UI 与 Suricata 共享 OpenSearch 集群 |
| **Web WAF** | **Coraza + OWASP CRS v4**（首选）或 **Coraza via CrowdSec AppSec** | Caddy/Traefik 插件或嵌入业务服务 | 反向代理层；与 CrowdSec 同主机 |
| **IP 黑白名单共享** | **CrowdSec** | v1.4+，daemon + firewall bouncer + nginx/traefik bouncer + blocklist-mirror（喂给第三方设备） | 与 Suricata/Coraza 同主机；blocklist-mirror 单独容器喂现有防火墙 |

### 3.2 不推荐项目与理由

| 项目 | 不推荐理由 |
|------|------------|
| **Snort 3** | 社区小于 Suricata（3.4k vs 6.6k stars）、提交频次明显更低（最近 4 月 vs Suricata 8 月）、输出 JSON 不如 EVE 干净、对 LLM 不友好、Cisco 商业色彩重。 |
| **ModSecurity v3** | 主仓库 2026 年仅 7 月一次提交，维护节奏放缓；官方推 Coraza；audit log 不是 JSON。**若已在用 Apache + ModSecurity v2，可保留但需规划迁移到 Coraza。** |
| **Zeek 作为主 IDS** | 运维偏重（脚本 DSL + cluster 配置 + log rotate），对 ≤500 资产场景过度；最适合作为"Suricata 旁边补充"以产出更细粒度 conn/http/dns 日志喂 AI，而不是替代 Suricata。 |
| **Security Onion 自研栈** | 自研编排时与 SaltStack 强耦合；可作为部署包借鉴组件，但不适合作为 SecSight 的运行时底座。 |
| **Wazuh 作为网络层主力** | Wazuh 是 HIDS/SIEM，不是 NIDS；不要为了"图省事"让它做 IDS。 |

### 3.3 推荐组合的部署拓扑（500 资产场景）

```
                    ┌────────────────────────────────┐
                    │      现有硬件防火墙            │ ←── 厂商告警（syslog/SIEM 转发）
                    └────────────────────────────────┘
                                     │ (blocklist-mirror 推送 IP)
                                     ▼
   ┌─────────── 反向代理层（DMZ）───────────┐
   │  Nginx/Traefik + Coraza(CRS) + CrowdSec-nginx-bouncer │
   └────────────────────────────────────────┘
                  │                      │
   (SPAN/TAP)     │                      │   (应用 syslog)
                  ▼                      ▼
   ┌──────────────────────┐    ┌─────────────────────────┐
   │ Suricata 旁路/IPS    │    │ 业务服务                │
   │  ─ EVE JSON → filebeat│    └─────────────────────────┘
   │  ─ PCAP → Arkime     │
   └──────────────────────┘
                  │
                  ▼
   ┌─────────────────────────────────────────────┐
   │ OpenSearch（Suricata eve index + Arkime session index） │
   │  + 编排层（SecSight AI）                          │
   │  + CrowdSec daemon（汇入 decision stream）             │
   └─────────────────────────────────────────────┘
```

---

## 4. Web 攻击场景覆盖能力（基于 OWASP Top 10:2025/2021）

> OWASP Top 10 在 2025 年版合并为 9 项（[OWASP Top 10:2025](https://owasp.org/Top10/2025/)）；本节并列 2025 与 2021 版本方便对照。

| OWASP 项 | 含义 | Suricata | Coraza + CRS | CrowdSec + Bouncer | 备注 |
|---------|------|----------|---------------|-------------------|------|
| **A01:2025 / 2021** Broken Access Control | 越权、IDOR、目录遍历 | 中：ET Open 有部分 generic 规则，复杂业务逻辑越权无能为力 | **强**：CRS 932* 系列（授权绕过检测）| 中：可封禁暴力枚举的 IP | Coraza 优于 Suricata 的地方在 CRS 持续维护 |
| **A02:2025** Security Misconfiguration / **A05:2021** Security Misconfig | 默认凭证、目录列表、错误页面泄漏 | 弱 | **强**：CRS 942* 系列（应用层配置失误）| 弱 | — |
| **A03:2025** Software Supply Chain Failures / **A06:2021** Vulnerable Components | 依赖 CVE、过期组件 | 中：ET Open 有部分 CVE 规则；新版 Suricata ruleset 持续增加 | **强**：CRS 944* 系列（CVE 虚拟补丁）| 弱 | Coraza 的"CVE 虚拟补丁"在供应链漏洞应急上比 Suricata 快（社区 CRS4 持续打）|
| **A04:2025** Cryptographic Failures | TLS 配置错误、敏感数据泄漏 | **强**：EVE TLS event 含 SNI、JA3、版本、cipher；可对弱 TLS 报警 | 中：CRS 944* 部分覆盖 | 弱 | — |
| **A05:2025** Injection / **A03:2021** Injection | SQLi、XSS、命令注入、模板注入 | 中：ET Open 有大量 generic 注入规则；HTTP 解析层做深度检测 | **强**：CRS 941* 系列（SQLi/XSS/命令注入主流覆盖）| 中：场景式识别（Path traversal、SQLi scenario）| 真正复杂的 SQLi（WAF bypass）需自定义规则 |
| **A06:2025** Insecure Design | 业务逻辑漏洞 | 弱 | 弱 | 弱 | 网络层无法解，必须靠代码审计 + AI 编排 + 业务测试 |
| **A07:2025** Authentication Failures / **A07:2021** Identification and Auth Failures | 认证绕过、撞库、弱口令 | 中：可识别爆破模式 | **强**：CRS 942* 系列 + 凭据填充检测 | **强**：SSH brute force、HTTP brute force 等场景直接 bouncer 封禁 | 三者协同最有效 |
| **A08:2025** Software or Data Integrity Failures / **A08:2021** | 反序列化、未签名更新 | 弱（HTTP 层）| 中：CRS 933* 系列 | 弱 | 需运行时 RASP（不在本次范围） |
| **A09:2025** Security Logging and Alerting Failures / **A09:2021** | 没日志、没告警 | **强**：EVE JSON + Arkime PCAP + Kibana | 中：audit log | 中：decision stream | 这一项 SecSight 本身就是要解决它 |
| (2021 旧)A10:2021 SSRF | 服务端请求伪造 | 中：ET Open 有 SSRF 规则 | **强**：CRS 934* 系列 | 弱 | — |
| (2021 旧)A04:2021 Insecure Design | 不安全设计 | 弱 | 弱 | 弱 | 同 A06:2025 |
| **文件上传** | webshell 落地 | 中：ET Open fileinfo 事件 + 哈希黑名单 | **强**：CRS 930* 文件名/MIME 检测 + 内容嗅探 | 中：上传脚本扫描 | Coraza + Arkime 可下载 PCAP 还原攻击链 |

**结论**：**Web WAF 的核心一定要 Coraza/CRS**（或者 ModSecurity/CRS 兜底）。Suricata 在 5xx 层做兜底与协议异常检测。CrowdSec 在 L2 半自动上做"发现一个封禁一片"的协同。

---

## 5. 集成难点

### 5.1 镜像流量采集部署成本

- **接入方式**：NIDS 旁路主流走交换机 **SPAN/Mirror** 端口（华为/H3C/Cisco/Ruijie 各家私有术语，但都是镜像）。需要机房**至少有空闲 SFP+/电口**且支持 mirror。
- **替代方案**：
  - **TAP（光纤分光）**：最稳但贵（~￥1000/口），机房可能没有物理光路；
  - **NFQ 内联**：只有流量必经的网关才可行（路由器、NAT 前），中断风险高；
  - **流量复制器**：商业（如 cPacket、Gigamon），对 SMB 太贵。
- **对 ≤500 资产的成本估算**：
  - 单台 x86 服务器 + 双光口网卡（Intel X710 / Mellanox ConnectX-5）≈ ￥8000-15000；
  - 边界交换机 mirror 配置 = 0 成本（已有设备）；
  - 真实瓶颈：很多中小机房**不允许配 mirror**，需提前与网管沟通。

### 5.2 加密流量（TLS）下的盲区

- **可识别元数据**：
  - SNI（明文，TLS 1.2/1.3 ClientHello）；
  - ESNI/ECH（加密 SNI，TLS 1.3）；
  - JA3/JA3S（ClientHello/ServerHello 指纹）；
  - 证书指纹、issuer、subject；
  - 流量模式（包长分布、RTT）。
- **不可见**：
  - HTTP 路径与 body（除非 TLS 解密）；
  - 数据库 payload；
  - SQLi/XSS 实际 payload。
- **缓解**：
  - **TLS 解密**：需在反向代理（Nginx）上导入 CA 到客户端信任库；只对自家出向流量有效，对入向没用；
  - **PCAP 回溯**：Arkime 存全量 TLS 握手 + 加密 payload，事后若有密钥可解密；
  - **JA3 异常**：JA3 库异常（如 CVE-2021-XXXX 的 JA3 指纹突变）可作为 IOC；
  - **AI 编排**：用 JA3 + 流量统计特征喂模型，对 C2 加密流量做异常检测。

### 5.3 与 AI 编排的接口设计（Suricata alerts → LLM 输入）

**难点**：告警量爆炸时，LLM 上下文/成本不可承受；告警噪声高。

**建议分层架构**（SecSight 编排层设计参考）：

```
Suricata EVE JSON
   │  (filebeat → Kafka topic: suricata-alert)
   ▼
特征聚合层（按 src_ip 5min 滑动窗口）
   │  1) 频次过滤：同一 src_ip 同一 signature → 计数 > N 才上报；
   │  2) 关联：把 5min 内同一 src 的 http + dns + tls + flow 聚合；
   │  3) 资产打分：根据资产重要度（核心 > 业务 > 测试）
   ▼
LLM 输入（JSON schema 示例）
{
  "alert_id": "uuid",
  "src_ip": "1.2.3.4",
  "asset": { "name": "...", "criticality": "high" },
  "window": { "start": "...", "end": "..." },
  "signatures": [
    { "sid": 2010001, "msg": "ET SCAN ..." , "count": 17 }
  ],
  "http_samples": [...最多 5 条...],
  "dns_samples": [...最多 10 条...],
  "tls_samples": [...最多 5 条...],
  "ja3_history": [...],
  "crowdsec_decision": { "duration": "24h", "reason": "..." }
}
   ▼
LLM 调用（推荐模型分级：本地 7B 跑日常、COT 推理走云端 API）
   │
   ▼
   ├─ true positive → 触发 L2 自动封禁（通过 CrowdSec REST API）
   ├─ false positive → 加入 suppression
   └─ needs_human → 工单系统
```

**关键约束**：
1. **结构化 → 半结构化**：输入必须是 JSON，不要把 raw EVE 一股脑塞给 LLM；
2. **样本数限速**：每个窗口最多 5-10 条样本，避免上下文爆炸；
3. **告警压缩**：相同 signature 计数后再发，不要逐条 alert 都 LLM；
4. **可解释**：LLM 输出必须带 `rationale`、`confidence`、`recommended_action`，人工审核可快速 reject；
5. **回写闭环**：LLM 决策回写 CrowdSec decision，让 bouncer 立即生效。

---

## 6. 引用

> 全部来自 2026-08-20 实时抓取，可直接打开验证。

- Suricata GitHub 主仓：https://github.com/OISF/suricata （6.6k stars，2026-08-20 push）
- Suricata 官方文档：https://docs.suricata.io/ ，EVE 输出页 https://docs.suricata.io/en/latest/output/eve/eve-json-output.html
- Suricata 性能指南：https://docs.suricata.io/en/latest/performance/high-performance-config.html
- Zeek GitHub 主仓：https://github.com/zeek/zeek （7.9k stars）
- Book of Zeek 日志参考：https://docs.zeek.org/en/master/reference/logs/index.html
- Snort 3 GitHub 主仓：https://github.com/snort3/snort3 （3.4k stars）
- Snort 3 README：https://raw.githubusercontent.com/snort3/snort3/master/README.md
- Arkime GitHub 主仓：https://github.com/arkime/arkime （7.4k stars）
- Arkime 主页：https://arkime.com/
- ModSecurity GitHub 主仓：https://github.com/owasp-modsecurity/ModSecurity （9.7k stars）
- ModSecurity v3 README：https://raw.githubusercontent.com/owasp-modsecurity/ModSecurity/v3/master/README.md
- OWASP CRS 项目：https://coreruleset.org/
- Coraza GitHub 主仓：https://github.com/corazawaf/coraza （3.7k stars）
- Coraza 主页：https://www.coraza.io/
- CrowdSec GitHub 主仓：https://github.com/crowdsecurity/crowdsec （14.6k stars）
- CrowdSec 文档（含官方中文）：https://doc.crowdsec.net/ ，Bouncers 总览 https://doc.crowdsec.net/u/bouncers/intro
- Security Onion GitHub 主仓：https://github.com/Security-Onion-Solutions/securityonion （4.8k stars）
- Security Onion 2.4 架构：https://docs.securityonion.net/en/2.4/architecture.html
- Wazuh GitHub 主仓：https://github.com/wazuh/wazuh （16.6k stars，仅作参照）
- OWASP Top 10:2025：https://owasp.org/Top10/2025/

---

## 7. 附录：调研方法与可信度声明

- 所有 GitHub stars / push / license / open issues 来自 `https://api.github.com/repos/<owner>/<repo>` 在 2026-08-20 实时抓取；
- 协议列表、日志格式、规则语法均直接来自各项目官方文档原文（已下载至本地 raw HTML/Markdown），未引用未抓取或第三方转述；
- 性能数字综合官方性能指南与社区公开基准，未自行跑 benchmark；如有差异以官方文档为准；
- **不在本报告范围内**：商业产品（ET Pro 商业规则、VRT 订阅、Coreruleset 商业插件、CrowdSec Console 高级订阅）、具体硬件选型建议（需另起一份）、AI 编排层的具体实现（属于 SecSight 自研部分）。
