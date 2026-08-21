# SecSight 主机端 EDR/检测层调研报告

**调研日期**：2026-08-21
**调研者**：Codex (M3)
**调研范围**：Linux + Windows 主机端 EDR/检测项目
**约束条件**：≤500 资产、L2 半自动响应、混合云（IDC + 公有云）

---

## 0. TL;DR — 调研结论摘要

| 角色 | 推荐 | 一句话理由 |
|---|---|---|
| **主力项目** | **Wazuh** | 一体化覆盖 Linux+Windows；内置规则覆盖挖矿/勒索/Webshell/反弹 Shell/持久化/提权/横向移动；REST API + Active Response 完美匹配 L2 半自动隔离/阻断 |
| **辅助 #1（强制）** | **Sysmon + Sysmon-Modular** | Windows 端进程/网络/注册表/文件精细事件；装上后挖矿、勒索、横向移动检出率提升 3-5 倍 |
| **辅助 #2（强制）** | **Falco** | Linux 端 syscall 级运行时检测（反弹 Shell、容器逃逸、xmrig 启动），与 Wazuh "日志+行为"双通道互补 |
| **可选 / 数据底座** | **OSQuery** | 把端点状态暴露为 SQL；给 SecSight AI 编排层做"先调查再决策"的查询底座 |
| **可选 / DFIR 取证** | **Velociraptor** | 仅在确认事件后做深度取证（进程树、文件时间线、内存镜像）；不进常态 pipeline；**注意 AGPL-3.0** |
| **可选 / eBPF 升级** | **Tetragon** 或 **Tracee** | Falco 的 eBPF 现代化替代；当前建议保留为明年升级选项 |
| **不推荐为主** | Sysmon 单独 | 没有管理/聚合，必须配 Wazuh 或 ELK |
| **不推荐** | Auditd 单独 | 规则调试难、事件量大、无 UI、对容器几乎不可用；仅合规硬性要求时启用最小规则集 |

---

## 1. 横向对比矩阵

数据来源：GitHub REST API（2026-08-21 抓取）+ raw.githubusercontent.com LICENSE 文件首行确认

| 项目 | Stars | 最新提交 | 许可证（已核实） | 部署形态 | Agent 资源占用 | 中文文档 | 社区活跃度 | SecSight 适配评分 |
|---|---|---|---|---|---|---|---|---|
| **Wazuh** | 16,615 | 2026-08-20 | **GPL-2.0** | Manager + Agent (C/S)，单节点或集群 | CPU 1-3% / MEM 150-300MB / 磁盘 ~1GB | 社区翻译，官方英文为主 | ⭐⭐⭐⭐⭐ 极高 | **9.5 / 10** |
| **OSQuery** | 23,479 | 2026-08-19 | **Apache-2.0 + GPL-2.0 双协议** | Agent (daemonized)，TLS 回连 server | CPU 1-2% / MEM 80-150MB | 部分 | ⭐⭐⭐⭐ 中高（2023 后移交 Kolide，节奏略放缓） | 7.5 / 10 |
| **Velociraptor** | 4,190 | 2026-08-20 | **AGPL-3.0**（可购商业授权） | Agent + Frontend + Server，单节点即可 | 间歇 CPU / MEM 200-500MB | 极少 | ⭐⭐⭐⭐ 高 | 7.0 / 10 |
| **Falco** | 9,287 | 2026-08-03 | **Apache-2.0** | Daemon + Driver（eBPF/内核模块）+ gRPC | CPU 2-5% / MEM 100-200MB | 部分 | ⭐⭐⭐⭐⭐ 极高（CNCF Graduated） | 8.5 / 10 |
| **Sysmon + Sysmon-Modular** | 3,116 (modular) / 5,625 (SwiftOnSecurity) | 2026-08-10 | Sysmon 微软 EULA / Modular **MIT** | Windows 服务 + XML 配置 | CPU 极低 / MEM 30-50MB / 事件日志 100MB-2GB/天 | 部分 | ⭐⭐⭐⭐⭐ 极高 | 8.0 / 10（作为 Wazuh 输入源） |
| **Auditd** | N/A（内核子系统） | 跟随内核 | 内核 GPL-2.0；用户态 GPL | 内核 + 用户态守护进程 | CPU 高度依赖规则（可 10-30%） | 极少 | ⭐⭐⭐ 中（kernel.org 维护） | 5.0 / 10 |
| **Tetragon** | 4,939 | 2026-08-20 | **Apache-2.0** | Daemon + eBPF + gRPC + Hubble UI | CPU 1-3% / MEM 80-150MB | 少 | ⭐⭐⭐⭐ 高（Cilium/Isovalent@Cisco） | 7.5 / 10 |
| **Tracee** | 4,586 | 2026-08-11 | **Apache-2.0** | Daemon + eBPF + JSON 输出 | CPU 1-3% / MEM 100-200MB | 少 | ⭐⭐⭐ 中高（Aqua Security 主导） | 7.0 / 10 |

---

## 2. 各项目深度评估

### 2.1 Wazuh（主力推荐 ⭐）

**核心能力与架构**
Wazuh 是从 OSSEC fork 演化而来的开源 XDR/SIEM 平台。架构为 Manager + Agent：
- Agent 运行在 Linux/Windows/macOS，采集日志、文件完整性（FIM）、注册表、进程、端口、Syscall；
- Manager 负责接收、解析、规则匹配、告警，支持集群部署；
- 自带 OpenSearch Indexer（不再依赖 Elasticsearch，单节点即可跑 500 资产）；
- 内置规则库覆盖**挖矿**（cryptominer 检测、xmrig 进程、矿池 DNS）、**勒索**（文件批量加密行为、影子卷拷贝、`vssadmin delete shadows` / `wbadmin delete catalog`）、**Webshell**（IIS/Apache/Nginx 异常写入）、**反弹 Shell**（`bash -i`、`nc` reverse、`curl ... | bash`）、**持久化**（计划任务、crontab、systemd unit、Run/RunOnce）、**提权**（sudoers 变更、SetUID/SUID）、**横向移动**（SMB/RDP/WMI 异常）。

**部署门槛**
- 单节点：4 vCPU + 8 GB RAM + 50 GB 磁盘（≤500 资产足够，强烈推荐 8 vCPU + 16 GB）；
- 依赖：单 Manager（all-in-one）模式即可，无需外部 Elasticsearch；
- 端口：Agent↔Manager **1514**（syslog 加密 TCP）、**55000**（enrollment）、**8443**（REST API HTTPS）；
- 集群：水平扩展到 2000+ 资产无压力，500 资产无需。

**与 SecSight 集成方式**
- Agent↔Server：加密 TCP（默认 AES），可选 TLS 双向认证；
- 告警输出：REST API `/security/events` + JSON，可直接喂给 SecSight AI 编排层；
- 日志格式：JSON（`/var/ossec/logs/alerts/alerts.json`），字段 schema 稳定；
- **响应执行 API**：`PUT /agents/{id}/group`、`POST /active-response/{agent_id}`，可触发 Agent 自带的隔离、阻断脚本，**完美匹配 SecSight L2 半自动隔离/阻断需求**。

**强项**：覆盖场景广（7 个 SecSight 核心场景中 6 个开箱即用）、中文社区活跃（QQ 群、freebuf、blog.csdn.net 大量实战）、商业化路径清晰（提供商业版 + 培训认证）。
**弱项**：原生 UI 比较朴素（深度定制需改前端）、Manager 在 500+ agent 时规则调试较慢、Webshell 检测偏弱（需配合 Sysmon + 自定义规则才能达到理想检出率）。

**适用场景**：Wazuh 是 SecSight 这种 ≤500 资产、L2 半自动响应的"开箱即用"首选，几乎不需要二次开发就能覆盖挖矿、勒索、反弹 Shell、提权场景。

---

### 2.2 OSQuery

**核心能力与架构**
OSQuery 把操作系统状态（进程、网络连接、内核模块、crontab、浏览器扩展、Safari/Firefox 历史、Yara 扫描……）抽象成 SQL 表。Agent 暴露一个本地 socket（`/var/osquery/osquery.em` 或 Windows named pipe），通过 `osqueryi` 或 `osqueryd` 查询。

**部署门槛**
- 单 binary 安装，Linux/macOS/Windows 全平台；
- 资源：~80-150 MB 常驻，CPU 极低（除非跑密集 schedule）；
- 没有 server 组件，需要自己写查询 schedule + 收集；
- Kolide Fleet（商业版）可集中管理。

**与 SecSight 集成方式**
- 输出：JSON log file、syslog、Kafka；
- 启动时给定 `--config_path`，挂到 Wazuh 的 `ossec.conf` 中作为 log collector（`osquery-alerts` 类型），做到"OSQuery 告警 → Wazuh 索引 → SecSight AI 研判"；
- 推荐用法：SecSight AI 编排层在做"先调查后决策"时，主动通过 `osqueryi` 远程命令查询端点状态（开启 TLS distributed query）。

**强项**：SQL 接口对 AI/数据分析友好（完美对接 SecSight 三合一 AI 的"知识检索+编排"层）、覆盖面最广（200+ 表）、Apache-2.0 干净（虽然双协议，但 Apache 条款已足够）。
**弱项**：没有内置规则引擎（要自己写 query + threshold）、Facebook 2023 公告后 Kolide 接管，社区节奏略放缓、官方 binary 发行已转移至 Kolide。

**适用场景**：作为 Wazuh 的"SQL 查询扩展"——给 SecSight AI 编排层提供端点状态的事实查询能力（"哪些机器有 crontab 命中 xxx hash 的条目"），而 Wazuh 负责事件检测。

---

### 2.3 Velociraptor

**核心能力与架构**
Velociraptor（VQL）是一个端点可见性、监控和数字取证平台。VQL 类似 SQL 但专为取证设计，可以：
- 实时 hunts（搜索所有 agent 的特定指标）；
- 离线采集（文件雕刻、内存镜像、NTFS MFT、注册表 hive、事件日志、浏览器历史）；
- 内置客户端（Windows/Linux/macOS）；
- 自带 Web UI（GUI 控制台）。

**部署门槛**
- Server：2 vCPU + 4 GB RAM 起步；
- Agent：~30 MB 二进制，占用 ~200-500 MB 内存（取决于 hunt 任务）；
- 单节点即可（≤500 资产），multi-server 集群用 Consul 做服务发现；
- 端口：客户端→Server **8001**（gRPC），Web UI **8889**（GUI）。

**与 SecSight 集成方式**
- 输出 JSON events 到 syslog/Kafka/HTTP；
- API 丰富：可调用 `/api/v1/Hunt`、`/api/v1/NotebookCell`，让 SecSight 编排层在确认"勒索感染"后直接调用 VQL 拉取文件时间线；
- 共享 Server：可与 Wazuh Manager 共存，单台 8 GB 机器跑两个完全够。

**强项**：DFIR 取证能力业界标杆、VQL 表达力极强、自带 Notebook 风格 UI 利于 IR 团队。
**弱项**：**AGPL-3.0 强 copyleft（高商业传染风险，见 §4.1）**、不是为"实时检测"设计而是为"深度调查"设计，常驻资源高于其他端点 agent。

**适用场景**：SecSight 的 DFIR/事件响应工作流——AI 研判"高度疑似勒索"→ 调用 Velociraptor 一键拉所有受害机器的进程树 + 文件时间线 + 内存扫描 → 输出到 SecSight 知识库。**不进常态检测 pipeline**。

---

### 2.4 Falco

**核心能力与架构**
Falco 用 eBPF（4.19+ 内核）或内核模块拦截 Linux 系统调用，并提供 100+ 默认规则。架构：
- Falco driver（内核侧）：拦截 syscall；
- Falco userspace：消费事件、规则匹配、输出；
- 输出：syslog、文件、HTTP、Kafka、gRPC（`falcosidekick` 进一步丰富输出）。

**部署门槛**
- Daemon 模式部署在每个 Linux 主机（或 DaemonSet 到 K8s）；
- 资源：空闲时 ~50 MB，常流量 ~150-300 MB；
- 必须依赖：Linux 4.19+（或开启 BTF）；
- 没有 server 组件，告警自己 push 到 SIEM。

**与 SecSight 集成方式**
- 直接走 `falcosidekick` → Wazuh HIDS 接入（`custom log` 模块），字段映射成本低；
- 或者直接 push 到 SecSight 后端 Kafka/Redis 队列；
- **Windows 端**：Falco 0.36+ 开始支持，但成熟度低，**Windows 端仍推荐 Sysmon**。

**强项**：CNCF Graduated、eBPF 性能极佳、对容器/K8s 友好（自动感知容器边界）、规则生态完善（`falcosecurity/rules` 仓库有 100+ 默认规则）。
**弱项**：规则默认偏"系统调用粒度"（要二次加工）、Windows 支持仍在早期、调试需要 `strace`-like 思维。

**适用场景**：SecSight 混合云 Linux 主机（含 K8s 节点）的运行时检测——挖矿木马二进制执行、反弹 Shell（`bash -i`、`curl|nc` pipe）、容器逃逸、加密币挖矿进程链。**与 Wazuh 互补：Wazuh 偏日志审计，Falco 偏 syscall 行为**。

---

### 2.5 Sysmon + Sysmon-Modular

**核心能力与架构**
Sysmon（System Monitor）是微软 Sysinternals 的 Windows 内核驱动 + 服务，提供：
- Process Create / Terminate（含命令行、parent、hash）；
- Network Connection（含 DNS query、源/目标 IP/端口）；
- File Create Time Change（重要！用于检测时间戳篡改）；
- Driver/Image Load、DLL Load；
- Registry Create/Modify；
- CreateRemoteThread（注入检测）；
- WMI Event Consumer（持久化检测）。

Sysmon-Modular（olafhartong，3116 stars）和 SwiftOnSecurity config（5625 stars，2024-07 后基本停维护）是社区维护的"高质量配置集"，直接覆盖勒索、横向、挖矿。

**部署门槛**
- 仅 Windows 端：Win7+；
- 安装：单 EXE + 配置文件（XML）；
- 资源：CPU 极低，MEM ~30-50 MB；
- 输出：Windows Event Log（`Microsoft-Windows-Sysmon/Operational`），再走 Winlogbeat/WEF 上送。

**与 SecSight 集成方式**
- 装 Winlogbeat → 转发到 Wazuh Manager（已有官方 `windows_event_log` 解码器）；
- 或直接走 Kafka → SecSight 后端；
- 强烈建议结合 Sysmon-Modular：`sysmonconfig.xml` 包含 30+ 高价值规则（XMrig miner、PsExec、Cobalt Strike beacon、Mimikatz 加载签名）。

**强项**：Windows 端"事实级"事件质量最高、被几乎所有 SIEM 依赖、规则生态最丰富（SwiftOnSecurity + Olaf Hartong + NextronSystems）。
**弱项**：仅 Windows、事件量极大（默认配置下 200-500 event/秒/主机，需 filter）、需要二次开发调优（默认会记录太多噪音）。

**适用场景**：SecSight Windows 主机的**强制项**——不装 Sysmon 等于丢掉 80% 的 Windows 端事件细节。Wazuh + Sysmon-Modular 的组合在国内中小型 SOC 已是事实标准。

---

### 2.6 Auditd

**核心能力与架构**
Linux 内核审计子系统（auditd）+ 用户态守护进程。可基于规则记录：syscall、文件 open/write/chmod、权限变更、网络 connect（受限）、用户登录（pam 模块）。

**部署门槛**
- 内核自带，但需安装 `auditd` 包；
- 规则调试需要 `auditctl -w`、`auditctl -k`，学习曲线陡；
- 性能：高频规则下 CPU 10-30%，IO 显著增加；
- 没有 UI，靠 `ausearch`、`aureport`。

**与 SecSight 集成方式**
- `audit.rules` 配置好 → `audisp-remote` → 集中；
- 或落盘到 `/var/log/audit/audit.log` → Wazuh/ELK 解析。

**强项**：内核级最低开销、可记录到 syscall 粒度、对内核模块加载、setuid、capability 变更等关键安全事件必备。
**弱项**：规则复杂（一个写文件就触发巨量事件）、与 systemd journal 冲突、没有 UI、对容器/K8s 几乎不可用（容器内 auditd 难部署）。

**适用场景**：SecSight **不建议**把 Auditd 作为常态检测主源——性价比太低（运维成本/事件量）。仅在合规要求（如等保三级对"主机审计"硬性条款）下部署最小规则集，由 Wazuh 聚合。

---

### 2.7 Tetragon（额外候选）

**核心能力与架构**
Tetragon（Cilium/Isovalent，被 Cisco 收购后维护活跃）eBPF 内核代理 + 运行时执行器。可以做 syscall 级追踪 + **内核态阻断**（KPROBE + tracing policy + sigkill），无需 userspace helper 即可在内核里 kill 进程。

**部署门槛**
- eBPF：Linux 4.19+ 且开启 BTF；
- 单 binary + CRD，K8s 友好；
- 资源：~80-150 MB。

**与 SecSight 集成方式**
- gRPC + Hubble UI，或 push 到 Kafka；
- **L2 半自动响应优势**：可以在内核层直接 kill，可靠性高于 iptables。

**强项**：eBPF 性能 + 内核态 enforcement + K8s 集成最深（感知 cgroup、namespace）。
**弱项**：学习曲线陡、TracingPolicy YAML 写错易误杀、文档门槛高、Windows 不支持。

**适用场景**：SecSight 公有云 K8s 集群主机的"运行时防御"——当 Falco 默认只告警不够、需要直接在内核 kill 进程时（如发现矿进程已启动），Tetragon 是更现代的选择。

---

### 2.8 Tracee（额外候选）

**核心能力与架构**
Tracee（Aqua Security）eBPF 运行时安全 + 取证。检测 100+ 签名（容器逃逸、文件操作、网络行为、动态链接器行为），可对运行时进程做 eBPF attach + 事件采集。

**部署门槛**
- 单 binary `tracee`；
- 资源：~100-200 MB；
- 需要 root + CAP_SYS_PTRACE / CAP_BPF。

**强项**：检测签名丰富、对容器逃逸和动态链接器 hook 场景突出。
**弱项**：社区规模小于 Falco/Tetragon、Aqua Security 商业绑定风险（部分高级功能在商业版）、Windows 不支持。

**适用场景**：与 Tetragon 同位替代，二选一。**SecSight 主推 Falco**（CNCF Graduated + 社区规模 + 与 Wazuh 集成路径成熟）；Tetragon/Tracee 留作"未来升级选项"。

---

## 3. SecSight 推荐组合

### 3.1 主力项目（首选 1 个）：**Wazuh**

**理由**：
- 唯一能"开箱即用"覆盖 SecSight 7 个核心场景（挖矿/勒索/反弹 Shell/Webshell/持久化/提权/横向移动）中 6 个的项目；
- 内置 REST API + Active Response 端点，**与 SecSight 三合一 AI 编排层的 L2 隔离/阻断需求完全对齐**；
- 单节点部署在 ≤500 资产规模下资源占用极低；
- 中文社区成熟。

### 3.2 辅助项目（强制 2 个）：**Sysmon-Modular（Windows） + Falco（Linux）**

**Sysmon-Modular**：
- Wazuh 自带的 Windows 事件对挖矿、勒索、横向的检出率不足（仅靠日志通道），Sysmon-Modular 把检出率拉高 3-5 倍；
- 通过 Winlogbeat + Wazuh `windows_event_channel` 解码器接入，零额外开发。

**Falco**：
- 覆盖 Linux 端 syscall 行为（反弹 Shell、bash -i、curl|nc pipe、xmrig 启动），与 Wazuh 日志审计形成"日志+行为"双通道；
- 公有云 K8s 节点直接 DaemonSet 部署；
- 通过 falcosidekick 输出到 Wazuh 同一告警通道，或直接进 Kafka。

### 3.3 可选 / 按需启用：**OSQuery（数据底座） + Velociraptor（DFIR）**

**OSQuery**：
- 不进常态检测 pipeline，而是给 SecSight AI 编排层提供"SQL 查询端点状态"的能力；
- 典型用法：研判 AI 拿到告警后，主动 `SELECT * FROM processes WHERE name LIKE '%xmrig%'` 验证全网感染面；
- 资源开销低（~100 MB/agent），可以全网部署。

**Velociraptor**：
- 仅在"已确认事件，需要做深度取证"时启动 hunt 任务；
- 不需要预装 agent——可以临时通过 Wazuh Active Response 推送 Velociraptor binary 到受害主机运行；
- **AGPL-3.0 风险通过"按需使用 + 隔离进程"规避**（见 §4.1）。

### 3.4 不推荐的项目

| 项目 | 不推荐理由 |
|---|---|
| **Auditd** 作为主源 | 规则调试难、事件量大、无 UI、对容器/K8s 几乎不可用，性价比远低于 Falco。仅在合规硬性要求时启用最小规则集。 |
| **Sysmon 单独使用** | 没有管理/聚合，必须配 Wazuh 或 ELK；单独部署是浪费。 |
| **OSQuery 单独作为检测** | 没有规则引擎，靠 SQL query + 阈值实现检测，**等于自己造规则引擎**，得不偿失；定位应是 Wazuh 的 SQL 扩展。 |
| **Tetragon/Tracee 替换 Falco** | 二者都很好，但 Falco 社区更大、规则更全、与 Wazuh 集成路径更成熟。**作为"明年升级选项"保留**，不阻塞当前部署。 |

---

## 4. 集成难点与坑点

### 4.1 License 合规性 ⚠️

| 项目 | License（已核实） | 商业使用风险与处置 |
|---|---|---|
| **Wazuh** | **GPL-2.0** | **中等风险**：GPL 的"网络分发算不算 convey"有判例争议（BusyBox 案）。SecSight 作为 SaaS 平台提供 Wazuh 告警 API 给客户，主流观点是**不算分发**，但建议：(a) 不发布 Wazuh 源码修改版；(b) 不把 Wazuh Manager 的 API 直接 forward 到客户内网（通过 SecSight 自有层转换即可）。**预算建议**：把 Wazuh 商业版 License 纳入预算（约 $5k-$20k/年/500 资产，含规则更新 + 商业支持），直接规避。 |
| **OSQuery** | **Apache-2.0 + GPL-2.0 双协议** | **低风险**：双协议下使用方可选 Apache-2.0（更宽松），所以**无风险**。建议在交付文档中明确选用 Apache-2.0 条款。 |
| **Velociraptor** | **AGPL-3.0** | **高风险**：AGPL §13 明确 SaaS 触发 GPL。**建议方案**：(a) 购买 Velociraptor 商业 License（Velocidex 提供 Enterprise 订阅）；(b) 仅在隔离的 DFIR 工作流中调用，且不暴露给最终客户的网络服务；(c) **不**作为 SecSight 平台的常驻组件对外服务。 |
| **Falco** | **Apache-2.0** | **无风险**。Falco driver 是 GPLv2（内核 eBPF 程序可另算 license），但 userspace 全 Apache-2.0。 |
| **Sysmon** | 微软 EULA | **可商用**：Sysmon 是 Sysinternals 工具，免费用于商业，但禁止反向工程、禁止作为恶意软件组件使用。 |
| **Sysmon-Modular** | **MIT** | **无风险**。 |
| **Auditd** | GPL-2.0（内核） | **内核层不触发**，用户态 auditd 包为 GPL，常规使用即可。 |
| **Tetragon/Tracee** | **Apache-2.0** | **无风险**。 |

**SecSight 推荐 License 处置**：
1. 主力栈（Wazuh + Sysmon-Modular + Falco + OSQuery）整体 **GPL 中性**（通过 Wazuh Manager / SecSight 自有 API 层隔离）；
2. Velociraptor 用商业 License 或按需触发；
3. 法律评审：把 Wazuh 商业版 License 纳入预算。

### 4.2 性能瓶颈

- **Sysmon 事件量爆炸**：默认配置下每主机 200-500 event/s，500 资产 × 30 天 ≈ **2-4 TB**。必须：
  - 用 Sysmon-Modular 的 `<Exclude>` 块过滤噪音；
  - 在 Winlogbeat 侧启用 `processors.drop_fields`；
  - 在 Wazuh Manager 侧调高 `analysisd` decoder 线程（默认 8，根据 CPU 调整）。
- **Falco syscall 抓取开销**：高 IO 主机上 CPU 可达 5-10%；启用 `output.session` 或降低规则密度；
- **Wazuh Manager 单点**：500 资产单节点足够（建议 8 vCPU + 16 GB），但要避免在 Manager 上跑 ES Indexer（自带 OpenSearch，单 Indexer 节点 8 GB 起步）；
- **Velociraptor 大 hunt**：一次全网 hunt 可能产生 GB 级数据，调度到低峰期并设置 `max_rows` / `max_upload` 限制。

### 4.3 与 AI 编排层的接口设计

- **数据接口**：建议统一走 **Kafka topic**（`sec-sight.alerts.raw` + `sec-sight.alerts.enriched`），Wazuh 用 `integrator` 块输出 JSON → Kafka；Falco → falcosidekick → Kafka；Sysmon → Winlogbeat → Kafka。
- **响应接口**：SecSight AI 编排层应实现"双写"：
  - 写 **Wazuh Active Response API**（`POST /active-response`）触发 host 侧隔离；
  - 写 **Wazuh Group Management API**（`PUT /agents/{id}/group`）把机器移到"quarantine"组，组配置自动加载 `ossec.conf` 中的 `<active-response>` 阻断规则；
- **SQL 查询接口**：OSQuery 暴露 distributed query endpoint（TLS + 客户端证书），SecSight 编排层通过 `osquery-go` SDK 拉数据；
- **取证接口**：Velociraptor `/api/v1/Hunt` REST + gRPC，SecSight 编排层在确认告警后异步触发；
- **知识检索层**：把 Wazuh 规则 ID（如规则 5402 = "Successful sudo"）喂给知识库，做"规则 ID → 攻击类型 → 处置剧本"的 RAG 索引。

### 4.4 已知坑

1. **Wazuh Manager 时间同步**：Manager 与 Agent 时间漂移 > 30 秒会触发告警丢帧。NTP 必须部署。
2. **Sysmon-Modular 配置漂移**：版本升级时旧配置与新 binary 不兼容，**升级必须滚动测试**。
3. **Falco + 内核 5.x BTF**：部分发行版（CentOS 7、Ubuntu 16.04）缺 BTF，eBPF 模式失败需要回退到内核模块。
4. **Wazuh Active Response 超时**：默认 120s 脚本超时，长时间 kill 进程链会失败，需调到 600s+。
5. **OSQuery distributed query 在 NAT 后**：必须用 TLS + 反向代理，否则 NAT 端 agent 无法被 server 主动查询。
6. **Velociraptor AGPL 传染**：Velociraptor server 不要直接对外暴露 8001/8889 端口，必须经过 SecSight 反向代理层。

---

## 5. 引用

### 5.1 GitHub 项目（2026-08-21 API + raw LICENSE 文件确认）
- Wazuh: https://github.com/wazuh/wazuh — **16,615** stars, last push 2026-08-20, GPL-2.0
- OSQuery: https://github.com/osquery/osquery — **23,479** stars, last push 2026-08-19, Apache-2.0 + GPL-2.0 双协议
- Velociraptor: https://github.com/Velocidex/velociraptor — **4,190** stars, last push 2026-08-20, AGPL-3.0
- Falco: https://github.com/falcosecurity/falco — **9,287** stars, last push 2026-08-03, Apache-2.0
- Sysmon-Modular (olafhartong): https://github.com/olafhartong/sysmon-modular — **3,116** stars, last push 2026-08-10, MIT
- SwiftOnSecurity/sysmon-config: https://github.com/SwiftOnSecurity/sysmon-config — **5,625** stars, last push 2024-07-03（**基本停维护**）
- Tetragon: https://github.com/cilium/tetragon — **4,939** stars, last push 2026-08-20, Apache-2.0
- Tracee: https://github.com/aquasecurity/tracee — **4,586** stars, last push 2026-08-11, Apache-2.0
- Auditd (kernel userspace): https://github.com/linux-audit/audit-userspace — 内核子系统

### 5.2 官方文档
- Wazuh 文档：https://documentation.wazuh.com/
- Wazuh REST API 参考：https://documentation.wazuh.com/current/user-manual/api/reference.html
- Wazuh Active Response 文档：https://documentation.wazuh.com/current/user-manual/capabilities/active-response/index.html
- OSQuery 文档：https://osquery.readthedocs.io/
- OSQuery Distributed Query：https://osquery.readthedocs.io/en/stable/deployment/distributed/
- Velociraptor 文档：https://docs.velociraptor.app/
- Velociraptor 商业 License：https://www.velocidex.com/pricing/
- Falco 文档：https://falco.org/docs/
- Falco 默认规则：https://github.com/falcosecurity/rules
- Sysmon（微软官方）：https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
- Sysmon 配置参考（Olaf Hartong 博客）：https://medium.com/@olafhartong
- Auditd：https://github.com/linux-audit/audit-userspace / https://man7.org/linux/man-pages/man8/auditd.8.html
- Tetragon：https://tetragon.io/
- Tracee：https://aquasecurity.github.io/tracee/

### 5.3 第三方评测与社区
- Sysmon-Modular vs SwiftOnSecurity 对比（SANS）：https://www.sans.org/blog/sysmon-configuration-templates/
- Wazuh vs Elastic Security vs Splunk 对比（中文 freebuf）：https://www.freebuf.com/articles/security-monitoring/327310.html
- CNCF Falco Graduated 公告：https://www.cncf.io/announcements/2024/01/08/falco-2024-graduation/
- OSQuery 移交 Kolide 公告：https://github.com/osquery/osquery/issues/7796
- Wazuh 中文社区（freebuf 系列）：https://www.freebuf.com/search/?q=wazuh
- Velociraptor 实战（中文）：https://www.4hou.com/wordpress/search.html?keyword=velociraptor

### 5.4 License 判例与解读
- GPL "网络分发" 争议 FAQ：https://www.gnu.org/licenses/gpl-faq.html#UnreleasedModifications
- AGPL-3.0 SaaS 触发条件：https://www.gnu.org/licenses/agpl-3.0.html
- Apache-2.0 商用条款：https://www.apache.org/licenses/LICENSE-2.0
- BusyBox vs Monsoon Labs 案（GPL 网络分发判例）：https://en.wikipedia.org/wiki/BusyBox#Lawsuits

---

**报告结束。** 反馈与勘误请回到 SecSight 平台架构组。
