# 

我来帮你做这个 AI 安全运维工具的调研和设计规划。先从多个维度并行调研成熟开源项目，再给出整体架构设计。

第一批调研有了关键发现，继续补充 SIEM、AI Agent 框架和挖矿检测方向。

继续补充威胁情报、DFIR 取证、网络流量分析和安全大模型方向的调研。

调研已覆盖六大维度，再深入几个关键 AI\-SOC 项目的架构细节，然后整合输出。

调研完成，覆盖了 6 大技术维度、30 \+ 开源项目。以下是完整的调研总结与架构设计规划。

---

# AI 驱动安全运维工具 — 开源调研与架构设计规划

## 一、成熟开源项目调研总结

### 1\.1 AI\-SOC / SOAR 自动化平台（核心对标）

|项目|定位|核心特点|成熟度|许可证|
|---|---|---|---|---|
|**Vigil SOC**|开源 AI SOC 平台|13 个专业 Agent 协同，基于 MCP 协议 \+ Bifrost LLM 网关，7200 \+ 检测规则，置信度阈值 \(0\.90\) 自动响应，Apache 2\.0，本地优先|★★★★☆ 活跃|Apache 2\.0|
|**CyberNest SOAR**|AI 增强 SOAR|双层 AI 管道 \(XGBoost/LightGBM \+ LLM\)，集成 Wazuh/Suricata/Zeek/Arkime/Velociraptor 全栈，动态风险评分 \(CVSS\+EPSS\+SSVC\)|★★★☆☆ 开发中|非商业免费|
|**Shuffle**|开源 SOAR 编排|no\-code 可视化工作流，MITRE 映射，200 \+ 集成，社区最成熟，Docker 一键部署|★★★★★ 成熟|开源|
|**Tracecat**|新一代 SOAR|无代码工作流设计，案件管理一体化，Python 可扩展|★★★★☆ 活跃|开源|
|**DeepSOC**|国产多 Agent SOC|指挥官 / 经理 / 操作员 / 执行器 / 专家五层 Agent，SOAR 编排集成|★★★☆☆ 开发中|开源|
|**SynapCores SOAR**|自主 SOC 平台|Tier\-1 分诊 Agent，不可变审计，MCP 检测门户，单 Docker 主机自托管|★★★☆☆ 新|开源|
|**SecOS**|多 Agent 安全 OS|NDR/IAM/UEBA/SOAR/AEGIS \(LLM 分诊 P1\-P4\) 五 Agent 协同|★★★☆☆ 新|开源|

**关键洞察**：Vigil SOC 的架构理念最接近你的需求 —— 多专业 Agent \+ MCP 工具协议 \+ 置信度阈值自动响应 \+ 可审计工作流。建议作为核心参考架构。

### 1\.2 入侵检测 / EDR / 异常检测

|项目|层面|核心能力|适用场景|
|---|---|---|---|
|**Wazuh**|主机 \(HIDS\)\+XDR|日志分析、FIM、入侵检测、漏洞扫描、恶意软件检测、合规检查、Active Response|主力端点监控，跨 Windows/Linux/macOS|
|**Falco**|运行时 \(eBPF\)|内核级系统调用监控，容器 / 云原生运行时安全，零侵入|K8s / 容器环境、异常进程行为检测|
|**Osquery**|主机查询|SQL 化主机状态查询，按需取证，轻量 Agent|按需深度取证、合规检查|
|**Velociraptor**|DFIR 取证|企业级端点监控 \+ 数字取证 \+ 应急响应，VQL 查询语言，覆盖攻击全生命周期|深度应急响应、证据采集|
|**poolnarc**|eBPF 挖矿检测|专门检测加密挖矿行为的 eBPF 程序|挖矿病毒专项检测|

### 1\.3 SIEM / 日志分析 / 告警关联

|项目|特点|选型建议|
|---|---|---|
|**OpenSearch \+ Security Analytics**|开源 fork Elasticsearch，内置 Sigma 规则库、MITRE ATT\&CK 映射、威胁检测探测器|**首选**，与 Wazuh 原生集成，无许可证风险|
|**GrayLog**|轻量日志平台，Sigma v2\.0 原生支持，多格式采集|备选，适合中小规模|
|**Sigma 规则体系**|通用检测规则标准 \(YAML\)，3000 \+ 社区规则，可转换为各 SIEM 格式，v2\.0 支持多事件关联|**必选**，作为检测规则层的统一标准|

### 1\.4 网络流量分析 \(NDR\)

|项目|能力|定位|
|---|---|---|
|**Suricata**|IDS/IPS，签名 \+ 行为检测，多线程高性能|实时威胁检测主力|
|**Zeek**|协议元数据提取，行为分析，非签名式|深度流量分析、异常行为基线|
|**Arkime**|全流量 PCAP 捕获 \+ 索引 \+ 搜索，PB 级存储|事后取证、流量回溯|
|**Clear NDR \(原 SELKS\)**|Suricata\+Zeek\+Arkime\+ELK 一体化发行版|快速搭建 NDR 环境|

### 1\.5 威胁情报 / DFIR

|项目|特点|
|---|---|
|**OpenCTI**|基于 STIX 2\.1 的知识图谱，GraphQL API，威胁 Actor/TTP/IOC 关联，与 MISP/TheHive 集成|
|**MISP**|威胁情报共享平台，IOC 管理，REST API，社区生态最广|
|**DFIR\-IRIS**|TheHive 许可证变更后的全开源替代，事件管理 \+ 证据管理 \+ 时间线分析 \+ Python 模块|

### 1\.6 安全专用大模型

|模型|开发者|参数|特点|
|---|---|---|---|
|**Foundation\-Sec\-8B**|Cisco Foundation AI|8B|基于 Llama 3\.1 继续预训练，安全任务性能追平 Llama 3\.1\-70B，可本地部署，宽松许可证|
|**SecGPT V2\.0**|云起无垠 \(国产\)|\-|全球首个网络安全开源大模型，漏洞分析 / 日志溯源 / 攻防推演 / 命令解析，中文优化|
|**Meta SecAlign\-8B/70B**|Meta|8B/70B|内置提示注入防御的安全模型|

### 1\.7 AI Agent 编排框架

|框架|特点|
|---|---|
|**LangGraph**|多 Agent 有向图编排，状态持久化，human\-in\-the\-loop 检查点，故障恢复，生产级|
|**MCP 协议**|模型上下文协议，工具调用开放标准，30 \+ 安全工具已有 MCP Server|
|**DeepMCPAgent**|零代码 MCP 动态工具发现，RBAC 权限管控，全链路审计|

---

## 二、整体架构设计

### 2\.1 设计原则

1. **不重复造轮子**：检测 / 采集 / 存储层全部复用成熟开源组件，自研聚焦在 AI 决策与自动化响应层

2. **本地优先**：大模型可本地化部署，敏感数据不出内网

3. **人机协同**：高置信度自动处置，低置信度人工审核，置信度阈值可配置

4. **全链路可审计**：Agent 每一步推理、每个工具调用、每次处置动作都留痕

5. **场景化 Playbook**：每个安全场景有标准化的 "发现→排查→处置→复盘" 闭环

### 2\.2 六层架构

```Plain Text
┌─────────────────────────────────────────────────────────────┐
│                    展示层 (Presentation)                      │
│   SOC大屏 / 告警看板 / 事件时间线 / ATT&CK热力图 / 审计日志    │
├─────────────────────────────────────────────────────────────┤
│                  AI 决策层 (AI Brain)  ← 核心自研              │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌───────────────┐  │
│  │ 分诊Agent │ │ 调查Agent │ │ 响应Agent │ │ 威胁狩猎Agent  │  │
│  └──────────┘ └──────────┘ └──────────┘ └───────────────┘  │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐                    │
│  │ 情报Agent │ │ 取证Agent │ │ 报告Agent │  ← LangGraph编排  │
│  └──────────┘ └──────────┘ └──────────┘                    │
│         安全大模型(Foundation-Sec-8B / SecGPT) + RAG知识库   │
├─────────────────────────────────────────────────────────────┤
│              编排与响应层 (Orchestration)                     │
│    SOAR Playbook引擎 / MCP工具网关 / 置信度路由 / 审批流      │
├─────────────────────────────────────────────────────────────┤
│              检测与关联层 (Detection)                         │
│    Sigma规则引擎 / 告警关联 / 异常基线 / MITRE ATT&CK映射     │
├─────────────────────────────────────────────────────────────┤
│              数据采集层 (Collection)                          │
│  ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐ ┌──────────┐  │
│  │ Wazuh  │ │ Falco  │ │Suricata│ │ Zeek   │ │Arkime    │  │
│  │ Agent  │ │ eBPF   │ │ IDS/IPS│ │ 元数据 │ │ 全流量   │  │
│  └────────┘ └────────┘ └────────┘ └────────┘ └──────────┘  │
│  安全设备告警接入(WAF/防火墙/EDR/云安全) / 业务日志 / 指标     │
├─────────────────────────────────────────────────────────────┤
│              数据与情报层 (Data & Intel)                      │
│  OpenSearch(日志/告警) / PostgreSQL(事件/审计) / Redis(缓存) │
│  OpenCTI(威胁情报知识图谱) / MISP(IOC) / 向量库(RAG)         │
└─────────────────────────────────────────────────────────────┘
```

---

## 三、核心模块详细设计

### 3\.1 AI 决策层（核心自研模块）

#### 多 Agent 角色设计

|Agent|职责|工具权限|推理模式|
|---|---|---|---|
|**TriageAgent 分诊**|告警评分、去重、降噪、优先级排序 \(P0\-P4\)、误报过滤|只读：SIEM 查询、IOC 查询|快速模式|
|**InvestigatorAgent 调查**|根因分析、攻击链重建、横向影响评估、时间线构建|只读：日志检索、流量查询、端点查询、情报查询|深度模式|
|**ResponderAgent 响应**|生成处置方案、执行遏制动作、置信度评估|读写：防火墙阻断、主机隔离、账号禁用、进程终止 \(需审批\)|阈值路由|
|**ThreatHunterAgent 狩猎**|假设驱动威胁狩猎、ATT\&CK 覆盖度分析、检测盲区发现|只读：全量数据检索、Sigma 规则生成|深度模式|
|**IntelAgent 情报**|IOC 富化、威胁 Actor 画像、TTP 匹配、漏洞关联|只读：OpenCTI/MISP/VirusTotal/Shodan|快速模式|
|**ForensicsAgent 取证**|证据采集、内存分析、持久化检查、样本提取|只读：Velociraptor/Osquery|深度模式|
|**ReporterAgent 报告**|事件报告生成、复盘分析、改进建议、合规报告|只读|快速模式|

#### Agent 编排引擎（基于 LangGraph）

```Plain Text
告警进入 → TriageAgent(评分/去重)
              │
       ┌──────┴──────┐
    误报/低危      中高危
       │              │
    归档记录    InvestigatorAgent(根因分析)
                      │
              IntelAgent(情报富化) ──→ ForensicsAgent(取证)
                      │
              ResponderAgent(处置方案)
                      │
            ┌─────────┴─────────┐
      置信度≥0.90          置信度<0.90
            │                    │
      自动执行处置          人工审批队列
            │                    │
      ReporterAgent(报告) ←──────┘
```

#### 安全大模型部署策略

- **默认方案**：本地化部署 `Foundation-Sec-8B-Instruct`（8\-bit 量化约 8\.5GB 显存，单张 RTX 3090/4090 可跑），用于告警分析、日志解读、处置推理

- **中文场景增强**：`SecGPT V2.0` 用于中文安全报告生成、国内威胁情报理解

- **复杂推理**：通过 Bifrost 类 LLM 网关可切换调用云端模型（DeepSeek/Qwen/GPT），敏感数据脱敏后送出

- **RAG 知识库**：内置应急响应手册、Sigma 规则说明、ATT\&CK 技术详情、历史案例，向量检索增强推理准确性

### 3\.2 检测与关联层

#### 统一检测规则：Sigma

- 采用 Sigma 作为唯一检测规则描述语言，社区 3000 \+ 规则直接复用

- 自研规则转换层：Sigma → OpenSearch Query / Suricata 规则 / Wazuh 规则

- Sigma v2\.0 关联规则支持多事件时序关联（如 "失败登录 N 次后成功登录 \+ 异常进程创建"）

#### 告警关联引擎

- **时序关联**：同一资产 / 同一攻击者 IP 在时间窗口内的多告警聚合为一个事件

- **因果关联**：基于 ATT\&CK 战术链，将初始访问→执行→持久化→横向移动的告警串联

- **资产上下文关联**：结合 CMDB 资产重要性，调整告警优先级（核心服务器告警自动升级）

#### 异常检测基线

- 基于统计的行为基线：登录时间 / 地点、进程白名单、网络连接模式

- AI 辅助异常评分：大模型对偏离基线的行为做语义判断（是正常变更还是异常）

### 3\.3 编排与响应层

#### MCP 工具网关

所有外部工具通过 MCP 协议暴露给 Agent，内置 MCP Server 包括：

|工具类别|MCP Server|能力|
|---|---|---|
|SIEM 查询|OpenSearch MCP|日志检索、告警查询、聚合统计|
|端点操作|Wazuh/Velociraptor MCP|进程查询、文件采集、命令执行 \(沙箱\)|
|网络操作|防火墙 / WAF MCP|IP 阻断、域名封禁、规则下发|
|情报查询|OpenCTI/MISP MCP|IOC 查询、Actor 画像、TTP 检索|
|流量分析|Arkime/Zeek MCP|PCAP 检索、会话查询|
|身份管理|LDAP/AD MCP|账号禁用、密码重置、权限查询|
|通知|飞书 / 钉钉 / 邮件 MCP|告警推送、审批通知|

#### 置信度驱动的自动响应

```Plain Text
响应决策 = f(威胁置信度, 资产重要性, 处置动作风险等级)

处置动作分级：
  L1-信息采集(只读)    → 全自动，无需审批
  L2-通知告警          → 全自动
  L3-网络阻断(IP/域名) → 置信度≥0.85 自动，否则审批
  L4-主机隔离/账号禁用 → 置信度≥0.90 自动，否则审批
  L5-进程终止/文件删除 → 必须人工审批
  L6-系统级操作(重装等) → 必须人工审批 + 双人复核
```

### 3\.4 数据采集层

#### 端点采集

- **Wazuh Agent**：主力，部署在所有服务器，提供日志采集、FIM、rootkit 检测、Active Response

- **Falco**：部署在容器 / K8s 节点，eBPF 运行时异常检测（挖矿的异常系统调用、可疑进程 fork）

- **Velociraptor**：按需部署，应急时深度取证

#### 网络采集

- **Suricata**：核心交换机镜像口，IDS/IPS 实时检测

- **Zeek**：同镜像口，协议元数据提取（DNS 隧道、异常 SSL 证书、C2 信标检测）

- **Arkime**：全流量存储（建议保留 7\-30 天，用于事后回溯）

#### 安全设备告警接入

- 统一 Webhook/Syslog 接入：WAF、防火墙、EDR、云安全中心、邮件网关

- 告警标准化：转换为统一的 ECS \(Elastic Common Schema\) 格式

---

## 四、安全场景覆盖与 Playbook 设计

### 4\.1 场景全景图（按 MITRE ATT\&CK 战术覆盖）

|战术|典型场景|检测方式|自动处置等级|
|---|---|---|---|
|初始访问|暴力破解、Web 漏洞利用、钓鱼|Suricata 规则 \+ WAF 告警 \+ 登录失败关联|L3 自动阻断 IP|
|执行|恶意命令、WebShell、可疑脚本|Wazuh 命令审计 \+ Falco 进程检测|L4/L5 需审批|
|持久化|计划任务、注册表、启动项、SSH 密钥|Wazuh FIM\+Sigma 规则|L4 隔离 \+ 取证|
|权限提升|内核漏洞、sudo 滥用、UAC 绕过|Falco 系统调用 \+ 日志分析|L4 隔离|
|防御规避|日志清除、进程注入、文件 less|Wazuh FIM \+ 行为分析|L4 隔离 \+ 取证|
|凭据访问|密码抓取、哈希传递、票据攻击|Sigma 规则 \+ 域控日志|L4 隔离 \+ 改密|
|横向移动|远程服务、SMB/WMI、RDP|Zeek 流量 \+ 登录日志|L3 阻断 \+ L4 隔离|
|数据窃取|异常外发、DNS 隧道、大容量传输|Zeek 流量基线 \+ DLP|L3 阻断|
|**命令控制**|**C2 信标、反向 Shell、挖矿通信**|**Zeek\+Suricata \+ 流量基线**|**L3 阻断 \+ L4 隔离**|
|影响|**挖矿病毒**、勒索软件、DDoS 僵尸|**CPU 异常 \+ 进程特征 \+ 矿池连接**|**L4 隔离 \+ L5 终止**|

### 4\.2 重点场景：挖矿病毒应急 Playbook（完整闭环）

#### 阶段 1：发现（多维度检测规则）

```yaml
# Sigma规则示例 - 挖矿进程检测
title: Suspicious Cryptominer Process Execution
id: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
status: experimental
description: Detects known cryptominer process names and patterns
logsource:
  category: process_creation
  product: linux
detection:
  selection:
    Image|endswith:
      - '/xmrig'
      - '/minerd'
      - '/kdevtmpfsi'
      - '/kinsing'
      - '/sys-mon'
      - '/dbus-update'
    CommandLine|contains:
      - 'stratum+tcp://'
      - 'stratum+ssl://'
      - '--cpu-max-threads-hint'
      - 'pool.minexmr.com'
      - 'pool.supportxmr.com'
  condition: selection
level: critical
```

**触发条件（任一满足即告警）：**

1. 进程名 / 命令行匹配挖矿特征（xmrig/minerd/kdevtmpfsi/kinsing 等）

2. 出站连接到已知矿池端口（3333/4444/5555/7777/8888/14433）

3. CPU 持续 \> 80% 超过 10 分钟 \+ 非业务进程

4. Falco 检测到异常高 CPU 进程 \+ 隐藏文件行为

5. eBPF \(poolnarc\) 检测到挖矿特定系统调用模式

#### 阶段 2：排查（InvestigatorAgent 自动执行）

Agent 按以下步骤自动调查，每步结果记录到事件时间线：

```Plain Text
Step 1: 进程分析
  - ps aux --sort=-%cpu | head -20  (通过Wazuh/Velociraptor远程执行)
  - 定位高CPU进程PID、路径、命令行参数、父进程
  - 检查进程是否隐藏(对比ps和/proc)

Step 2: 网络分析
  - ss -tnp | grep <PID>  查看矿池连接地址
  - 查询目标IP/域名在OpenCTI/MISP中的情报
  - Arkime回溯该主机近24小时异常连接

Step 3: 持久化检查
  - crontab -l 检查计划任务
  - systemctl list-unit-files 检查异常服务
  - /etc/rc.local、~/.bashrc、/etc/profile.d/ 检查启动项
  - SSH authorized_keys 检查未授权密钥
  - 检查LD_PRELOAD劫持

Step 4: 入侵路径分析
  - 回溯该主机近7天登录日志(成功/失败)
  - 检查Web服务访问日志(是否有漏洞利用)
  - 关联同网段其他主机是否有相同IOC

Step 5: 影响评估
  - 该进程运行时长、CPU消耗、业务影响
  - 是否有数据泄露迹象
  - 是否横向扩散到其他主机
```

#### 阶段 3：处置（ResponderAgent 生成方案，按置信度自动 / 审批执行）

```Plain Text
标准处置流程：
  1. [L3-自动] 防火墙阻断矿池IP/域名 + 阻断异常出站连接
  2. [L4-置信度≥0.9自动] 主机网络隔离(仅保留运维通道)
  3. [L5-需审批] 终止挖矿进程 kill -9 <PID>
  4. [L5-需审批] 删除恶意文件/计划任务/服务
  5. [L5-需审批] 清除持久化项(crontab/service/启动项/SSH密钥)
  6. [取证-自动] Velociraptor采集内存镜像+恶意样本+日志
  7. [修复-需审批] 修补入侵入口漏洞
  8. [验证-自动] 24小时监控确认无复发
```

#### 阶段 4：复盘（ReporterAgent 自动生成）

- 事件时间线（攻击入口→植入→持久化→发现→处置）

- IOC 清单（IP / 域名 / 文件哈希 / 进程名）

- ATT\&CK 技术映射

- 根因分析（哪个漏洞 / 弱口令导致入侵）

- 改进建议（检测规则补充、防护策略加固）

- 自动导出为飞书文档 / PDF 报告

### 4\.3 其他重点场景 Playbook（框架）

**勒索软件**：文件批量加密行为检测 → 立即隔离主机 → 阻断 C2 → 取证 → 评估备份恢复 → 根因分析

**WebShell**：Web 目录 FIM 变更 \+ 异常请求 → 定位 WebShell 文件 → 阻断访问 IP → 清除文件 → 回溯入侵路径 \(漏洞 / 弱口令\) → 修补

**暴力破解**：登录失败频率关联 → 自动阻断源 IP → 检查是否有成功登录 → 成功则升级为入侵事件调查

**横向移动**：异常 SMB/WMI/RDP 连接 → 关联源主机是否已失陷 → 阻断横向连接 → 双主机隔离调查

**数据泄露**：异常大流量外发 \+ 非工作时间 → 阻断连接 → 评估泄露范围 → 溯源

---

## 五、技术选型最终方案

### 5\.1 技术栈总览

|层级|组件|选型|理由|
|---|---|---|---|
|**AI 编排**|Agent 框架|LangGraph|生产级多 Agent 编排，状态持久化，human\-in\-the\-loop|
||工具协议|MCP|开放标准，生态快速增长，30 \+ 安全集成|
||本地大模型|Foundation\-Sec\-8B|Cisco 开源，安全领域专精，可本地部署|
||中文增强|SecGPT V2\.0|国产安全大模型，中文安全场景优化|
||向量库|pgvector / Milvus|RAG 知识库检索|
|**SOAR**|编排引擎|自研 \(基于 LangGraph\) \+ Shuffle 集成|核心场景自研精细控制，通用流程用 Shuffle|
|**检测**|规则标准|Sigma|社区 3000 \+ 规则，事实标准|
||关联引擎|自研 \(基于 OpenSearch 聚合 \+ 时序\)|灵活定制 ATT\&CK 链路关联|
|**SIEM**|存储检索|OpenSearch|开源无风险，Wazuh 原生集成，Security Analytics 插件|
||可视化|OpenSearch Dashboards / Grafana|告警看板 \+ 指标监控|
|**端点**|HIDS/XDR|Wazuh|最成熟开源，全平台覆盖，Active Response|
||运行时|Falco|eBPF 零侵入，容器友好|
||DFIR|Velociraptor|企业级取证，VQL 灵活查询|
|**网络**|IDS/IPS|Suricata|高性能，多线程，规则生态丰富|
||元数据|Zeek|行为分析，协议解析深度|
||全流量|Arkime|PB 级 PCAP 存储检索|
|**情报**|知识图谱|OpenCTI|STIX 2\.1，GraphQL，可视化好|
||IOC 共享|MISP|社区最大，集成最广|
|**案件**|事件管理|DFIR\-IRIS|全开源，TheHive 替代|
|**后端**|API|FastAPI \(Python\)|异步高性能，自动文档|
||消息队列|Redis / Kafka|告警流水线、Agent 任务队列|
||主数据库|PostgreSQL|事件 / 审计 / 配置存储|
|**前端**|UI|React \+ shadcn/ui|参考 Vigil/CyberNest 技术栈|
|**部署**|容器化|Docker Compose \(起步\) → K8s \(规模化\)|参考 CyberNest 的 compose 编排|
||网关|Kong / NGINX|API 网关、统一认证|

### 5\.2 自研 vs 集成策略

|模块|策略|说明|
|---|---|---|
|多 Agent 决策引擎|**自研**|核心竞争力，基于 LangGraph\+MCP 构建|
|场景 Playbook|**自研**|挖矿 / 勒索 / WebShell 等场景精细化控制|
|置信度路由 \+ 审批流|**自研**|安全处置的核心管控逻辑|
|告警关联引擎|**自研**|结合资产上下文 \+ ATT\&CK 链路的定制关联|
|数据采集 / 检测 / 存储|**集成开源**|Wazuh/Suricata/Zeek/OpenSearch，不造轮子|
|通用 SOAR 编排|**集成 Shuffle**|no\-code 流程，非核心场景快速搭建|
|威胁情报|**集成 OpenCTI\+MISP**|成熟方案，直接用|
|案件管理|**集成 DFIR\-IRIS**|成熟方案|

---

## 六、开发路线图

### Phase 0：基础环境搭建（2\-3 周）

* [ ] Docker Compose 编排：OpenSearch \+ Wazuh Manager \+ PostgreSQL \+ Redis

* [ ] 部署 Wazuh Agent 到测试服务器，验证日志采集

* [ ] 部署 Suricata \(测试环境镜像口\)，验证 IDS 告警

* [ ] 部署 OpenCTI，导入基础威胁情报

* [ ] 本地部署 Foundation\-Sec\-8B，验证推理性能

### Phase 1：MVP — 告警分析 \+ 挖矿场景（4\-6 周）

* [ ] 告警接入管道：Wazuh/Suricata 告警 → 标准化 → OpenSearch

* [ ] TriageAgent：告警去重、评分、优先级排序

* [ ] InvestigatorAgent：日志检索、IOC 查询、基础根因分析

* [ ] MCP 工具网关：OpenSearch 查询 \+ OpenCTI 情报查询

* [ ] **挖矿病毒 Playbook**：发现规则 \+ 自动排查 \+ 处置方案生成

* [ ] 基础 Web UI：告警列表 \+ 事件详情 \+ Agent 推理过程展示

* [ ] 飞书 / 钉钉告警推送

**MVP 验收标准**：模拟挖矿病毒入侵，系统能在 5 分钟内发现并自动完成排查，给出处置方案。

### Phase 2：自动响应 \+ 多场景扩展（6\-8 周）

* [ ] ResponderAgent \+ 置信度路由 \+ 审批流

* [ ] MCP 扩展：防火墙阻断、Wazuh Active Response、Velociraptor 取证

* [ ] 新增场景：勒索软件、WebShell、暴力破解、横向移动

* [ ] 部署 Falco，增强运行时检测

* [ ] Sigma 规则库导入 \+ 管理界面

* [ ] 事件时间线自动构建

### Phase 3：威胁狩猎 \+ 情报增强（4\-6 周）

* [ ] ThreatHunterAgent：假设驱动狩猎

* [ ] 部署 Zeek \+ Arkime，流量分析能力

* [ ] ATT\&CK 覆盖度分析仪表盘

* [ ] RAG 知识库：应急手册 \+ 历史案例 \+ 规则说明

* [ ] 自动生成 Sigma 规则建议（检测盲区补全）

### Phase 4：生产化 \+ 规模化（持续）

* [ ] 性能优化：告警吞吐、Agent 并发、大模型推理加速

* [ ] K8s 部署方案，水平扩展

* [ ] 多租户 / 多环境支持

* [ ] 合规报告自动生成（等保 2\.0）

* [ ] Agent 反馈学习：人工处置结果回流优化模型

* [ ] 安全设备广泛接入（WAF/EDR/ 云安全）

---

## 七、关键风险与应对

|风险|影响|应对|
|---|---|---|
|**大模型幻觉 / 误判**|错误处置导致业务中断|置信度阈值 \+ 人工审批 \+ 只读优先 \+ 操作沙箱预演|
|**告警风暴**|Agent 处理不过来|去重聚合 \+ 优先级队列 \+ 限流降级，高优先级优先处理|
|**MCP 工具权限滥用**|Agent 越权操作|RBAC 细粒度权限 \+ 每个工具调用审计 \+ 高危操作强制审批|
|**本地大模型性能不足**|推理慢，无法实时|8\-bit 量化 \+ GPU 推理 \+ 简单任务用小模型 \+ 复杂任务路由云端|
|**检测规则覆盖不足**|漏报|Sigma 社区规则持续同步 \+ ATT\&CK 覆盖度分析 \+ ThreatHunter 补盲区|
|**挖矿病毒对抗检测**|进程隐藏 / 流量加密|多维度交叉验证 \(CPU \+ 进程 \+ 网络 \+ eBPF\)\+ 行为分析而非仅特征匹配|

---

## 八、建议的起步行动

1. **先搭 MVP 验证核心链路**：用 1 台测试机部署 Wazuh \+ OpenSearch \+ 自研 TriageAgent \+ 挖矿 Playbook，跑通 "发现→分析→处置方案" 闭环

2. **参考 Vigil SOC 的代码结构**：其 13Agent 设计和 MCP 集成方式可以直接借鉴，避免从零设计

3. **挖矿场景做深做透**：作为第一个标杆场景，把检测规则、排查步骤、处置动作、复盘报告全部标准化，其他场景照此模板扩展

4. **大模型先本地跑 Foundation\-Sec\-8B**：有 GPU 的话直接部署，验证安全推理能力，不行再用 API

需要我针对某个具体模块（比如挖矿 Playbook 的详细代码框架、LangGraph Agent 编排的实现、MCP 工具网关的设计）做更深入的设计，或者直接开始搭建 MVP 环境吗？

以上是完整的调研与设计规划。核心思路是：**检测 / 采集 / 存储层全部复用成熟开源组件（Wazuh\+Suricata\+Zeek\+OpenSearch\+OpenCTI），自研聚焦在 AI 多 Agent 决策层和场景化 Playbook**，以挖矿病毒为第一个标杆场景做深做透，再逐步扩展到勒索、WebShell、横向移动等场景。

你可以告诉我下一步想深入哪个方向：

- 直接开始搭建 **MVP 环境**（Docker Compose 编排 \+ Wazuh \+ OpenSearch）

- 深入设计 **LangGraph 多 Agent 编排** 的代码框架

- 深入设计 **MCP 工具网关** 的实现方案

- 把 **挖矿病毒 Playbook** 细化为可执行的检测规则 \+ 排查脚本 \+ 处置流程

- 输出为 **飞书文档** 便于团队协作

> （注：部分内容可能由 AI 生成）
