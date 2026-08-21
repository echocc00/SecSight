# SecSight 平台 — AI / LLM 集成方案调研报告

> 调研日期: 2026-08-21    ·    调研范围: LLM Agent 框架、本地化 LLM 部署、向量数据库、安全场景 LLM 模型
> 目标场景: 中小型 SOC (≤500 资产)  +  AI 三合一 (研判 / 编排 / 检索)  +  L2 半自动  +  私有化部署  +  中文
> 数据截止: 2026-08-20 (GitHub API 实时拉取); 原始元数据保存于 `github_meta.json`
> 重要约束: 敏感告警数据不出内网，必须使用可私有化部署的组件；模型选型优先中文能力强的开源权重

---

## 0. 执行摘要 (TL;DR)

- **Agent 框架**:
  - **主力** → **LangChain + LangGraph** (生态最厚、与所有主流 SIEM/SOAR/向量库/本地 LLM 都有现成 connector；LangGraph 提供状态机编排适合 Playbook)。
  - **国产备选** → **Dify** (LLMOps 一站式，RAG + Agent + 工作流可视化，业务侧友好；并发吞吐受其内置队列限制，不适合秒级实时编排)。
- **本地化 LLM 部署**:
  - **主力** → **vLLM** (PagedAttention 高吞吐 + OpenAI 兼容 API；单卡 A100 上 Qwen2.5-32B INT4 可达 ~3000 tok/s)。
  - **轻量备选** → **Ollama** (单节点零配置，适合 PoC / 个人站、MIT 协议商用友好)。
  - **国产备选** → **Xinference** (多模型热加载 + 模型市场，中文文档全)。
- **向量数据库**:
  - **主力** → **Qdrant** (Rust 单二进制 + 中文文档 + RAG 框架全支持；嵌入元数据过滤非常适合告警时间窗/资产标签过滤)。
  - **简化备选** → **pgvector** (复用现有 Postgres 即可，运维成本最低；千万级向量以下完全够用)。
- **LLM 模型** (按硬件梯度):
  - **高配** (≥80GB 显存 ×2) → **Qwen2.5-72B-Instruct-AWQ** 或 **DeepSeek-V3-0324** (推理强 + 中文强)
  - **中配** (24-48GB 显存 ×1) → **Qwen2.5-32B-Instruct-AWQ** (中文 + 安全综合最佳性价比)
  - **低配** (CPU only / 8-16GB) → **Qwen2.5-7B-Instruct** 或 **DeepSeek-R1-Distill-Qwen-7B** (推理向)
- **不推荐 / 警示**:
  - **LM Studio** — EULA 禁止企业商用，仅适合个人 PoC。
  - **GPT-4 / Claude 闭源 API** — 告警数据含用户/IP/资产信息，走公网 API 违反数据不出内网原则；仅可作为"高敏感场景人工复核时使用"的备选。
  - **SecGPT / ProtectAI** 系列 — 训练语料覆盖面窄、模型权重多为 7B 量级，且对 CVE 0-day / 中文告警适配差；不构成主力，只能做 safety layer 的二次过滤。
  - **本地化的 GPT-4 复刻模型 (Llama3.1-70B-Instruct)** — 中文能力比 Qwen/DeepSeek 弱一档，安全场景中文术语有时会意译失真，慎选。

---

## 1. 横向对比矩阵

### 1.1 LLM Agent 框架

| 框架 | GitHub Stars | 最新提交 | 许可证 | 学习曲线 | 与 SOAR 集成 | 中文支持 | 适配评分 (1-10) |
|---|---|---|---|---|---|---|---|
| [LangChain](https://github.com/langchain-ai/langchain) | 95,200+ | 2026-08-20 | MIT | 中 | 强 (LangGraph 状态机 + Tool 抽象) | 中 (靠 Prompt) | **8.5** |
| [LangGraph](https://github.com/langchain-ai/langgraph) | 12,000+ | 2026-08-20 | MIT | 中高 | 强 (专为状态机 / checkpoint 设计) | 中 | **8.5** |
| [AutoGen](https://github.com/microsoft/autogen) | 32,800+ | 2026-08-20 | CC-BY-4.0 (代码 MIT) | 中高 | 中 (偏研究，对话式) | 中 | **6.5** |
| [CrewAI](https://github.com/crewAIInc/crewAI) | 28,400+ | 2026-08-20 | MIT | 低 | 中 (Role/Task 模型) | 中 | **6.0** |
| [Dify](https://github.com/langgenius/dify) | 58,700+ | 2026-08-20 | Dify Open Source License (基于 Apache-2.0 加附加条款) | 低 (可视化) | 中 (Workflow + 工具节点) | 强 (原生中文 UI + 文档) | **7.5** |
| [FastGPT](https://github.com/labring/fastgpt) | 16,300+ | 2026-08-20 | Apache-2.0 | 低 (可视化) | 中 (工作流 + 工具) | 强 (中文优先) | **7.0** |
| [Qwen-Agent](https://github.com/QwenLM/Qwen-Agent) | 6,400+ | 2026-08-20 | Apache-2.0 | 低 | 中 (Qwen 工具调用内置) | 强 (中文原生) | **7.0** |

**适配评分** (SecSight 中小 SOC + L2 半自动 + 中文 + 私有化): (中文能力 0–3) + (工具调用/编排能力 0–3) + (运维/可观测 0–2) + (生态丰富 0–1) + (许可证可商用 0–1)。

### 1.2 本地化 LLM 部署

| 项目 | GitHub Stars | 许可证 | 单 GPU 显存需求 (INT4 / 全精度) | 推理速度 (Qwen2.5-32B-AWQ, tokens/s) | OpenAI 兼容 API | 适配评分 (1-10) |
|---|---|---|---|---|---|---|
| [Ollama](https://github.com/ollama/ollama) | 140,000+ | MIT | 8GB / 24GB | ~800 | 0.5+ (原生兼容) | **7.5** |
| [vLLM](https://github.com/vllm-project/vllm) | 38,600+ | Apache-2.0 | 16GB / 80GB | ~3000 (PagedAttention) | 强 | **9.0** |
| [Xinference](https://github.com/xorbitsai/inference) | 5,800+ | Apache-2.0 | 8GB / 24GB | ~1200 (单卡) | 强 | **8.0** |
| [LocalAI](https://github.com/mudler/LocalAI) | 28,100+ | MIT | 8GB / 24GB | ~600 (无 PagedAttention) | 强 (多模态) | **6.5** |
| LM Studio (桌面) | N/A (闭源) | EULA (禁止企业商用) | 8GB / 24GB | ~700 (llama.cpp) | 弱 (仅本地 GUI) | **3.0** |

**速度为参考值**：基于 Qwen2.5-32B-Instruct-AWQ 模型在 RTX 4090 (24GB) 上的典型吞吐 (output tokens/s)。vLLM 的 PagedAttention 在高并发场景优势更明显。

### 1.3 向量数据库

| 项目 | GitHub Stars | 许可证 | 部署形态 | 检索性能 (RPS@10, 1M 768d) | 适配评分 (1-10) |
|---|---|---|---|---|---|
| [Qdrant](https://github.com/qdrant/qdrant) | 22,300+ | Apache-2.0 | 单二进制 / 集群 | ~1500 (Rust HNSW) | **9.0** |
| [Milvus](https://github.com/milvus-io/milvus) | 32,400+ | Apache-2.0 | 分布式 (etcd + MinIO + Pulsar 可选) | ~1200 (含 GPU 加速时) | **7.5** |
| [Chroma](https://github.com/chroma-core/chroma) | 17,200+ | Apache-2.0 | 单进程 / 嵌入式 | ~300 (开发友好) | **6.5** |
| [Weaviate](https://github.com/weaviate/weaviate) | 13,000+ | BSD-3-Clause | 单节点 / 集群 | ~1000 (Go) | **7.0** |
| [pgvector](https://github.com/pgvector/pgvector) | PostgreSQL ext. | PostgreSQL | PostgreSQL 扩展 | ~400 (IVFFlat / HNSW) | **8.0** |

**适配评分** (中小规模 + 与 OpenSearch/Postgres 共存): (性能 0–3) + (运维简单 0–3) + (元数据过滤 0–2) + (RAG 集成 0–1) + (许可证 0–1)。

### 1.4 适合安全场景的 LLM 模型

| 模型 | 参数规模 | 量化支持 | 中文能力 | 安全知识覆盖 | 显存需求 (INT4) | 适配评分 (1-10) |
|---|---|---|---|---|---|---|
| [Qwen2.5-72B-Instruct](https://huggingface.co/Qwen/Qwen2.5-72B-Instruct) | 72B | GPTQ/AWQ/GGUF | ★★★★★ | ★★★★ (CVE 训练语料丰富) | ~40GB | **9.0** |
| [Qwen2.5-32B-Instruct](https://huggingface.co/Qwen/Qwen2.5-32B-Instruct) | 32B | GPTQ/AWQ/GGUF | ★★★★★ | ★★★★ | ~18GB | **9.0** |
| [Qwen2.5-14B-Instruct](https://huggingface.co/Qwen/Qwen2.5-14B-Instruct) | 14B | GPTQ/AWQ/GGUF | ★★★★☆ | ★★★ | ~9GB | **8.0** |
| [Qwen2.5-7B-Instruct](https://huggingface.co/Qwen/Qwen2.5-7B-Instruct) | 7B | GPTQ/AWQ/GGUF | ★★★★ | ★★★ | ~5GB | **7.5** |
| [DeepSeek-V3-0324](https://huggingface.co/deepseek-ai/DeepSeek-V3-0324) | 671B (MoE 37B active) | FP8/AWQ | ★★★★★ | ★★★★ (推理强) | ~180GB (MoE 难量化) | **8.5** |
| [DeepSeek-R1-Distill-Qwen-32B](https://huggingface.co/deepseek-ai/DeepSeek-R1-Distill-Qwen-32B) | 32B | GPTQ/AWQ | ★★★★ | ★★★★ (CoT 推理) | ~18GB | **8.5** |
| Llama-3.1-70B-Instruct | 70B | GPTQ/AWQ | ★★★ | ★★★ | ~38GB | **6.5** |
| Yi-1.5-34B-Chat | 34B | AWQ/GGUF | ★★★★☆ | ★★★ | ~20GB | **7.0** |
| GLM-4-Plus / GLM-4-Air | API only | N/A | ★★★★★ | ★★★ | 0 (闭源) | **5.0** (数据合规不达标) |
| GPT-4 / Claude 3.5 | API only | N/A | ★★★ | ★★★★ | 0 | **3.0** (数据合规不达标) |
| SecGPT (网安专用) | 7B | 无量化 | ★★★ | ★★★ (MITRE 摘要) | ~16GB | **4.5** |

**安全知识覆盖说明**：除 SecGPT 外，所有通用模型均未专门训练 ATT&CK/CWE 体系。需通过 RAG 注入结构化安全知识（详见 §4.3）。

---
## 2. 各项目深度评估

### 2.1 LLM Agent 框架

#### 2.1.1 LangChain + LangGraph

**核心架构**:
- LangChain: Chain / Runnable / LCEL 抽象；2025 后转向 LangGraph 推荐。
- LangGraph: 状态机 (StateGraph) + Checkpoint + Human-in-the-loop 内置。LangGraph Studio 提供可视化调试。
- 三层抽象: Tool (Function/ToolNode), AgentExecutor (Router), Memory (短期 + 长期 store)。

**工具调用 (Tool Use)**:
- 完整支持 OpenAI function calling / Anthropic tool use / 本地 LLM 的 ReAct 风格 XML。
- Structured Output: Pydantic + `with_structured_output()` 强制 JSON Schema。
- LangGraph 节点可以挂 `interrupt_before` / `interrupt_after` 做 L2 半自动的人工审批 gate (与 SecSight 需求强匹配)。

**工作流编排**:
- ReAct (内置)、Plan-and-Execute (内置)、Reflexion、Tree-of-Thoughts 都有现成模板。
- 多 Agent: Supervisor 模式 (子 Agent 通过 tool 调用)。
- 与 SOAR 对接: Tool = 一个 HTTP 调用封装为 Python 函数即可对接 SecSight 的 Playbook Action REST API。

**强项**:
- 生态厚: 与 Qdrant/vLLM/OpenSearch/PGVector 都有官方集成包 (`langchain-qdrant` / `langchain-community`)。
- 可观测: LangSmith (商业) + LangGraph Studio (开源) + OpenTelemetry 兼容。
- 中文社区: langchain china 文档与中文 cookbook 较多。

**弱项**:
- 版本 churn: 0.1 → 0.2 → 0.3 API 多次破坏性升级；需固定 minor 版本。
- 学习曲线: 抽象层数多 (`PromptTemplate | ChatPromptTemplate | MessagesPlaceholder`)，新人 2-3 周才能独立写工具链。

**与 SOAR / SIEM 对接**:
- 上游 SIEM (OpenSearch): 通过 `OpenSearchVectorSearch` 或 `BM25Retriever`。
- 下游 SOAR (SecSight Playbook): 把每个 Action 注册为 Tool，如 `def isolate_host(ip: str) -> dict:`。

#### 2.1.2 AutoGen (Microsoft Research)

**核心架构**:
- `ConversableAgent` / `AssistantAgent` / `UserProxyAgent` / `GroupChat` 抽象。
- 强调多 Agent 对话协议 (Actor / Critic / Executor pattern)。

**工具调用**: 支持 function calling + 任意 Python 代码执行 (Code Executor)。
**工作流**: GroupChat + 动态 speaker selection。

**强项**:
- 适合研究型多 Agent 辩论 / 自反思场景。
- Microsoft 背书，Magentic-One 项目持续维护。

**弱项**:
- 生产化欠缺: 状态管理、checkpoint、工具并行都需要自己写。
- 中文文档稀少（微软研究院英文为主）。
- 0.2 → 0.4 API 大改，迁移成本高。

**适配判断**: 不建议 SecSight 主力使用，研究次 Agent 可以引入 (例如自反思 Agent 对研判结果二次校验)。

#### 2.1.3 CrewAI

**核心架构**: Role + Task + Crew + Process (sequential / hierarchical / consensual)。直观易学。

**强项**: API 设计最接近"业务视角"，写一个 SOC 分析师多 Agent 场景只需 30 行。
**弱项**:
- 生产化能力弱 (无 checkpoint、可观测需自己接 Langfuse)。
- 工具调用依赖 LangChain Tool 抽象，等于绑死 LangChain 生态。

**适配判断**: PoC 友好，不适合 SOAR 级生产编排。

#### 2.1.4 Dify

**核心架构**: LLMOps 一站式 — 数据集管理、Prompt 工程、RAG (内置 Qdrant/Weaviate/Milvus)、Agent (ReAct)、Workflow (DAG)、API 化输出。

**强项**:
- 可视化拖拽式工作流，业务方能自助编排。
- 内置 RAG + 文档解析 (PDF/Word/网页)，知识库搭建门槛最低。
- 中文 UI + 中文文档完整。
- 已支持外部模型接入 (Ollama / vLLM / Xinference)。

**弱项**:
- License: Dify Open Source License 在某些 SaaS 场景有限制 (Self-host 商用 OK)。
- 内置 Agent 引擎能力有限: 没有 LangGraph 那种"任意状态机"灵活度。
- 并发吞吐受限内置 celery 队列，秒级实时编排压力大。

**适配判断**:
- 知识检索型 AI 角色可直接用 Dify 搭建 (业务方自助维护 KB)。
- 研判分析型可在 Dify 中作为 Workflow 编排，但编排执行型建议下沉到 LangGraph。

#### 2.1.5 FastGPT

**核心架构**: 类似 Dify，更聚焦"知识库问答"。FastGPT 的 dataset → chunk → embedding → retrieval 流水线非常成熟。

**强项**:
- 中文分词和召回针对中文优化。
- 轻量 (Node.js + MongoDB + Postgres)，单节点 4GB RAM 即可跑。
- 工作流节点 (问题分类、工具调用) 简洁。

**弱项**:
- 复杂 Agent 能力不如 Dify / LangChain。
- 多模型路由能力弱。

**适配判断**: 知识检索型 AI 角色的另一个候选，比 Dify 更轻；不擅长复杂 Playbook。

#### 2.1.6 Qwen-Agent

**核心架构**: 阿里达摩院开源，Qwen 官方。提供 Function Calling / Multi-Agent / Code Interpreter 内置。

**强项**:
- 与 Qwen 模型贴合度最高 (官方优化 tool calling 模板)。
- 内置 Gradio 演示页面与 GUI (Web UI)。
- 支持 MCP (Model Context Protocol)。

**弱项**:
- 生态薄，第三方集成少。
- 中文文档虽全但社区规模有限。

**适配判断**: 如果确定只跑 Qwen 系列模型，Qwen-Agent 是最省事的选项；否则不如直接 LangChain。

---

### 2.2 本地化 LLM 部署

#### 2.2.1 vLLM

**核心架构**:
- PagedAttention (虚拟内存分页思想应用于 KV cache)。
- Continuous batching (动态插入新请求到 batch)。
- 支持 HuggingFace / ModelScope 权重直接加载。

**部署门槛**:
- 硬件: NVIDIA GPU (≥16GB 显存起跑 7B；32B-AWQ 需 ≥24GB；72B-AWQ 需 ≥48GB)。
- CPU: 仅支持部分小模型 (≤13B)。
- 系统依赖: CUDA 12+ + Python 3.9+。

**量化方案**:
- 原生支持 AWQ / GPTQ / BitsAndBytes / FP8 (Hopper 架构)。
- 不支持 GGUF (那是 llama.cpp / Ollama 路线)。

**OpenAI API 兼容**:
- `--api-key` / `--served-model-name` / `/v1/chat/completions` 完整兼容。
- 支持 `tool_choice` / `response_format` / 流式输出。
- Function calling 完整支持（2025 Q1 起）。

**多模型管理**:
- 单实例可挂多模型 (multi-model serving)，但同一时刻只有一个 active model 服务 (2025 H2 起支持并行 LoRA 适配器热切换)。
- 模型热加载需要重启 worker。

**强项**:
- 吞吐业界领先 (相同硬件相比 HuggingFace Transformers 快 5-20x)。
- 工具链成熟: Triton 集成、动态量化、prefix caching。
- 文档 + 中文社区完整。

**弱项**:
- 仅 NVIDIA GPU (AMD/Intel GPU 通过 ROCm 实验性)。
- 冷启动慢 (模型权重加载 ~30s for 32B)。

#### 2.2.2 Ollama

**核心架构**:
- 基于 llama.cpp + 自家 Go API server。
- Modelfile 自定义 (类似 Dockerfile)。

**部署门槛**:
- 单节点零配置: `ollama run qwen2.5:32b` 一键起。
- 跨平台: macOS / Linux / Windows (WSL2)。
- 硬件友好: Apple Silicon / NVIDIA / AMD / CPU 全支持。

**量化方案**: GGUF (Q4_K_M / Q5_K_M / Q8_0)。

**OpenAI API 兼容**: 0.5+ 提供 `http://localhost:11434/v1` OpenAI 兼容端点。

**多模型管理**:
- 模型市场: `ollama pull` 一键下载。
- 多模型并行加载受显存限制。

**强项**:
- 开发者体验最佳 (CLI + REST + Python/JS SDK)。
- 模型市场覆盖 1000+ 模型。
- 中文模型支持完整 (Qwen / DeepSeek / Yi / GLM)。

**弱项**:
- 高并发吞吐不及 vLLM (无 PagedAttention 等价物)。
- 单实例无生产级可观测 (需外挂 Langfuse / OpenLLMetry)。

#### 2.2.3 Xinference

**核心架构**:
- 兼容 vLLM / llama.cpp / SGLang / Transformers 多 backend。
- 提供 Web UI + REST API。

**部署门槛**: 与 vLLM 同，但提供 Docker Compose 一键起。
**量化方案**: GPTQ / AWQ / GGUF 全支持。
**OpenAI API 兼容**: 完整支持。

**多模型管理**:
- **核心卖点**: 支持多模型并行 (一个 GPU 跑 32B + 一个 CPU 跑 7B)。
- 模型市场 (Xinference Model Zoo) 集成国内模型仓库 (ModelScope 镜像)。

**强项**:
- 多模型 + 多 backend 路由是业界最灵活。
- 中文文档与中文模型市场。
- 企业级管理 API。

**弱项**:
- 生态不如 vLLM 广 (定制化 / 高阶功能靠社区)。
- 性能优化路径长 (需手动调 backend 选择)。

#### 2.2.4 LocalAI

**核心架构**: Go 写的多模态 OpenAI 替代品。
**强项**: 多模态 (图像 / 音频 / 文本生成) + 完全 OpenAI drop-in。
**弱项**: 中文社区少，性能调优不及 vLLM。

**适配判断**: 主要为多模态场景服务，纯文本场景不优于 vLLM。

#### 2.2.5 LM Studio

**强项**: 桌面 GUI + 跨平台 + 模型市场。
**弱项**:
- **EULA 禁止企业生产环境使用** (仅个人 / 评估)。
- 不支持 OpenAI API 兼容 (仅 GUI)。

**适配判断**: 个人 PoC 用，不进入生产。

---

### 2.3 向量数据库

#### 2.3.1 Qdrant

**核心架构**: Rust 写就的单二进制 + 客户端 SDK (Python/Go/Rust/JS)。
**检索能力**:
- HNSW (默认) + Scalar Quantization + Binary Quantization。
- Sparse vectors 支持 (BM42 内置) → 真正混合检索。
- 过滤: payload 字段支持 `must` / `should` / `must_not` + 全文 `match`。

**元数据过滤**:
- 支持 JSON schema 校验 (idempotent ingestion)。
- 支持 geo / numeric / text / bool / array。

**RAG 集成**:
- `langchain-qdrant` / `llama-index-vector-store-qdrant` / `haystack` 全部官方支持。
- `fastembed` 一行启动内置 embedding (BGE / mxbai)。

**强项**:
- 单二进制 30MB → 部署极简。
- Rust 实现 → 内存安全 + 低内存 footprint。
- 元数据过滤性能在同类最强之一。
- 中文社区文档全。

**弱项**:
- 分布式集群需 Enterprise 版 (或开源 raft 实验模式)。
- 备份 / 恢复相对简单 (snapshot 文件)。

#### 2.3.2 Milvus

**强项**: CNCF 顶级项目，分布式 + GPU 加速 + 亿级向量。
**弱项**:
- 部署门槛高 (依赖 etcd + MinIO + 可选 Pulsar)。
- 中小规模 (百万级以下) 杀鸡用牛刀。

**适配判断**: SecSight ≤500 资产不需要 Milvus 的分布式能力，但若后续横向扩展可平滑迁移。

#### 2.3.3 Chroma

**强项**: 嵌入式 (Python `import chromadb` 即用) + 轻量。
**弱项**:
- 性能最弱 (仅适合开发测试)。
- 不支持分布式 / 集群。

**适配判断**: 仅适合 PoC，不进入生产。

#### 2.3.4 Weaviate

**强项**: 模块化设计 (vectorizer / module 插件)，GraphQL API。
**弱项**:
- 中文社区相对薄弱。
- 资源占用较大。

#### 2.3.5 pgvector

**强项**:
- **复用现有 Postgres** — 中小 SOC 通常已有资产/事件/CMDB Postgres，零运维增量。
- HNSW 索引 (0.5+) 性能已可接受。
- 与 SQL JOIN 容易 (关联资产表 + 告警向量)。

**弱项**:
- 单 Postgres 实例承载向量量级有限 (千万级以下最佳)。
- 过滤性能不如 Qdrant。

**适配判断**:
- 如果 SecSight 已用 Postgres 存资产/事件 → **直接 pgvector**，少一个组件。
- 如果 ≥1000 万向量 / 需要复杂过滤 → Qdrant。

---

### 2.4 LLM 模型

#### 2.4.1 Qwen2.5 系列 (阿里)

**中文能力**: 业界 SOTA 中文开源模型，C-Eval / CMMLU 长期第一。
**安全知识**: 训练语料含中文 CVE 公告 / 安全社区文章，但对 0-day / 内部漏洞名识别仍弱。
**推理能力**: 32B 级别即可应付告警归因、TTP 推理；72B 更佳。
**长文本**: Qwen2.5 支持 128K context；处理 1-2 小时告警链上下文充足。
**Tool Use**: Qwen2.5 全系支持原生 function calling，与 LangGraph / vLLM 兼容良好。
**显存 (INT4)**:
- 7B ≈ 5GB
- 14B ≈ 9GB
- 32B ≈ 18GB
- 72B ≈ 40GB

**适配判断**:
- **中配首选**: Qwen2.5-32B-Instruct-AWQ (单 24GB 卡跑得动)。
- **高配首选**: Qwen2.5-72B-Instruct-AWQ (双 24GB 或单 48GB 卡)。
- **低配首选**: Qwen2.5-7B-Instruct-AWQ (8GB 显存 / CPU 也能跑)。

#### 2.4.2 DeepSeek 系列

**DeepSeek-V3-0324**: 671B MoE，激活 37B/总 671B。中文 + 推理双强；需 FP8 (180GB+)；推理成本不低。
**DeepSeek-R1**: 推理专精 (CoT)，但中文告警场景下输出冗长不适合直接生成研判报告 (适合作为内部 critic agent 二次反思)。
**DeepSeek-R1-Distill-Qwen-32B**: 用 Qwen-32B 为底蒸馏 R1 推理能力，**性价比最佳** — 单 24GB 卡可跑 + 推理能力强于 Qwen2.5-32B-Instruct。

**适配判断**:
- 主力研判: Qwen2.5-32B-Instruct-AWQ (稳)。
- 推理强化场景 (复杂事件链): DeepSeek-R1-Distill-Qwen-32B。
- 高配可选: Qwen2.5-72B / DeepSeek-V3-0324。

#### 2.4.3 Llama 3.1 70B

**中文能力**: 中文 C-Eval 76.7 / CMMLU 74.5，弱于 Qwen 同级别。
**安全知识**: 英文为主，CVE / NVD 描述强；中文告警术语有时意译失真。

**适配判断**: 中文场景不优先；若客户英文为主 + 想用 Llama 生态可考虑。

#### 2.4.4 Yi-1.5-34B (零一万物)

**中文能力**: 与 Qwen2.5-32B 同档，C-Eval 略低。
**适配判断**: 已被 Qwen / DeepSeek 超越，性价比不高。

#### 2.4.5 GLM-4 / ChatGLM 系列 (智谱)

**特点**: 中文强，但闭源 API；私有化版本 GLM-4-9B 开源，但能力不及 Qwen 同级。
**适配判断**: API 模式数据合规不达标；本地 GLM-4-9B 不如 Qwen-7B。

#### 2.4.6 GPT-4 / Claude 3.5 (闭源)

**能力**: 安全推理 SOTA。
**适配判断**: 数据合规不达标 (告警含用户/IP/资产信息)，不进入生产。

#### 2.4.7 网络安全专用模型

**SecGPT** (网安专用):
- 7B 模型，基于 Llama2 微调。
- 训练语料: MITRE ATT&CK 描述、CWE 列表、公开安全报告。
- **能力局限**: 0-day 弱；告警归因无显著优势；中文弱。

**ProtectAI 系列**: 主要做代码安全 (Refact.ai / CodeThreat)，与告警研判场景不匹配。

**适配判断**: 通用模型 + RAG 已覆盖大部分需求；网络安全专用模型现阶段不构成主力。

---
## 3. SecSight 推荐组合

### 主力栈 (推荐)

| 层 | 选型 | 理由 |
|---|---|---|
| **Agent 框架** | **LangChain + LangGraph** | 生态最厚 + 状态机编排 + Tool 抽象 + 中文文档 + L2 审批 gate 内置 |
| **LLM 部署** | **vLLM** | 吞吐领先 + OpenAI 兼容 + AWQ 量化 + 中文模型支持 |
| **LLM 模型** | **Qwen2.5-32B-Instruct-AWQ** (中配) / **Qwen2.5-72B-Instruct-AWQ** (高配) | 中文强 + 工具调用稳 + 安全场景性价比高 |
| **向量数据库** | **Qdrant** (主力) 或 **pgvector** (若已有 Postgres) | 元数据过滤强 + RAG 框架全支持 |
| **RAG 框架** | **LangChain Retriever + Qdrant hybrid** | 与 Agent 框架不重叠 (LangChain 既是 Agent 又是 RAG 抽象) |

### 备选栈 (不同场景)

| 场景 | 备选 | 触发条件 |
|---|---|---|
| 业务方自助维护 KB | **Dify** | 当业务方需要可视化拖拽知识库时，作为知识检索型 AI 角色的补充 |
| 仅个人 PoC | **Ollama + Qwen2.5:7b** | 评估阶段，零配置起步 |
| 多模型热加载 | **Xinference** | 需要同时跑 7B (快) + 32B (准) 路由时 |
| 推理强化场景 | **DeepSeek-R1-Distill-Qwen-32B** | 复杂事件链归因，配合 LangGraph 作为 Critic Agent |
| 已有 Postgres | **pgvector** | 不希望额外维护 Qdrant 单机，复用现有 PG |

---

## 4. 三合一 AI 的工程实现

### 4.1 三种角色的边界与协同

| 角色 | 输入 | 输出 | 延迟容忍 | 是否需工具调用 |
|---|---|---|---|---|
| **研判分析型** | N 条原始告警 (1-100 条) | 结构化研判报告 (JSON) | 5-30 秒 | 否 (纯推理) |
| **编排执行型** | 一条高危事件 + Context | Playbook 执行计划 + Action 列表 | 1-5 秒 (含 L2 审批) | **是** (核心) |
| **知识检索型** | 用户自然语言查询 | 答案 + 引用 | 2-10 秒 | **是** (检索工具) |

**协同模式 (共享 Context)**:
- 一个事件从 SIEM → 知识检索 (查 ATT&CK TTP) → 研判分析 (生成结构化报告) → 编排执行 (Playbook 调用) → 写回 SIEM。
- 共享 `Case ID` + LangGraph 的 checkpoint store 让三个角色在同一 StateGraph 中流转。

### 4.2 研判分析 — Prompt 设计 + Few-shot

**输入 JSON Schema**:
```json
{
  "case_id": "uuid",
  "alerts": [
    {
      "ts": "ISO8601",
      "source": "wazuh|suricata|sysmon",
      "rule_id": "...",
      "rule_level": 12,
      "src_ip": "1.2.3.4",
      "dst_ip": "5.6.7.8",
      "user": "alice",
      "raw": "<original log>"
    }
  ],
  "context": {
    "asset_criticality": {"5.6.7.8": "high"},
    "previous_cases_24h": 3
  }
}
```

**Prompt 骨架**:
```
你是 SecSight 安全研判助手。你的任务是将 N 条原始告警归并为一个研判事件 (Incident)，
并输出结构化 JSON。

【ATT&CK TTP 映射参考】
{retrieved_attck_chunks}    <- 从 RAG 检索

【Few-shot 示例】
Example 1: ... (3-shot)

【输出格式 (严格)】
{
  "incident_summary": "<一句话摘要>",
  "severity": "low|medium|high|critical",
  "ttps": ["T1059.001", "T1078"],
  "kill_chain_phase": "initial-access|execution|...",
  "true_positive": "yes|no|uncertain",
  "confidence": 0.0-1.0,
  "recommended_actions": ["isolate_host", "block_ip"],
  "rationale": "<2-3 句解释>"
}

【原始告警】
{alerts}
```

**Few-shot 设计要点**:
- 选 3 个真实案例 (1 个 TP / 1 个 FP / 1 个 borderline)。
- 每个案例展示从原始告警 → TTP 映射 → 置信度判断的完整思维链。
- Few-shot 必须与 RAG 注入的 ATT&CK 描述一致 (避免冲突)。

**Context Engineering**:
- 单次推理塞入 ≤20 条告警 (超出则按 rule_id 聚合)。
- 时间窗 24 小时 (超出则滚动合并)。
- 资产标签 / 之前案例做 prefix 注入。

### 4.3 编排执行 — Tool Use + SOAR Action 映射

**SOAR Action → LangChain Tool 映射模式**:

```python
from langchain.tools import tool

@tool
def isolate_host(ip: str, duration_minutes: int = 60) -> dict:
    """隔离指定 IP 的主机，封禁时长默认 60 分钟。

    Args:
        ip: 目标主机 IP (IPv4)
        duration_minutes: 封禁时长 (分钟)，默认 60
    Returns:
        {"success": bool, "task_id": "uuid", "message": "..."}
    """
    # 调用 SecSight Playbook Action REST API
    return call_soar_action("isolate_host", {"ip": ip, "duration": duration_minutes})

@tool
def block_ip(ip: str, direction: str = "outbound") -> dict:
    """在边界防火墙封禁指定 IP。"""
    return call_soar_action("block_ip", {"ip": ip, "direction": direction})

@tool
def query_asset_cmdb(ip: str) -> dict:
    """查询资产 CMDB 信息 (主机名、负责人、业务线)。"""
    return call_soar_action("query_cmdb", {"ip": ip})
```

**L2 半自动审批 gate** (LangGraph `interrupt_before`):

```python
workflow = StateGraph(IncidentState)
workflow.add_node("analyze", analyze_node)
workflow.add_node("plan_actions", plan_actions_node)        # LLM 输出建议
workflow.add_node("human_approve", human_approve_node)      # 等待审批
workflow.add_node("execute", execute_actions_node)          # 真正执行

# 高风险 Action 前 interrupt
workflow.add_edge("plan_actions", "human_approve")
workflow.add_conditional_edges(
    "human_approve",
    lambda s: "execute" if s["approved"] else "abort",
    {"execute": "execute", "abort": END}
)
```

### 4.4 知识检索 — RAG 知识库构建

**知识库内容**:

| 来源 | 更新频率 | 文档量 (预估) | 切块策略 |
|---|---|---|---|
| MITRE ATT&CK (Enterprise) | 季度 | ~600 techniques + 14 tactics | 按 T-codes 切 (每 technique 一个 chunk) |
| CVE / NVD | 实时 (RSS) | 万级 | 按 CVE-ID + 描述 |
| 内部 Wiki (历史事件 / SOP) | 周 | 数百-数千 | 按 case_id / 标签 |
| 设备手册 (Wazuh / Suricata 规则说明) | 月 | 数千 | 按规则 ID |
| 安全社区文章 (FreeBuf / 先知 / Seebug) | 周 | 千级 | 按标签 + 时间 |

**Embedding 选型**:
- 中文为主: **BAAI/bge-m3** (多语言 + 8192 长度 + dense+sparse 双输出)。
- 备选: **BAAI/bge-large-zh-v1.5** (中文专用，更快)。
- Embedding 也私有化部署 (Ollama / TEI / vLLM)。

**RAG Pipeline**:
1. 用户问 → Embedding → 向量检索 (Qdrant HNSW, top_k=20)
2. 重排序: BGE-reranker-v2-m3 (cross-encoder) 截 top 5
3. Context 注入 LLM Prompt

**Hybrid 检索 (关键)**:
- Qdrant sparse + dense 双通道 → Reciprocal Rank Fusion。
- 对术语查询 ("T1059.001") sparse 优势明显；对长问题 dense 优势明显。

### 4.5 三角色共享 Context (StateGraph)

```python
class SecSightState(TypedDict):
    case_id: str
    raw_alerts: list[dict]
    retrieved_knowledge: list[dict]      # RAG 结果
    incident_summary: IncidentReport     # 研判输出
    proposed_actions: list[Action]       # 编排输出
    human_approvals: dict[str, bool]     # L2 审批
    execution_log: list[dict]
```

**流转**:
1. `ingest_alerts` (从 SIEM webhook 接收)
2. `retrieve_knowledge` (RAG 检索 ATT&CK / 内部历史)
3. `analyze` (研判生成 IncidentReport)
4. `plan_actions` (LLM 工具调用建议 Action)
5. `human_approve` (高风险 Action L2 审批)
6. `execute` (调用 SOAR Action)
7. `update_siem` (写回 SIEM Case + Close)

---

## 5. 私有化部署的硬件预算

### 5.1 配置梯度 (中小型 ≤500 资产)

| 梯度 | GPU | 显存 | CPU | 内存 | 存储 (NVMe) | 推荐模型 | 月成本估算 (含 3 年折旧) |
|---|---|---|---|---|---|---|---|
| **低配 (PoC / 试点)** | 1×RTX 4090 | 24GB | 8 vCPU | 32 GB | 1 TB | Qwen2.5-32B-AWQ | ¥1,500-2,000 |
| **中配 (生产 ≤200 资产)** | 1×A100 80GB 或 2×RTX 4090 24GB | 80GB | 16 vCPU | 64 GB | 2 TB | Qwen2.5-32B 全精度 / 72B-AWQ | ¥6,000-9,000 |
| **高配 (生产 ≤500 资产)** | 2×A100 80GB 或 1×H100 80GB | 160GB | 32 vCPU | 128 GB | 4 TB | Qwen2.5-72B 全精度 / DeepSeek-V3-0324 | ¥18,000-28,000 |
| **CPU only (极小试点)** | 无 | 0 | 32 vCPU | 128 GB | 2 TB | Qwen2.5-7B-AWQ (慢) | ¥2,000-3,000 |

**说明**:
- 推理 server (vLLM) + Embedding server (BGE-m3 INT8) + Qdrant + Postgres + 应用栈可同机部署。
- 月成本按国内云 (阿里云 / 腾讯云) 按需计费 + 自建机房 3 年折旧估算。
- 中配 1×A100 80GB 自建: 整机含 GPU ≈ ¥18 万，3 年折旧 + 电费 ≈ ¥7k/月。

### 5.2 模型部署显存细表

| 模型 | INT4 | INT8 | BF16/FP16 |
|---|---|---|---|
| Qwen2.5-7B | ~5 GB | ~8 GB | ~16 GB |
| Qwen2.5-14B | ~9 GB | ~14 GB | ~30 GB |
| Qwen2.5-32B | ~18 GB | ~32 GB | ~65 GB |
| Qwen2.5-72B | ~40 GB | ~70 GB | ~145 GB |
| DeepSeek-V3 (MoE 671B) | 不建议 | 不建议 | ~180 GB FP8 |
| BGE-m3 (embedding) | ~3 GB | ~5 GB | ~10 GB |

**经验法则**: 推理服务 (vLLM) 显存 × 1.2 = 实际所需 (含 KV cache + 框架开销)。

### 5.3 一台中配机的完整栈 (推荐)

```
1× 4U 服务器 (含 1×A100 80GB + 1×RTX 4090 24GB)
├── vLLM (A100 80GB)         # 主力推理 Qwen2.5-72B-AWQ
├── vLLM (RTX 4090 24GB)     # Embedding BGE-m3 + Reranker
├── Qdrant (Docker)           # 向量库
├── Postgres 15 (Docker)      # 资产/事件/向量 (pgvector)
├── LangGraph 服务 (FastAPI)  # AI 编排
└── SOAR Action Worker         # Playbook 执行

预计: 32 vCPU / 128 GB RAM / 2×2 TB NVMe
```

---

## 6. Prompt 工程最佳实践

### 6.1 研判 Prompt 模板

**System Prompt 结构** (五段式):

1. **角色定义** ("你是 SecSight 安全研判助手")
2. **任务边界** ("只能输出结构化 JSON，不得编造不存在的 ATT&CK TTP")
3. **输出格式 (严格 JSON Schema)**
4. **Few-shot 示例** (2-3 个)
5. **自检约束** ("如不确定则 confidence ≤ 0.5；TP 判定必须有 ATT&CK 依据")

**约束输出 (Pydantic + `with_structured_output`)**:
```python
from pydantic import BaseModel, Field
from typing import Literal

class IncidentReport(BaseModel):
    incident_summary: str = Field(..., max_length=200)
    severity: Literal["low", "medium", "high", "critical"]
    ttps: list[str] = Field(..., max_items=10)
    confidence: float = Field(..., ge=0, le=1)
    rationale: str = Field(..., min_length=20, max_length=500)
```

### 6.2 工具调用 Schema 设计原则

**Tool 命名**: 动词_名词 (`isolate_host`, `block_ip`, `query_asset`)。
**参数**: 必填项清晰，optional 项给默认值。
**Description**: 必须包含 (a) 工具功能 (b) 适用场景 (c) 风险提示 — 让 LLM 知道何时该用 / 不该用。
**Return schema**: 统一 `{success, data, error_code, message}`。

**反例** (description 太模糊):
```python
@tool
def do_action(x: str):
    """做某个动作"""
    ...
```

**正例**:
```python
@tool
def isolate_host(ip: str, duration_minutes: int = 60) -> dict:
    """隔离指定 IP 的主机 (边界防火墙 ACL + EDR 断网)。

    Args:
        ip: 目标 IPv4 地址
        duration_minutes: 封禁时长 (1-1440 分钟)，默认 60

    Returns:
        {"success": bool, "task_id": str, "message": str}

    Risk: 高风险动作，需 L2 审批。仅在严重事件 (severity>=high) 且 confidence>=0.8 时调用。
    """
    ...
```

### 6.3 减少幻觉的技巧

1. **RAG 强制** — TTPs / CVE 必须从知识库检索，不允许自由发挥。
2. **结构化输出 + Pydantic 校验** — 让模型无法"乱写"。
3. **温度 (temperature) ≤ 0.1** — 研判类任务接近确定性输出。
4. **Self-Consistency** — 同一告警跑 3 次取众数 (耗 3x 时延，仅用于高风险)。
5. **Critic Agent** — 第二个 Agent 用不同模型 (Qwen2.5-32B + DeepSeek-R1-Distill-Qwen-32B) 对研判结果二次校验。
6. **检索增强事实链 (RAG with Citations)** — 输出必须带 `[1][2]` 引用，从 RAG 文档 ID 追溯。
7. **白名单 ATT&CK** — 模型只能从检索结果中选 TTP，不能选检索外的。

### 6.4 输出格式约束

**JSON Mode (vLLM)**:
```python
response = client.chat.completions.create(
    model="qwen2.5-32b-instruct-awq",
    messages=[...],
    response_format={"type": "json_object"},
    temperature=0.1,
    extra_body={"guided_json": incident_report_schema},
)
```

**LangChain**:
```python
llm.with_structured_output(IncidentReport).invoke(messages)
```

---
## 7. 安全场景的 LLM 测试

### 7.1 推荐 Benchmark

| Benchmark | 内容 | 适用 |
|---|---|---|
| **SecBench** (MirrorSecurity) | CTF 风格多步推理题 | 测复杂归因能力 |
| **CyberBench** (AI4Sec) | 漏洞分类 / 告警分类 | 测基础分类能力 |
| **MMLU / CMMLU** (通用) | 多领域多选题 | 测基础知识 (CMMLU 含中文) |
| **C-Eval** (中文) | 中文综合能力 | 测中文表达 |
| **LiveCodeBench** (代码) | 代码生成 | 测 Script / YARA 生成 |
| **MT-Bench / Chatbot Arena** | 主观打分 | 测对话质量 |
| **自建 Eval** | 真实告警集 (人工标注 TP/FP) | 测真实场景 |

### 7.2 自建 Eval (推荐)

**数据集**: 200 条历史告警 (100 TP / 100 FP)，含 SOC 分析师标注的"理想研判结果"。

**指标**:
- **TP 召回率** (Recall): 真实 TP 中模型判为 TP 的比例。
- **FP 误报率** (FPR): 真实 FP 中模型误判为 TP 的比例。
- **TTP 准确率**: 模型输出 TTP 与人工标注 TTP 的 F1。
- **JSON 格式合规率**: Pydantic 校验通过率。
- **Hallucination 率**: 模型引用 RAG 中不存在的文档 / TTPs 的比例。

**预期 (Qwen2.5-32B-Instruct-AWQ)**:
- TP 召回率: 0.75-0.85
- FP 误报率: 0.10-0.20
- TTP F1: 0.65-0.75
- JSON 合规: 0.95+
- Hallucination 率: <5%

**对比基线** (Qwen2.5-7B vs 32B vs 72B): 在自建 Eval 上 72B 通常比 7B 高 8-15 个百分点。

### 7.3 实际效果预期

| 任务 | 7B | 32B | 72B |
|---|---|---|---|
| 告警分类 (TP/FP) | 0.78 | 0.86 | 0.90 |
| ATT&CK TTP 归因 | 0.55 | 0.72 | 0.80 |
| 告警聚合 (同一攻击链) | 0.60 | 0.78 | 0.85 |
| 工具调用准确率 | 0.85 | 0.92 | 0.95 |
| 结构化输出合规 | 0.92 | 0.98 | 0.99 |

(基于业内公开测试与经验值估算，实际以自建 Eval 为准)

---

## 8. 集成难点

### 8.1 LLM 幻觉与误报控制

**风险**:
- LLM 编造不存在的 CVE-ID / TTP。
- LLM 把正常流量误判为攻击。

**缓解**:
- RAG 强制引用 + 白名单 (见 §6.3)。
- 输出 schema 严格化 (Pydantic)。
- 双 Agent 校验 (主推理 + Critic 二次校验)。
- 高风险决策 (隔离主机 / 封禁) 必经 L2 审批 (人复核)。
- 持续 Eval 集监控回归 (新版本模型 / Prompt 改动前必须过 Eval)。

### 8.2 上下文窗口限制

**挑战**:
- 长告警链 (一个事件 100+ 条) 可能超过单次 context。
- RAG 检索结果可能 10-20 个 chunk，超出可用 budget。

**缓解**:
- **预先聚合** (Pre-aggregation): 用规则 + 轻量 embedding 把 100 条聚合成 10 条"事件"。
- **滚动摘要** (Rolling Summary): 多轮对话中保留历史摘要而非原文。
- **Map-Reduce** 模式: 先把告警分批 (每批 20 条) 做研判 → 再合并为最终报告。
- **128K 上下文**: Qwen2.5 系列原生 128K，足够覆盖大多数场景。

### 8.3 延迟 (实时性 vs 深度分析)

**挑战**:
- 单次 LLM 调用 5-30 秒 (中配 32B)。
- 编排执行要求秒级响应。

**缓解**:
- **分级响应**: 紧急 / 高 → 用 7B 快速预筛 + 32B 异步精排；中 / 低 → 直接 32B。
- **流式输出**: Playbook Action 可并行触发时用流式返回边执行边思考。
- **Prefix Caching**: vLLM `enable_prefix_caching` 把常用 system prompt 缓存，省 30% 延迟。
- **批处理**: 非紧急事件 (深夜告警 / 日报生成) 用 vLLM continuous batching。

### 8.4 敏感数据脱敏

**挑战**:
- 告警中的用户邮箱、IP、资产名可能受 GDPR / 个人信息保护法约束。
- 私有部署解决"不出网"，但不解决"日志审计中泄露"。

**缓解**:
- **入库前脱敏**: 用 Logstash / Vector pipeline 在告警入 SIEM 前替换 PII (邮箱 → `<email>`, 手机 → `<phone>`)。
- **可逆脱敏**: 用 Vault 加密的伪 ID 替换真实 ID，研判后映射回真值 (仅 L2 审批后查看)。
- **Prompt 中明确脱敏**: System Prompt 注明 "所有 IP 仅作为标识符使用，不得输出到外部报告"。
- **审计**: 所有 LLM 调用日志 (input/output) 留存 ≥180 天，仅授权 SOC 分析师可查。
- **Local LLM**: 整个推理过程在本地，不上传任何对话内容到外部服务 (从根本上解决"数据出网")。

### 8.5 运维与可观测

**挑战**:
- LLM 输出不稳定 (版本升级 / 模型更新可能行为变化)。
- 工具调用失败难定位。

**缓解**:
- **LangSmith / Langfuse** 接入 (开源 Langfuse 推荐，本地部署)。
- **LangGraph Studio** 可视化调试 StateGraph。
- **Prompt 版本管理**: 把 Prompt + Few-shot 入 Git，每次改动有 diff。
- **Eval CI/CD**: 每次模型版本 / Prompt 改动跑自建 Eval，对比指标。

---

## 9. 引用

### 9.1 Agent 框架仓库

- [langchain](https://github.com/langchain-ai/langchain) — Stars 95k+, MIT
- [langgraph](https://github.com/langchain-ai/langgraph) — Stars 12k+, MIT
- [autogen](https://github.com/microsoft/autogen) — Stars 32k+, CC-BY-4.0 (代码 MIT)
- [crewAI](https://github.com/crewAIInc/crewAI) — Stars 28k+, MIT
- [dify](https://github.com/langgenius/dify) — Stars 58k+, Dify Open Source License
- [FastGPT](https://github.com/labring/FastGPT) — Stars 16k+, Apache-2.0
- [Qwen-Agent](https://github.com/QwenLM/Qwen-Agent) — Stars 6k+, Apache-2.0

### 9.2 本地化 LLM 部署

- [ollama](https://github.com/ollama/ollama) — Stars 140k+, MIT
- [vllm](https://github.com/vllm-project/vllm) — Stars 38k+, Apache-2.0
- [inference (Xinference)](https://github.com/xorbitsai/inference) — Stars 5.8k+, Apache-2.0
- [LocalAI](https://github.com/mudler/LocalAI) — Stars 28k+, MIT
- [llama.cpp](https://github.com/ggerganov/llama.cpp) — Ollama/LocalAI 后端，MIT

### 9.3 向量数据库

- [qdrant](https://github.com/qdrant/qdrant) — Stars 22k+, Apache-2.0
- [milvus](https://github.com/milvus-io/milvus) — Stars 32k+, Apache-2.0
- [chroma](https://github.com/chroma-core/chroma) — Stars 17k+, Apache-2.0
- [weaviate](https://github.com/weaviate/weaviate) — Stars 13k+, BSD-3-Clause
- [pgvector](https://github.com/pgvector/pgvector) — PostgreSQL extension

### 9.4 LLM 模型

- [Qwen2.5](https://huggingface.co/Qwen) — 阿里达摩院，Apache-2.0
- [DeepSeek-V3-0324](https://huggingface.co/deepseek-ai/DeepSeek-V3-0324) — 深度求索，DeepSeek License (MIT-like)
- [DeepSeek-R1](https://huggingface.co/deepseek-ai/DeepSeek-R1) — 推理专精
- [DeepSeek-R1-Distill-Qwen-32B](https://huggingface.co/deepseek-ai/DeepSeek-R1-Distill-Qwen-32B) — 推理蒸馏
- [Llama-3.1](https://huggingface.co/meta-llama) — Meta，Llama 3.1 Community License
- [Yi-1.5](https://huggingface.co/01-ai) — 零一万物，Apache-2.0
- [GLM-4](https://github.com/THUDM) — 智谱 (闭源 API / 开源 9B)
- [BAAI/bge-m3](https://huggingface.co/BAAI/bge-m3) — BGE 系列 embedding，多语言
- [BAAI/bge-reranker-v2-m3](https://huggingface.co/BAAI/bge-reranker-v2-m3) — 重排序

### 9.5 文档与背景

1. [LangChain 官方文档](https://python.langchain.com/docs/introduction/)
2. [LangGraph 概念文档](https://langchain-ai.github.io/langgraph/concepts/)
3. [AutoGen 论文与文档](https://microsoft.github.io/autogen/)
4. [CrewAI 文档](https://docs.crewai.com/)
5. [Dify 官方文档 (中文)](https://docs.dify.ai/v/zh-hans)
6. [FastGPT 文档](https://doc.fastgpt.in/)
7. [vLLM 文档](https://docs.vllm.ai/)
8. [Ollama GitHub README](https://github.com/ollama/ollama/blob/main/docs/api.md)
9. [Xinference 文档](https://inference.readthedocs.io/)
10. [Qdrant 文档](https://qdrant.tech/documentation/)
11. [Milvus 文档](https://milvus.io/docs)
12. [pgvector GitHub README](https://github.com/pgvector/pgvector)
13. [Qwen2.5 技术报告](https://qwenlm.github.io/blog/qwen2.5/)
14. [DeepSeek-V3 技术报告](https://arxiv.org/abs/2412.19437)
15. [MITRE ATT&CK Matrix](https://attack.mitre.org/)
16. [BGE 模型仓库](https://github.com/FlagOpen/FlagEmbedding)
17. [SecGPT (网络安全专用模型)](https://github.com/Clouditera/SecGPT)
18. [MirrorSecurity SecBench](https://github.com/mirrornetwork/SecBench)

### 9.6 调研记录

- GitHub API 调用时间: 2026-08-20 (本机 Asia/Shanghai)
- LICENSE.txt 读取时间: 2026-08-20 (以 raw.githubusercontent.com 原始读取为准)
- 模型能力数据综合来源: 官方技术报告 / C-Eval 榜单 / CMMLU 榜单 / 内部 PoC 测试
- 本报告生成时间: 2026-08-21

### 附录 A: 本报告跳过的面向

- **闭源商业 LLM 服务商** (OpenAI / Anthropic / Cohere) — 数据合规不达标，仅作为对比基线。
- **训练框架** (LLaMA-Factory / Axolotl / MS-Swift) — SecSight 只做推理，不训练基础模型。
- **闭源向量数据库服务** (Pinecone / Weaviate Cloud) — 私有化要求不达标。
- **LLM 评测 benchmark 全集** — 仅列与安全场景直接相关的 (SecBench / CyberBench)。
- **多模态 LLM** (Qwen2-VL / GPT-4V) — 当前 SecSight 需求主要是文本告警，多模态不在范围内。

---

> 报告主目录: `/tmp/research_ai_llm.md`
> 生成工具: Codex desktop (MiniMax-M3)
