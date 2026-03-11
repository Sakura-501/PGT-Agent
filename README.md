# PGT-Agent

基于 Harbor 框架的溯源图（Provenance Graph）安全分析 Agent，用于自动化分析终端威胁检测与响应（TDR）场景下的攻击链、MITRE 映射和 IOC 提取。

## 架构概览

```
src/pgt_agent/
├── __init__.py              # 包入口，导出 PGTAgent
└── pgt_agent_impl/
    ├── agent.py             # 核心 Agent 实现（Harbor BaseAgent 子类）
    ├── graph.py             # 溯源图预处理与压缩
    ├── prompting.py         # Prompt 构建
    ├── schema.py            # 输出报告 JSON Schema
    ├── reporting.py         # 报告生成（JSON → Markdown）
    ├── parsing.py           # LLM 输出解析
    └── helpers.py           # 通用工具函数
```

## 核心模块说明

### 1. agent.py - PGTAgent 主类

继承自 `harbor.agents.base.BaseAgent`，实现完整的 Agent 生命周期：

```
┌─────────────────────────────────────────────────────────────┐
│                        PGTAgent                              │
├─────────────────────────────────────────────────────────────┤
│  setup()     → 准备环境（创建 artifacts 目录）               │
│  run()       → 核心分析流程                                  │
│    ├─ 下载溯源图 (source_graph.json)                         │
│    ├─ 预处理图数据 (graph.py)                                │
│    ├─ 构建 Prompt (prompting.py)                             │
│    ├─ 调用 LLM (OpenAI API 兼容)                             │
│    ├─ 解析输出 (parsing.py)                                  │
│    └─ 生成报告 (reporting.py)                                │
└─────────────────────────────────────────────────────────────┘
```

**关键配置参数：**

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `source_graph_path` | `/app/source_graph.json` | 容器内溯源图路径 |
| `report_md_path` | `/logs/artifacts/report.md` | Markdown 报告输出路径 |
| `report_json_path` | `/logs/artifacts/report.json` | JSON 报告输出路径 |
| `large_graph_char_threshold` | 220000 | 大图字符阈值 |
| `prompt_graph_char_limit` | 180000 | Prompt 字符限制 |
| `alert_detail_limit` | 40 | 告警边详情数量限制 |

### 2. graph.py - 溯源图预处理

处理大规模溯源图，支持三种模式：

```
┌─────────────────────────────────────────────────────────────┐
│                   图数据处理流程                             │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  原始图 (raw_graph)                                          │
│       │                                                      │
│       ▼                                                      │
│  ┌─────────────────┐                                         │
│  │ 字符数判断       │                                         │
│  └────────┬────────┘                                         │
│           │                                                  │
│     ≤ threshold                                          > threshold
│           │                                                  │
│           ▼                                                  ▼
│    ┌─────────────┐                              ┌──────────────────┐
│    │ mode: full  │                              │ 尝试 JSON 解析    │
│    │ 原样返回    │                              └────────┬─────────┘
│    └─────────────┘                                       │
│                                     ┌────────────────────┼────────────────────┐
│                                     │ 解析失败           │ 解析成功            │
│                                     ▼                    ▼                    │
│                           ┌─────────────────┐  ┌─────────────────┐            │
│                           │ mode: truncated │  │ build_compressed│            │
│                           │ -invalid-json   │  │ context()       │            │
│                           │ 截断处理        │  │                 │            │
│                           └─────────────────┘  │ • 提取边/节点    │            │
│                                                │ • 构建时间线     │            │
│                                                │ • 收集告警详情   │            │
│                                                │ • 生成摘要       │            │
│                                                └────────┬────────┘            │
│                                                         │                      │
│                                                         ▼                      │
│                                              ┌─────────────────────┐          │
│                                              │ 超过限制？           │          │
│                                              └──────────┬──────────┘          │
│                                                    是   │   否                │
│                                                         │                      │
│                                              ┌──────────┘                      │
│                                              ▼                                 │
│                                    ┌─────────────────────┐                    │
│                                    │ shrink_compressed   │                    │
│                                    │ _context()          │                    │
│                                    │ 逐步裁剪：           │                    │
│                                    │ alert→timeline→edge │                    │
│                                    └─────────────────────┘                    │
│                                                                         │
│                                    输出: mode: compressed                │
└─────────────────────────────────────────────────────────────────────────┘
```

**压缩后的数据结构：**

```json
{
  "summary": {
    "machine_id": "...",
    "incident_uuid": "...",
    "edge_count": 150,
    "alert_edge_count": 12,
    "node_count": 80
  },
  "skeleton": {
    "nodes": [{"id": "...", "type": "...", "name": "...", "is_alert": false}],
    "edges": [{"from": "...", "to": "...", "class_name": "...", "is_alert": true}]
  },
  "alert_edge_details": [...],  // 告警边详情（最多 alert_detail_limit 条）
  "timeline": [...]             // 时间排序的事件流（最多 80 条）
}
```

### 3. prompting.py - Prompt 构建

生成包含任务指令、图数据和输出 Schema 的用户 Prompt：

```
用户 Prompt 结构：
├─ 角色设定（安全专家）
├─ 输出要求（纯 JSON、无 markdown 包裹）
├─ 运行模式 + 统计信息
├─ 任务指令
├─ 输出 Schema (REPORT_SCHEMA)
└─ 溯源图数据
```

### 4. schema.py - 报告 Schema

定义 LLM 输出的 JSON 结构：

```
REPORT_SCHEMA
├─ metadata
│   ├─ machine_id
│   └─ insight_id
└─ report_data
    ├─ title
    ├─ date
    └─ sections
        ├─ event_summary          # 事件摘要
        │   ├─ event_brief
        │   ├─ threat_level
        │   ├─ initial_access_method
        │   ├─ initial_access_evidence
        │   └─ event_purpose
        ├─ attack_timeline[]      # 攻击时间线
        ├─ attack_graph           # Mermaid 流程图
        └─ future_behavior[]      # 行为预测
    └─ appendix
        └─ iocs[]                 # 入侵指标
```

### 5. reporting.py - 报告生成

支持三种报告生成模式：

| 函数 | 用途 |
|------|------|
| `json_to_markdown()` | 正常模式：JSON → 格式化 Markdown |
| `build_fallback_markdown()` | 降级模式：LLM 输出不可解析时，基于原始图生成基础报告 |
| `build_error_markdown()` | 错误模式：读取溯源图失败时的错误报告 |

**Markdown 报告结构：**

```markdown
# {title}
**生成日期:** {date}
**机器ID:** {machine_id}
**事件ID:** {insight_id}

## 1. 事件摘要
## 2. 攻击时间线
## 3. 攻击流程图 (Mermaid)
## 4. 行为预测
## 附录：入侵指标 (IOCs)
```

### 6. parsing.py - LLM 输出解析

从 LLM 输出中提取 JSON 对象：

```
解析策略：
1. 尝试提取 ```json ... ``` 代码块
2. 尝试提取 ``` ... ``` 代码块（验证是否为 JSON 对象）
3. 从文本中提取第一个完整的 JSON 对象（处理嵌套大括号）
```

### 7. helpers.py - 工具函数

提供图数据处理的辅助函数：

| 函数 | 说明 |
|------|------|
| `extract_edges()` | 从图中提取边列表 |
| `is_alert_edge()` | 判断边是否为告警边 |
| `node_label()` / `node_id()` | 提取节点标签/ID |
| `skeleton_node()` | 生成精简节点信息 |
| `class_to_tactic()` / `class_to_mitre()` | 类名映射到战术/MITRE |
| `normalize_ioc_type()` | 标准化 IOC 类型（IP/域名/URL/哈希/路径） |

## 数据流

```
┌─────────────────────────────────────────────────────────────────────┐
│                           完整数据流                                 │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌──────────────┐     ┌──────────────┐     ┌──────────────┐         │
│  │ source_graph │ ──► │ graph.py     │ ──► │ prompting.py │         │
│  │ .json        │     │ 预处理/压缩   │     │ 构建 Prompt  │         │
│  └──────────────┘     └──────────────┘     └──────────────┘         │
│                                                    │                 │
│                                                    ▼                 │
│                                            ┌──────────────┐         │
│                                            │ LLM API      │         │
│                                            │ (OpenAI 兼容) │         │
│                                            └──────────────┘         │
│                                                    │                 │
│                                                    ▼                 │
│  ┌──────────────┐     ┌──────────────┐     ┌──────────────┐         │
│  │ report.md    │ ◄── │ reporting.py │ ◄── │ parsing.py   │         │
│  │ report.json  │     │ 生成报告      │     │ 解析 JSON    │         │
│  └──────────────┘     └──────────────┘     └──────────────┘         │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

## 安装与使用

### 安装

```bash
cd PGT-Agent
uv pip install -e .
```

### Harbor 配置

```yaml
# configs/pgt-agent.yaml
agents:
  - name: pgt-agent
    import_path: pgt_agent:PGTAgent
    model_name: glm-4.7  # 或其他 OpenAI 兼容模型

environment:
  type: docker
  env:
    OPENAI_API_KEY: ${OPENAI_API_KEY}
    OPENAI_BASE_URL: ${OPENAI_BASE_URL:-https://open.bigmodel.cn/api/paas/v4}

datasets:
  - path: benchmark/your-dataset
```

### 运行

```bash
harbor run --config configs/pgt-agent.yaml
```

## 环境变量

| 变量 | 必需 | 说明 |
|------|------|------|
| `OPENAI_API_KEY` | 是 | LLM API 密钥 |
| `OPENAI_BASE_URL` | 否 | API 端点（默认 OpenAI，可配置智谱等） |

## 输出产物

Agent 运行后生成以下文件：

| 文件 | 路径 | 说明 |
|------|------|------|
| Markdown 报告 | `/logs/artifacts/report.md` | 人类可读的安全分析报告 |
| JSON 报告 | `/logs/artifacts/report.json` | 结构化报告数据 |
| 原始输出 | `/logs/artifacts/report.raw.txt` | LLM 原始输出（用于调试） |

## 依赖

- `harbor>=0.1.45` - Agent 框架
- `openai>=1.0.0` - LLM API 客户端
