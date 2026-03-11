# PGT-Agent - 溯源图智能分析 Agent

## 项目愿景

打造一个像 **Claude-Code/Codex** 那样的智能 Agent：
- **自主思考决策** → **调用工具** → **获取结果** → **再思考再行动** → **输出结果**

```
┌─────────────────────────────────────────────────────────────────┐
│                    理想 Agent 架构                                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────┐     ┌───────────┐     ┌─────────────────┐              │
│  │  Brain      │────▶│  Skills  │────▶│   Memory        │              │
│  │  (ReAct +    │     │  (Tools) │     │   (RAG)         │              │
│ │  Reflection) │     │          │     │                 │              │
│  └─────────────┘     └───────────┘     └─────────────────┘              │
│         │                   │                    │                   │
│         │                   ▼                    ▼                   │
│         │            ┌─────────┐           ┌───────────┐               │
│         └───────────▶│  LLM    │◀───────────│  知识库   │               │
│                      └──────────           └───────────┘               │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## 一、你的 LangGraph StateGraph 多节点架构详解

### 1.1 完整流程图

```
compress → derive_context → rag → build_prompt → react → extract → validate → reflect
    │                                                                                 │
    │                                                                                 └───────► (验证失败/反思不满)
    │                                                                                         │
    └─────────────────────────────────────────────────────────────────────────┘
```

### 1.2 各节点作用详解

| 节点 | 输入 | 输出 | 作用 |
|------|------|------|------|
| **compress** | raw_graph | compressed_graph, graph_json | 图压缩：将大图压缩到 LLM 可处理大小 |
| **derive_context** | graph_json | derived_context | 派生上下文：提取拓扑统计、IOC、关键边 |
| **rag** | derived_context | rag_context | RAG检索：从知识库查询相关案例 |
| **build_prompt** | graph_json, rag_context, reflections | messages | 构建Prompt：组装系统提示词+用户提示词 |
| **react** | messages | report_raw | ReAct循环：LLM思考+工具调用，生成报告 |
| **extract** | report_raw | report | JSON提取：从LLM输出中解析结构化报告 |
| **validate** | report, compressed_graph | validation | 规则校验：检查报告完整性、证据索引 |
| **reflect** | report, validation | review, reflections | 反思评估：Critic检查质量，决定是否返工 |

### 1.3 核心设计理念

**多轮迭代质量保证**：

```python
# 伪代码示意
for attempt in range(max_attempts):
    # 1. 构建提示词（包含历史反思）
    prompt = build_prompt(
        graph=compressed_graph,
        rag_context=knowledge_base_search(),
        reflections=previous_reflections  # 关键！
    )

    # 2. LLM 生成报告
    report = llm_generate(prompt)

    # 3. 规则校验
    validation = validate_report(report, graph)

    # 4. Critic 反思
    review = critic_validate(report, validation)

    # 5. 判断是否合格
    if validation.ok and review.verdict == "pass":
        return report  # 成功退出
    else:
        reflections.append(review.reflection)  # 记录问题
        continue  # 进入下一轮迭代
```

---

## 二、与当前 PGT-Agent 的对比

### 2.1 当前架构（简化版）

```
┌──────────────────────────────────────────────┐
│            当前 PGT-Agent                    │
├──────────────────────────────────────────────┤
│                                              │
│  raw_graph → compress → LLM (单次) → report   │
│                                              │
│  ❌ 无 ReAct 循环                            │
│  ❌ 无 Reflection 质量控制                   │
│  ❌ 无 Skills 工具调用                      │
│  ❌ 无 RAG 知识增强                         │
│                                              │
└──────────────────────────────────────────────┘
```

### 2.2 差距分析

| 维度 | LangGraph Agent | 当前 PGT-Agent | 优先级 |
|------|-----------------|----------------|--------|
| **多轮思考** | ✅ ReAct循环 | ❌ 单次调用 | P0 |
| **质量保证** | ✅ validate + reflect | ❌ 无验证 | P0 |
| **工具能力** | ✅ 工具调用 | ❌ 无工具 | P1 |
| **图压缩** | ✅ compress + slim | ✅ 已实现 | ✓ |
| **IOC提取** | ✅ extract_graph_iocs | ❌ 无 | P1 |
| **知识增强** | ✅ RAG | ❌ 无 | P2 |

---

## 三、实现计划（渐进式）

### 阶段 1：ReAct + Reflection 核心框架 (P0)

**目标**：实现多轮迭代和质量闭环

```python
# 新增核心流程
async def run(self, instruction, environment, context):
    # 1. 压缩图（已有）
    compressed = prepare_graph_payload(raw_graph)

    for attempt in range(max_attempts):
        # 2. 构建提示词
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": build_user_prompt(compressed, reflections)}
        ]

        # 3. LLM 调用
        report_raw = await llm_call(messages)

        # 4. 解析报告
        report = parse_json(report_raw)

        # 5. 规则校验
        validation = validate_report(report, compressed)

        # 6. Critic 反思
        review = await reflect_critic(report, validation)

        # 7. 判断是否继续
        if should_stop(validation, review, attempt):
            return report  # 成功退出

        # 8. 记录反思，准备下一轮
        reflections.append(review["reflection"])
```

**代码结构**：

```
src/pgt_agent/
├── agent.py              # 主控制器
├── brain/
│   ├── prompts.py        # 系统提示词
│   ├── validator.py      # 规则校验
│   └── reflector.py      # Critic 反思
└── pgt_agent_impl/
    ├── graph.py          # 图压缩（已有）
    └── schema.py         # 报告 Schema（已有）
```

**Prompt 原则**：
- `REACT_SYSTEM_PROMPT` → 作为 `system_prompt`，定义角色和 SOP
- `CRITIC_SYSTEM_PROMPT` → 反思环节的 system_prompt
- 用户 prompt 保持现有结构，不影响任务输出

### 阶段 2：Skills 工具模块 (P1)

**目标**：增强分析能力

```
skills/
├── graph/
│   ├── compress.py      # 图压缩（已有）
│   └── extractor.py     # IOC提取、上下文派生
├── tools/
│   └── semantic.py      # 语义翻译工具
└── ttps/
    └── mitre.py          # ATT&CK 映射
```

### 阶段 3：Memory RAG 模块 (P2)

```
memory/
├── rag.py              # RAG 检索
└── knowledge_base/    # 本地知识库文档
```

---

## 四、关键设计决策

### 4.1 Prompt 策略

| Prompt 类型 | 来源 | 用途 |
|-------------|------|------|
| `REACT_SYSTEM_PROMPT` | brain/prompts.py | LLM system_prompt，定义角色+SOP |
| `CRITIC_SYSTEM_PROMPT` | brain/prompts.py | 反思环节的 system_prompt |
| 用户提示词 | 当前实现 | 保持不变，确保任务输出一致 |

**迁移原则**：
- 系统提示词 → 增强 Agent 能力，不改变任务格式
- 用户提示词 → 保持现有结构，确保向后兼容

### 4.2 Harbor 兼容性

**约束**：
- 必须继承 `harbor.agents.base.BaseAgent`
- 必须实现 `async def run()` 接口
- 输出到 `/logs/artifacts/report.md` 和 `report.json`

**实现策略**：
- 在 `run()` 内部实现 ReAct 循环
- 外部接口保持单次调用形式

### 4.3 迭代控制

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `max_attempts` | 2 | 最大迭代次数 |
| `validation_threshold` | 0.6 | 校验通过阈值 |
| `reflection_enabled` | True | 是否启用反思 |

---

## 五、迁移检查清单

### 阶段 1（ReAct + Reflection）✅ 已完成

- [x] 创建 `brain/prompts.py` - 迁移 REACT/CRITIC 提示词
- [x] 创建 `brain/validator.py` - 报告校验逻辑
- [x] 创建 `brain/reflector.py` - Critic 反思逻辑
- [x] 修改 `agent.py` - 实现多轮循环
- [x] 更新 `schema.py` - 确保 validation/reflection 兼容
- [x] 删除旧的 `pgt_agent_impl/prompting.py`
- [x] 代码格式化和检查通过

### 阶段 2（Skills）

- [ ] 创建 `skills/extractor.py` - IOC 提取
- [ ] 创建 `skills/context.py` - 上下文派生
- [ ] 添加工具调用接口（可选）

### 阶段 3（RAG）

- [ ] 创建 `memory/rag.py` - RAG 检索
- [ ] 创建 `memory/knowledge_base/` - 知识库目录
- [ ] 添加相似案例检索

---

## 六、开发命令

```bash
# 安装开发依赖
cd /Users/w1nd/Desktop/agent/1pgt/PGT-Agent
uv pip install -e .

# 运行测试
python -m pytest tests/ -v

# 格式化代码
ruff format .
ruff check --fix .
```

---

## 七、参考资源

- **LangGraph Agent**：`/Users/w1nd/Desktop/agent/tdir/deep_insight_agent`
- **Harbor Framework**：`/Users/w1nd/Desktop/agent/benchmark-ref/harbor`
- **Harbor Runtime**：`/Users/w1nd/Desktop/agent/1pgt/AGENTS.md`

---

## 八、当前状态

**版本**：0.2.0
**架构**：ReAct + Reflection 多轮迭代
**阶段1状态**：✅ 已完成

**已完成功能**：
- ✅ 多轮 ReAct 循环（max_attempts 可配置）
- ✅ Critic 反思质量控制
- ✅ 规则校验器（validate_report）
- ✅ 环境变量控制（MAX_ATTEMPTS, REFLECTION_ENABLED）

**下一步**：阶段 2 - Skills 工具模块（可选，待定）
