# NetOps AI Agent

自然语言驱动的网络运维智能体：自动完成「拓扑设计 → 离线预检 → Containerlab 部署 → 探测验证 → 故障自愈」闭环，全部通过命令行与本地 Containerlab 交互。

## 仓库结构

```
netops-ai-agent/
├── langgraph_netagent/     Python 核心（pip install -e . 可编辑安装）
│   ├── langgraph_netagent/
│   │   ├── cli.py           netagent 命令行入口
│   │   ├── workflow/        LangGraph 8 节点状态机
│   │   ├── models/         Pydantic v2 契约
│   │   ├── prompts/        4 个生产 system prompt
│   │   ├── llm/            provider：mock / ollama / qwen / vllm
│   │   ├── tools/          Containerlab 适配器、故障注入、探针、导出器
│   │   └── data/           SFT 微调数据集
│   └── tests/               453 个测试
├── docs/                   设计与架构文档
└── README.md
```

## 快速开始

```bash
cd langgraph_netagent
pip install -e .
netagent --mode mock --intent "Connect pc1 and pc2 via frr1 with static routing" --output-dir ./my_lab
```

- `--mode mock`：零 Docker 模拟器（默认，CI/快速验证用）
- `--mode live`：真实 Containerlab
- `--provider mock|qwen|openai|vllm|ollama`：LLM 后端

退出码：`0`=探测通过 / `1`=被预检或人工拒绝 / `2`=熔断器动作。

## 工作流

`intent_parsing → topology_generation → offline_validation → human_approval → deployment → verification_probing → diagnosis_and_healing → circuit_breaker`

含两条回退边：预检/人工拒绝回到拓扑生成；探测失败进入自愈后回部署重跑；连续自愈失败触发熔断。

## 技术栈

- **Agent 编排**：LangGraph（双模式：官方库 / 自研 SimpleStateGraph 回退）
- **LLM**：Qwen 系列微调（SFT 数据见 `langgraph_netagent/data/`），兼容 Ollama / vLLM
- **网络实验**：Containerlab（FRRouting / Nokia SR Linux / Alpine）
