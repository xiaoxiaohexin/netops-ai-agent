# NetOps AI Agent

自然语言驱动的网络运维智能体：自动完成「拓扑设计 → 离线预检 → Containerlab/网卡部署 → 遥测探针 → 两阶段诊断与故障自愈」全生命周期闭环。

---

## 📦 安装方式 (Package & Installation)

本仓库已配置标准 Python 打包规范（PEP 517/518），支持多种便捷安装与分发方式：

### 方式 1: 通过 GitHub 一键在线安装（推荐）

无需手动克隆代码仓库，直接使用 `pip` 即可一键完成库与命令行工具安装：

```bash
pip install git+https://github.com/xiaoxiaohexin/netops-ai-agent.git
```

### 方式 2: 本地克隆或开发者可编辑安装

```bash
git clone https://github.com/xiaoxiaohexin/netops-ai-agent.git
cd netops-ai-agent
pip install -e .
```

### 方式 3: 离线 Wheel 二进制包分发

如果处于离线网络或企业内网，可直接从 Release 下载或本地执行 `python -m build` 构建的 `.whl` 文件：

```bash
pip install dist/netops_ai_agent-0.1.0-py3-none-any.whl
```

---

## 🚀 作为 CLI 命令行工具使用

安装完成后，系统将自动注册全局命令 `netagent`：

```bash
# 1. 启动交互式运维 REPL (支持实时自动识别宿主机网卡与在线资产)
netagent -it

# 2. 模拟器 Mock 极速验证模式
netagent --mode mock --intent "Connect pc1 and pc2 via frr1 with static routing" --output-dir ./my_lab

# 3. 真实环境常态监控模式
netagent --mode live --watch --interval 5
```

- `--mode mock`：零 Docker 模拟器（极速验证与测试用）
- `--mode live`：真实物理/虚拟网络（Containerlab 容器集群 或 宿主机网卡/虚拟机）
- `--provider mock|qwen|openai|vllm|ollama`：大模型后端支持

---

## 🐍 作为 Python 库二次开发

可以在您自己的 Python 项目中直接导入核心组件：

```python
from langgraph_netagent.tools.detector import EnvironmentDetector
from langgraph_netagent.tools.nic_adapter import LiveNICAdapter
from langgraph_netagent.workflow.harmonized_graph import create_harmonized_netops_graph

# 1. 自动探测当前宿主机物理/虚拟网卡与网络资产
detector = EnvironmentDetector()
topologies = detector.detect_available_topologies()
for topo in topologies:
    print(f"[{topo.display_type}] {topo.name}: {topo.summary}")

# 2. 挂载指定网卡（如 VMware VMnet8）进行主动巡检
nic = LiveNICAdapter("VMware Network Adapter VMnet8")
inspection = nic.inspect()
print("在线节点:", [node.name for node in inspection.nodes])
```

---

## 🧪 自动化测试套件

项目内置完备的端到端、故障自愈与对抗鲁棒性自动化测试集（972+ 单元与集成测试用例，100% Pass）：

```bash
cd langgraph_netagent
pytest -q
```
