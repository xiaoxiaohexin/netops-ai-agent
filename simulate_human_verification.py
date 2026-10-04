import os
import sys
import logging

# 配置详细的日志输出，以便直观看到图引擎内部在干什么
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)-7s] [%(funcName)s] %(message)s",
    datefmt="%H:%M:%S"
)

sys.path.insert(0, r"e:\netops-ai-agent\langgraph_netagent")

from langgraph_netagent.tools.nic_adapter import LiveNICAdapter
from langgraph_netagent.llm.providers.mock_provider import MockLLMProvider
from langgraph_netagent.workflow.day2_graph import build_day2_graph
from langgraph_netagent.workflow.day2_state import create_day2_initial_state
from langgraph.checkpoint.memory import MemorySaver

def simulate_hitl_verification():
    print("================================================================")
    print("   [启动] WLAN 物理网卡全链路诊断与 [人机验证] 深度测试   ")
    print("================================================================\n")
    
    print(">>> [步骤 1] 挂载宿主机 WLAN 真实无线网卡...")
    adapter = LiveNICAdapter(interface_name="WLAN")
    
    print(">>> [步骤 2] 注入 Mock 大模型与 LangGraph 记忆节点...")
    llm = MockLLMProvider()
    checkpointer = MemorySaver()
    
    print(">>> [步骤 3] 编译带有 [断点拦截] 机制的诊断图谱 (auto_approve=False)...\n")
    import warnings
    warnings.filterwarnings("ignore", category=DeprecationWarning)
    
    app = build_day2_graph(
        llm_provider=llm,
        lab_adapter=adapter,
        checkpointer=checkpointer,
        auto_approve=False
    )
    
    config = {"configurable": {"thread_id": "simulation-wlan-session-003"}}
    initial_state = create_day2_initial_state(auto_approve=False)
    
    print("=================== [解析] 第一阶段：开始图引擎诊断 ===================")
    
    # Run the graph until the interruption point
    paused_state = app.invoke(initial_state, config=config)
    status = paused_state.get("status")
    
    print(f"\n=================== [拦截] 图引擎运行中断 ===================")
    print(f"当前流转状态: '{status}'")
    
    if status == "healthy":
        print("\n[通过] [最终结论]: 遥测数据正常，网络处于健康基线，无故障无需生成补丁，安全拦截节点自动放行。验证完成！")
        return
        
    if status == "pending_approval":
        print("\n>>> 第二阶段：模拟人工专家 [安全审核] 操作...")
        print("-> [系统拦截] 检测到高危修复补丁，等待人类工程师下发指令。")
        print("-> [人工确认] 检查补丁无害 (模拟动作: APPROVE)。")
        
        print("\n>>> 第三阶段：将审核结果写入记忆节点，放行图谱...")
        checkpoint = checkpointer.get(config)
        cp_state = checkpoint.get("channel_values", checkpoint) if isinstance(checkpoint, dict) else getattr(checkpoint, "channel_values", checkpoint)
        
        if isinstance(cp_state, dict):
            cp_state["human_approved"] = True
        else:
            setattr(cp_state, "human_approved", True)
            
        print("\n=================== [启动] 恢复图引擎运行 ===================")
        final_state = app.invoke(None, config=config)
        
        final_status = final_state.get("status")
        print(f"\n[通过] [最终结论]: 补丁下发完毕，自愈流转成功，最终网络状态为: '{final_status}'")
    else:
        print(f"\n[失败] [异常状态]: {status}")

if __name__ == "__main__":
    simulate_hitl_verification()
