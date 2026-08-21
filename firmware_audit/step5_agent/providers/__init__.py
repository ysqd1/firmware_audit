"""providers:外部资源接入层(引擎鸭子类型消费的能力提供方)。

llm_client:LLM API 客户端(OpenAI 兼容,含重试;测试替身 ScriptedLLM 在 test/scripted_llm.py)
tools/:Agent 工具注册表(读盘/沙箱 CLI/API 三类,make_tools 统一装配)
"""
