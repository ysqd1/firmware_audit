"""engine:ReAct 执行引擎(L2 状态机 + L3 直接支撑)。

自包含包:react_loop(状态机)+ protocol(纯函数解析)
+ context(四分区上下文)+ transcript(落盘)。不依赖 data/providers,
被 runner 调用;包内互相只走相对导入。
"""
from .react_loop import ReactResult, run_react_agent

__all__ = ["ReactResult", "run_react_agent"]
