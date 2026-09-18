"""engine:Agent 执行引擎的 L3 直接支撑层(ADR-0012 公开切换后)。

自包含包:protocol(ReAct 纯函数解析)+ context(四分区上下文与压缩)
+ transcript(落盘)+ display(终端监控)。Host 的逐步 Agent Session 消费
context/transcript;protocol 由 display 的思考行渲染复用。不依赖
data/providers,包内互相只走相对导入。
"""
from .context import ContextManager
from .transcript import Transcript

__all__ = ["ContextManager", "Transcript"]
