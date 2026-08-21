"""sandbox_verify:verification 阶段的轻量沙箱复核工具(仿 DeepAudit run_code)。

在 firm_audit/sandbox 隔离容器内执行用户提供的复核脚本(Python/Node/PHP),
用于动态验证疑似漏洞(如命令注入的 Fuzzing Harness / 反序列化 PoC 探测),
避免误报。安全约束:
  - 只通过指定解释器运行脚本(python3/node/php -c),不开放任意 shell 命令
  - extracted/ 只读挂载(复核脚本需要读取固件文件时可传 path 挂载单文件)
  - 网络默认隔离(容器内不配桥接),资源受 run_docker 超时限制
"""
from __future__ import annotations

import tempfile
from pathlib import Path

from .base import AgentTool, ToolResult
from .cli_base import run_in_sandbox

# 允许的解释器 -> entrypoint 覆盖(白名单,拒绝任意命令注入)
_INTERPRETERS = {
    "python": "python3",
    "py": "python3",
    "python3": "python3",
    "node": "node",
    "js": "node",
    "javascript": "node",
    "php": "php",
}
MAX_CODE = 64 * 1024  # 复核脚本上限,防 LLM 提交巨型脚本


class SandboxVerifyTool(AgentTool):
    name = "sandbox_verify"
    description = ("在隔离沙箱内执行复核脚本(仅 python/node/php)动态验证疑似漏洞:"
                   "如命令注入的 Fuzzing Harness、反序列化/代码执行 PoC 探测。"
                   "沙箱网络隔离、extracted 只读。用于 verification 判断漏洞是否真实可利用。")
    params_doc = ('Action Input: {"code": "<脚本源码>", "language": "python|node|php", '
                  '"timeout": 60}  —— code 为待执行源码;language 默认 python')

    def _run(self, code: str, language: str = "python", timeout: int = 60) -> ToolResult:
        if not code or not code.strip():
            return ToolResult(ok=False, text="", error="code 不能为空")
        if len(code) > MAX_CODE:
            return ToolResult(ok=False, text="", error=f"复核脚本过大({len(code)} 字节,上限 {MAX_CODE})")
        interp = _INTERPRETERS.get((language or "").lower().strip())
        if interp is None:
            return ToolResult(ok=False, text="", error=f"不支持的 language: {language}(可用 python/node/php)")

        # 脚本写入宿主临时文件,挂载进容器执行(-c 的引号转义在跨平台不可靠)
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / ("v.py" if interp == "python3" else
                              "v.js" if interp == "node" else "v.php")
            src.write_text(code, encoding="utf-8")
            # 若脚本需要读固件文件,把 extracted 只读挂载;否则脚本本身在临时目录
            args = [f"/work/script/{src.name}"]
            rc, out, err = run_in_sandbox(
                args, interp, self.ctx, timeout=min(timeout, 180),
                extra_mounts=[(Path(td), "/work/script")],
            )
        combined = (out + ("\n" + err if err else "")).strip()
        if rc == 0:
            return ToolResult(ok=True, text=combined or "[退出码 0,无输出]", data={"exit_code": rc})
        # 非零退出:可能脚本崩溃返回正常信息,仍回文本让 LLM 判断(附退出码)
        return ToolResult(ok=True,  # 不判失败:脚本运行崩溃也是"证据",交 LLM 归类
                          text=f"[退出码 {rc}]\n{combined or '(无输出)'}",
                          data={"exit_code": rc})