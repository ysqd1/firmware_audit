"""list_files:枚举 process/ 下文件与目录(路径白名单防越界)。

参考 deepaudit 的 ListFilesTool(file_tool.py:参数 directory/pattern/
recursive/max_files + 项目根越界检查 + 排除目录 + 截断提示),按
firmware_audit 工具层约定改造:
- 白名单根 = process/(与 read_file 同根,复用 resolve + parents 判定)
- recursive 时自动排除 SDK/系统库目录(与 Step2 过滤口径一致),
  避免 LLM 在 extracted 全量树上撞 SDK 噪音
- 超出 max_files 截断并提示省略数与可下钻路径(失败不崩,给 LLM 换路)
"""
from __future__ import annotations

from pathlib import Path

from .base import AgentTool, ToolResult

# 与 Step2/概览口径一致:这些目录下的文件已按低价值剔除,枚举时跳过
DEFAULT_EXCLUDE_DIRS = {
    "usr/lib", "usr/local/lib", "usr/share", "lib", "opt",
    ".git", "__pycache__", "node_modules", ".pytest_cache",
}

DEFAULT_MAX_FILES = 100


class ListFilesTool(AgentTool):
    name = "list_files"
    description = ("列出 process/ 下的文件与目录(默认 100 条上限,目录项带 / 后缀)。"
                   "铺面首选工具:先用 directory='.' 看顶层,再按目录下钻;"
                   "recursive=True 递归(自动排除 SDK/系统库),pattern 过滤文件名。")
    params_doc = ('{"directory": ".", "pattern": "*.py", "recursive": false, '
                  '"max_files": 100} —— directory 相对 process/;pattern 可选; '
                  'recursive 可选;max_files 可选')

    def _run(self, directory: str = ".", pattern: str = "",
             recursive: bool = False, max_files: int = DEFAULT_MAX_FILES,
             **kw) -> ToolResult:
        # path 别名(deepaudit 兼容:LLM 偶发把 directory 写成 path)
        if "path" in kw and kw["path"]:
            directory = str(kw["path"])
        root = self.ctx.process_dir.resolve()
        try:
            n = max(1, int(max_files))
        except (TypeError, ValueError):
            n = DEFAULT_MAX_FILES
        ref = str(directory or ".").replace("\\", "/")
        target = (root / ref).resolve() if ref not in (".", "") else root
        if target != root and root not in target.parents:
            return ToolResult(ok=False, text="", error=f"路径越界: {directory}(只允许 process/ 之下)")
        if not target.exists():
            return ToolResult(ok=False, text="", error=f"目录不存在: {directory}")
        if not target.is_dir():
            return ToolResult(ok=False, text="", error=f"不是目录: {directory}")

        entries, truncated = self._collect(root, target, pattern, recursive, n)
        lines = [f"[{ref if ref not in ('.', '') else '.'} 列出 {len(entries)} 项(上限 {n})]"]
        lines += entries
        text = "\n".join(lines)
        if truncated:
            text += ("\n...(已达上限被截断,可用更具体的 directory 缩小范围,"
                     "或提高 max_files/用 pattern 过滤)")
        return ToolResult(ok=True, text=text, data={"count": len(entries), "truncated": truncated})

    def _collect(self, root: Path, target: Path, pattern: str,
                 recursive: bool, max_files: int) -> tuple[list[str], bool]:
        """枚举 target;返回 (相对路径行列表, 是否截断)。目录项带 / 后缀。

        recursive 时按"路径前缀"排除 SDK/系统库:排除集条目是路径式的
        (如 usr/lib),目录的相对路径(去尾斜杠)等于条目、或以
        "条目/" 开头(usr/lib/x86_64)均跳过下钻。
        """
        from fnmatch import fnmatch

        def _excluded(rel_dir: str) -> bool:
            r = rel_dir.rstrip("/")
            return r in DEFAULT_EXCLUDE_DIRS or any(
                r.startswith(e + "/") for e in DEFAULT_EXCLUDE_DIRS)

        out: list[str] = []
        truncated = False
        # 顶层目录项总是先列(即使非 recursive),给 LLM 下钻地图
        subdirs = sorted(d for d in target.iterdir() if d.is_dir())
        files = sorted(f for f in target.iterdir() if f.is_file())
        for d in subdirs:
            if len(out) >= max_files:
                truncated = True
                return out, truncated
            rel = d.relative_to(root).as_posix() + "/"
            out.append(rel)
            if recursive and not _excluded(rel):
                sub, trunc = self._collect(root, d, pattern, recursive,
                                           max_files - len(out))
                out += sub
                if trunc:
                    truncated = True
                    return out, truncated
        for f in files:
            if len(out) >= max_files:
                truncated = True
                return out, truncated
            if pattern and not fnmatch(f.name, pattern):
                continue
            out.append(f.relative_to(root).as_posix())
        return out, truncated
