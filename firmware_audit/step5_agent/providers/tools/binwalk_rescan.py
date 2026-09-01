"""binwalk_rescan:对不透明 .bin/固件段做 binwalk 签名复扫(仅识别,不落盘解包)。

recon 用它对 unknown 裸二进制按需重扫:确认内部是否藏 squashfs/cpio/gzip 等
嵌套容器。只跑签名识别(binwalk <file> 不写盘,extracted 只读挂载下安全),
深层解包仍归 Step1 管线,Agent 不重复做解包。

直接用 binwalk 专用镜像(2026-08-18 实测定案,两条弯路都不通):
  - sandbox pip 装 binwalk:PyPI 是停更的 2.1.0,Python 3.11 import 即崩
  - 跨镜像复制 v3 Rust 二进制:需 GLIBC 2.39,sandbox 基座 bullseye 只有 2.31
"""
from __future__ import annotations

from ....docker.docker_utils import docker_available, run_docker
from .base import AgentTool, ToolResult, resolve_within
from .cli_base import extracted_root

BINWALK_IMAGE = "binwalk"
_MOUNT = "/analysis"


class BinwalkRescanTool(AgentTool):
    name = "binwalk_rescan"
    description = ("对不透明二进制(.bin/固件段)做 binwalk 签名复扫,识别内部嵌套容器"
                   "(squashfs/cpio/gzip 等)。只识别不落盘;深层解包由 Step1 管线负责。")
    params = {
        "file_ref": {"type": "str", "required": True, "desc": "相对 extracted 根的二进制路径"},
    }

    def _run(self, file_ref: str) -> ToolResult:
        if not docker_available(BINWALK_IMAGE):
            return ToolResult(ok=False, text="",
                              error=f"binwalk 镜像不可用: {BINWALK_IMAGE}")
        root = extracted_root(self.ctx).resolve()
        ref = file_ref.strip().replace("\\", "/")
        # 防路径穿越:解析后必须仍在 extracted 根内(None 由 .strip() 抛,execute 兜底;
        # 空串按越界拒绝——C4 起,原行为是放行到 extracted 根,收敛为拒绝)
        if resolve_within(root, ref) is None:
            return ToolResult(ok=False, text="", error=f"非法路径: {file_ref}")
        rc, out, err = run_docker(
            BINWALK_IMAGE, [f"{_MOUNT}/{ref}"],
            mounts=[(root, _MOUNT, "ro")], entrypoint="binwalk",
            timeout=300, network="none",
        )
        if rc != 0:
            return ToolResult(ok=False, text="",
                              error=f"binwalk 失败(码 {rc}): {(err or out).strip()[:300]}")
        summary = out.strip()
        if not summary:
            return ToolResult(ok=True, text=f"{file_ref}: binwalk 无签名命中", data=[])
        return ToolResult(ok=True,
                          text=f"{file_ref} 签名复扫:\n" + "\n".join(summary.splitlines()[:40]),
                          data={"image": BINWALK_IMAGE, "output": summary[:8000]})
