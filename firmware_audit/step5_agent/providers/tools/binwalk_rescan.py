"""binwalk_rescan:对不透明 .bin/固件段做 binwalk 签名复扫(仅识别,不落盘解包)。

recon 用它对 unknown 裸二进制按需重扫:确认内部是否藏 squashfs/cpio/gzip 等
嵌套容器。只跑签名识别(binwalk <file> 不写盘,extracted 只读挂载下安全),
深层解包仍归 Step1 管线,Agent 不重复做解包。

直接用 binwalk 专用镜像(2026-08-18 实测定案,两条弯路都不通):
  - sandbox pip 装 binwalk:PyPI 是停更的 2.1.0,Python 3.11 import 即崩
  - 跨镜像复制 v3 Rust 二进制:需 GLIBC 2.39,sandbox 基座 bullseye 只有 2.31

幽灵扫描坑(2026-09-10 target/4 e2e 实测,票02):binwalk v3 对打不开的
目标退出码仍为 0,失败详情只打 stderr("Failed to open/read")——只看
退出码会对"没发生过的扫描"回喂 ok=True"0 命中"假观察。两层防御:
宿主侧预检目标必须真实存在(零容器调用);stderr 含打开/读取失败标记时
无视 rc 一律判失败。
"""
from __future__ import annotations

from ....docker.docker_utils import docker_available, run_docker
from .base import AgentTool, ToolResult, resolve_within
from .cli_base import extracted_root

BINWALK_IMAGE = "binwalk"
_MOUNT = "/analysis"
# v3 打不开目标时的 stderr 失败标记(实测 "Failed to open/read";小写包含
# 匹配,容忍大小写变体)
_OPEN_READ_FAIL_MARKERS = ("failed to open", "failed to read")


class BinwalkRescanTool(AgentTool):
    name = "binwalk_rescan"
    description = ("对不透明二进制(.bin/固件段)做 binwalk 签名复扫,识别内部嵌套容器"
                   "(squashfs/cpio/gzip 等)。只识别不落盘;深层解包由 Step1 管线负责。")
    params = {
        "file_ref": {"type": "str", "required": True, "desc": "相对 extracted 根的二进制路径"},
    }

    def _run(self, file_ref: str) -> ToolResult:
        root = extracted_root(self.ctx).resolve()
        ref = file_ref.strip().replace("\\", "/")
        # 防路径穿越:解析后必须仍在 extracted 根内(None 由 .strip() 抛,execute 兜底;
        # 空串按越界拒绝——C4 起,原行为是放行到 extracted 根,收敛为拒绝)
        cand = resolve_within(root, ref)
        if cand is None:
            return ToolResult(ok=False, text="", error=f"非法路径: {file_ref}")
        # 幽灵扫描预检(票02):目标必须真实存在于解包树,否则 binwalk v3 会
        # "静默成功"(rc=0 + stderr 报错,见模块注释)——宿主侧拦截,零容器调用;
        # 目录/非常规文件同样不付容器(那是误用,不是扫描对象)
        if not cand.is_file():
            what = "不是常规文件" if cand.exists() else "文件不在解包树"
            return ToolResult(
                ok=False, text="",
                error=(f"{what}: {file_ref}(binwalk 未执行;"
                       f"用 list_files 确认实际路径)"))
        if not docker_available(BINWALK_IMAGE):
            return ToolResult(ok=False, text="",
                              error=f"binwalk 镜像不可用: {BINWALK_IMAGE}")
        rc, out, err = run_docker(
            BINWALK_IMAGE, [f"{_MOUNT}/{ref}"],
            mounts=[(root, _MOUNT, "ro")], entrypoint="binwalk",
            timeout=300, network="none",
        )
        if rc != 0:
            return ToolResult(ok=False, text="",
                              error=f"binwalk 失败(码 {rc}): {(err or out).strip()[:300]}")
        # v3 幽灵扫描(见模块注释):打不开目标时 rc 仍为 0,失败只打 stderr——
        # 含打开/读取失败标记一律判失败并如实回喂,不产"扫了 0 命中"假象
        err_text = (err or "").strip()
        if any(m in err_text.lower() for m in _OPEN_READ_FAIL_MARKERS):
            return ToolResult(ok=False, text="",
                              error=(f"binwalk 打开/读取目标失败"
                                     f"(退出码 {rc} 不可信): {err_text[:300]}"))
        summary = out.strip()
        if not summary:
            return ToolResult(ok=True, text=f"{file_ref}: binwalk 无签名命中", data=[])
        return ToolResult(ok=True,
                          text=f"{file_ref} 签名复扫:\n" + "\n".join(summary.splitlines()[:40]),
                          data={"image": BINWALK_IMAGE, "output": summary[:8000]})
