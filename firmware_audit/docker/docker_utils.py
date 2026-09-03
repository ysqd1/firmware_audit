"""Docker 调用封装。

宿主机只跑 Python,binwalk/ghidra 走容器。
"""
from __future__ import annotations

import subprocess
from pathlib import Path


def to_docker_path(host_path: Path | str) -> str:
    """Windows 路径转 Docker 挂载用的路径(正斜杠)。"""
    p = str(host_path).replace("\\", "/")
    # 去掉 Windows 盘符冒号问题:D:/foo -> 保持(Docker Desktop 接受 D:/foo)
    return p


def run_docker(
    image: str,
    args: list[str],
    mounts: list[tuple[Path, str] | tuple[Path, str, str]] | None = None,
    entrypoint: str | None = None,
    workdir: str | None = None,
    timeout: int = 3600,
    env: dict[str, str] | None = None,
    network: str | None = None,
) -> tuple[int, str, str]:
    """运行 Docker 容器,返回 (returncode, stdout, stderr)。

    Args:
        image: 镜像名(如 "binwalk")
        args: 传给容器命令的参数列表
        mounts: [(宿主路径, 容器内路径[, "ro"|"rw"]), ...];第三段缺省 rw
                (Step4 Ghidra 要写 output 目录,默认必须可写)
        entrypoint: 覆盖镜像 entrypoint(如 "bash")
        workdir: 容器内工作目录
        timeout: 超时秒数
        env: 追加容器环境变量(如 {"BINWALK_RM_EXTRACTION_SYMLINK": "1"})
        network: Docker 网络模式(如 "none" 断网);None 用默认 bridge。
                Step5 Agent 工具一律 none(签名扫描/本地规则/沙箱复核均不需外网,
                cve_bin_tool_scan 的 CVE 库由 .cve_cache 卷预热 + --offline 维护)。

    失败不抛异常,返回非零退出码 + stderr,由调用方决定降级。
    """
    cmd = ["docker", "run", "--rm"]

    if entrypoint:
        cmd += ["--entrypoint", entrypoint]
    if workdir:
        cmd += ["-w", workdir]
    if network:
        cmd += ["--network", network]
    for k, v in (env or {}).items():
        cmd += ["-e", f"{k}={v}"]

    for mount in (mounts or []):
        host, container = mount[0], mount[1]
        mode = mount[2] if len(mount) > 2 else "rw"
        cmd += ["-v", f"{to_docker_path(host)}:{container}:{mode}"]

    cmd.append(image)
    cmd += args

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",   # 显式 utf-8:Windows 下 text=True 默认用 locale(gbk)
            errors="replace",   # 非法字节降级 U+FFFD,防 readerthread 崩溃/stdout=None
            timeout=timeout,
        )
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired as e:
        # 失败不抛异常(契约见 docstring): 超时返回 124(与 timeout 命令一致),
        # 调用方据此降级(Step3 classify 无 try 包裹,必须由 run_docker 兜底)。
        return 124, "", f"docker run timed out after {timeout}s: {e}"


def _ensure_tag(image: str) -> str:
    """镜像名补默认 tag。

    `docker image inspect <name>` 对无 tag 的镜像名(如 `binwalk`)解析失败
    ("No such image"),必须补 `:latest` 才能命中。`docker run <name>` 会自动
    默认 latest,但 inspect 不会——实测 binwalk/ghidra 均受影响。带 registry
    前缀(deepaudit/sandbox)或已带 tag 的不动。
    """
    if "/" in image:
        # 可能是 registry/name 或 name:tag,只需处理最后一段
        last = image.rsplit("/", 1)[-1]
        if ":" in last:
            return image
        return image + ":latest"
    if ":" in image:
        return image
    return image + ":latest"


def docker_available(image: str) -> bool:
    """检查 Docker 是否可用且指定镜像存在。

    用 `docker image inspect` 而非 `docker run --version`,
    因为不同镜像 entrypoint 不同(binwalk 接受 --version,
    ghidra 的 analyzeHeadless 不接受),统一用 inspect 最可靠。

    注意:inspect 对无 tag 镜像名会失败,必须先补 `:latest`(_ensure_tag)。
    """
    try:
        proc = subprocess.run(
            ["docker", "image", "inspect", _ensure_tag(image)],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
        )
        return proc.returncode == 0
    except Exception:
        return False
