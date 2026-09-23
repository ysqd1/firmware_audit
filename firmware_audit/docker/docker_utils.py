"""Docker 调用封装。

宿主机只跑 Python,binwalk/ghidra 走容器。
"""
from __future__ import annotations

import json
import os
import selectors
import subprocess
import threading
import time
from pathlib import Path


_DEFAULT_SESSION_PIDS_LIMIT = 128
_DEFAULT_MAX_OUTPUT_BYTES = 1 << 20
_OUTPUT_READ_CHUNK = 64 << 10
_PIPE_DRAIN_SECONDS = 1.0


def _decode_bounded_output(
    payload: bytes, truncated: bool, stream_name: str, limit: int,
    incomplete: bool = False,
) -> str:
    """Decode retained child output and make truncation visible to callers."""
    text = payload.decode("utf-8", errors="replace")
    if truncated:
        text += (f"\n...[{stream_name} output truncated after {limit} bytes; "
                 "the child was drained to avoid blocking]...\n")
    if incomplete:
        text += (f"\n...[{stream_name} output incomplete: pipe did not close "
                 "within the drain deadline]...\n")
    return text


def _stop_process(proc: subprocess.Popen) -> None:
    """Kill and reap a child, including when the caller is being interrupted."""
    try:
        proc.kill()
    except OSError:
        pass
    try:
        proc.wait(timeout=1)
    except BaseException:
        # A second wait handles a test seam or platform that interrupts the first
        # wait; failure to reap is still bounded and the original exception wins.
        try:
            proc.wait(timeout=1)
        except BaseException:
            pass


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
    user: str | None = None,
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
        user: --user 透传(如宿主 "1000:1000")。容器写挂载的产物随之归宿主
              用户——WSL 下容器默认 root,写出的文件 root:root 0640,宿主
              读回 Permission denied(Windows 文件层无此语义,Step4 实测)。

    失败不抛异常,返回非零退出码 + stderr,由调用方决定降级。
    """
    cmd = ["docker", "run", "--rm"]

    if entrypoint:
        cmd += ["--entrypoint", entrypoint]
    if workdir:
        cmd += ["-w", workdir]
    if network:
        cmd += ["--network", network]
    if user:
        cmd += ["--user", user]
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


# ---- 会话容器原语(票 16:qemu-exec-v2 执行会话;与 run_docker 同款 utf-8 纪律) ----
# run_docker 只覆盖"一次性 docker run --rm"形态;会话容器需要 -d 常驻 +
# 显式命名 + 逐条 docker exec + 终态 rm -f,原语在此收口,工具层不拼 docker 命令。

def _run_docker_cmd(
    cmd: list[str], timeout: float, *, max_output_bytes: int = _DEFAULT_MAX_OUTPUT_BYTES,
    stdin_bytes: bytes | None = None,
) -> tuple[int, str, str]:
    """Run a Docker CLI command with bounded, concurrently drained output.

    ``stdin_bytes`` 走 ``docker exec -i`` 通道:写入在独立线程完成(输入超过
    管道容量时不会阻塞输出排水;子进程不读也只丢写入线程,不影响主流程)。
    """
    if (not isinstance(max_output_bytes, int)
            or isinstance(max_output_bytes, bool)
            or max_output_bytes < 1):
        return 125, "", "invalid max_output_bytes: expected a positive integer"
    proc = None
    selector = None
    streams: dict[str, dict[str, object]] = {}
    timed_out = False
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.PIPE if stdin_bytes is not None else None,
        )
        if stdin_bytes is not None and proc.stdin is not None:
            def _feed(pipe, payload):
                try:
                    pipe.write(payload)
                    pipe.close()
                except OSError:
                    pass

            threading.Thread(target=_feed, args=(proc.stdin, stdin_bytes),
                             daemon=True).start()
        selector = selectors.DefaultSelector()
        for name, stream in (("stdout", proc.stdout), ("stderr", proc.stderr)):
            if stream is not None:
                selector.register(stream, selectors.EVENT_READ, name)
                streams[name] = {
                    "bytes": bytearray(), "truncated": False, "incomplete": False,
                }

        try:
            proc.wait(timeout=0)
        except subprocess.TimeoutExpired:
            pass
        deadline = time.monotonic() + timeout
        drain_deadline: float | None = None
        while selector.get_map() or proc.poll() is None:
            now = time.monotonic()
            returncode = proc.poll()
            if returncode is None:
                if now >= deadline:
                    timed_out = True
                    _stop_process(proc)
                    returncode = proc.poll()
                    drain_deadline = now + _PIPE_DRAIN_SECONDS
                wait_until = deadline if not timed_out else drain_deadline
            else:
                if drain_deadline is None:
                    drain_deadline = now + _PIPE_DRAIN_SECONDS
                wait_until = drain_deadline
            if wait_until is None or now >= wait_until:
                for key in selector.get_map().values():
                    streams[key.data]["incomplete"] = True
                break
            wait_for = min(0.05, wait_until - now)
            if selector.get_map():
                events = selector.select(wait_for)
                for key, _ in events:
                    name = key.data
                    try:
                        chunk = os.read(key.fd, _OUTPUT_READ_CHUNK)
                    except (BlockingIOError, InterruptedError):
                        continue
                    except OSError:
                        chunk = b""
                    if not chunk:
                        selector.unregister(key.fileobj)
                        key.fileobj.close()
                        continue
                    state = streams[name]
                    kept = state["bytes"]
                    remaining = max_output_bytes - len(kept)
                    if remaining > 0:
                        kept.extend(chunk[:remaining])
                    if len(chunk) > max(remaining, 0):
                        state["truncated"] = True
            else:
                time.sleep(wait_for)

        if proc.poll() is None:
            _stop_process(proc)
        returncode = proc.poll()
        if returncode is None:
            returncode = 124 if timed_out else 125
        stdout_state = streams.get(
            "stdout", {"bytes": b"", "truncated": False, "incomplete": False}
        )
        stderr_state = streams.get(
            "stderr", {"bytes": b"", "truncated": False, "incomplete": False}
        )
        stdout = _decode_bounded_output(
            bytes(stdout_state["bytes"]), stdout_state["truncated"],
            "stdout", max_output_bytes, stdout_state["incomplete"]
        )
        stderr = _decode_bounded_output(
            bytes(stderr_state["bytes"]), stderr_state["truncated"],
            "stderr", max_output_bytes, stderr_state["incomplete"]
        )
        if timed_out:
            stderr += f"\ndocker timed out after {timeout}s"
            return 124, stdout, stderr
        return returncode, stdout, stderr
    except OSError as exc:
        if proc is not None:
            _stop_process(proc)
        return 125, "", f"docker invocation failed: {exc}"
    except BaseException:
        if proc is not None:
            _stop_process(proc)
        raise
    finally:
        if selector is not None:
            for key in list(selector.get_map().values()):
                try:
                    selector.unregister(key.fileobj)
                except (KeyError, ValueError):
                    pass
                try:
                    key.fileobj.close()
                except OSError:
                    pass
            selector.close()


def docker_run_detached(
    image: str,
    args: list[str],
    *,
    name: str,
    mounts: list[tuple[Path, str, str]] | None = None,
    tmpfs: list[str] | None = None,
    entrypoint: str | None = None,
    network: str = "none",
    read_only: bool = False,
    init: bool = True,
    timeout: int = 120,
    pids_limit: int = _DEFAULT_SESSION_PIDS_LIMIT,
) -> tuple[int, str, str]:
    """`docker run -d --rm --name <name>`:会话容器(stdout=容器 ID)。"""
    if (not isinstance(pids_limit, int)
            or isinstance(pids_limit, bool)
            or pids_limit < 1):
        raise ValueError("pids_limit must be a positive integer")
    cmd = ["docker", "run", "-d", "--rm", "--name", name]
    if init:
        cmd.append("--init")
    cmd += ["--pids-limit", str(pids_limit)]
    if entrypoint:
        cmd += ["--entrypoint", entrypoint]
    if network:
        cmd += ["--network", network]
    if read_only:
        cmd.append("--read-only")
    for t in (tmpfs or []):
        cmd += ["--tmpfs", t]
    for host, container, mode in (mounts or []):
        cmd += ["-v", f"{to_docker_path(Path(host).resolve())}:{container}:{mode}"]
    cmd.append(image)
    cmd += args
    return _run_docker_cmd(cmd, timeout)


def docker_exec(
    container: str,
    args: list[str],
    *,
    env: dict[str, str] | None = None,
    detach: bool = False,
    timeout: int = 300,
    max_output_bytes: int = _DEFAULT_MAX_OUTPUT_BYTES,
    stdin_bytes: bytes | None = None,
) -> tuple[int, str, str]:
    """`docker exec [-d] [-i] [-e K=V...] <container> <args>`:直接 argv,不经 shell。

    stdout/stderr are drained concurrently and retained only up to
    ``max_output_bytes`` per stream; excess output is reported with a marker.
    ``stdin_bytes`` 提供时加 ``-i`` 并把字节作为目标进程 stdin(票 18 stdin
    模板;有界写入线程,不阻塞输出排水)。
    """
    cmd = ["docker", "exec"]
    if detach:
        cmd.append("-d")
    if stdin_bytes is not None:
        cmd.append("-i")
    for k, v in (env or {}).items():
        cmd += ["-e", f"{k}={v}"]
    cmd.append(container)
    cmd += args
    return _run_docker_cmd(cmd, timeout, max_output_bytes=max_output_bytes,
                           stdin_bytes=stdin_bytes)


def docker_rm(container: str, *, timeout: int = 60) -> tuple[int, str, str]:
    """`docker rm -f`:会话停机封存的权威拆除(杀容器即杀全部进程)。"""
    return _run_docker_cmd(["docker", "rm", "-f", container], timeout)


def docker_image_labels(image: str) -> dict[str, str] | None:
    """镜像 LABEL 字典;Docker/镜像不可用返回 None(设施核查用)。"""
    rc, out, _ = _run_docker_cmd(
        ["docker", "image", "inspect", "-f", "{{json .Config.Labels}}",
         _ensure_tag(image)], 30)
    if rc != 0:
        return None
    try:
        labels = json.loads(out.strip() or "{}")
    except ValueError:
        return None
    return labels if isinstance(labels, dict) else None


def docker_image_identity(image: str) -> dict | None:
    """Read immutable image ID and its labels together; execution uses this ID."""
    rc, out, _ = _run_docker_cmd(
        ["docker", "image", "inspect", _ensure_tag(image)], 30)
    if rc != 0:
        return None
    try:
        item = json.loads(out)[0]
        image_id = item["Id"]
        labels = item["Config"].get("Labels") or {}
        if not isinstance(image_id, str) or not image_id.startswith("sha256:"):
            return None
        if not isinstance(labels, dict):
            return None
        return {"image_id": image_id, "labels": labels}
    except (ValueError, KeyError, IndexError, TypeError):
        return None
