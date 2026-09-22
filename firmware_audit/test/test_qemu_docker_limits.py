"""会话 Docker 原语的进程数与输出边界回归测试。"""
from __future__ import annotations

import os
import signal
import subprocess
import sys
import threading
import textwrap

import pytest

from firmware_audit.docker import docker_utils


def test_detached_session_has_finite_default_pids_limit(monkeypatch) -> None:
    calls: list[tuple[list[str], int]] = []

    def fake_run(cmd: list[str], timeout: int, **kwargs):
        calls.append((cmd, timeout))
        return 0, "cid\n", ""

    monkeypatch.setattr(docker_utils, "_run_docker_cmd", fake_run)

    docker_utils.docker_run_detached("image", ["infinity"], name="session")

    command = calls[0][0]
    assert command[command.index("--pids-limit") + 1] == "128"


def test_detached_session_accepts_explicit_pids_limit(monkeypatch) -> None:
    calls: list[list[str]] = []

    def fake_run(cmd: list[str], timeout: int, **kwargs):
        calls.append(cmd)
        return 0, "cid\n", ""

    monkeypatch.setattr(docker_utils, "_run_docker_cmd", fake_run)

    docker_utils.docker_run_detached(
        "image", ["infinity"], name="session", pids_limit=17
    )

    command = calls[0]
    assert command[command.index("--pids-limit") + 1] == "17"


def test_docker_exec_forwards_output_limit(monkeypatch) -> None:
    seen: dict[str, object] = {}

    def fake_run(cmd: list[str], timeout: int, *, max_output_bytes: int):
        seen.update(cmd=cmd, timeout=timeout, max_output_bytes=max_output_bytes)
        return 0, "", ""

    monkeypatch.setattr(docker_utils, "_run_docker_cmd", fake_run)

    docker_utils.docker_exec("container", ["command"], max_output_bytes=4096)

    assert seen["max_output_bytes"] == 4096


def test_bounded_capture_marks_each_flooded_stream() -> None:
    script = textwrap.dedent(
        """
        import sys
        sys.stdout.write("o" * 10000)
        sys.stderr.write("e" * 10000)
        """
    )

    rc, stdout, stderr = docker_utils._run_docker_cmd(
        [sys.executable, "-c", script], timeout=5, max_output_bytes=64
    )

    assert rc == 0
    assert "o" * 64 in stdout
    assert "e" * 64 in stderr
    assert "output truncated" in stdout
    assert "output truncated" in stderr


def test_bounded_capture_retains_partial_output_on_timeout() -> None:
    script = textwrap.dedent(
        """
        import sys
        import time
        sys.stdout.write("before-timeout")
        sys.stdout.flush()
        time.sleep(2)
        """
    )

    rc, stdout, stderr = docker_utils._run_docker_cmd(
        [sys.executable, "-c", script], timeout=0.1, max_output_bytes=64
    )

    assert rc == 124
    assert "before-timeout" in stdout
    assert "timed out" in stderr


def test_bounded_capture_keeps_output_when_descendant_holds_pipe(tmp_path) -> None:
    pid_file = tmp_path / "descendant.pid"
    script = textwrap.dedent(
        f"""
        import pathlib
        import subprocess
        import sys
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(5)"])
        pathlib.Path({str(pid_file)!r}).write_text(str(child.pid))
        sys.stdout.write("parent-output")
        sys.stdout.flush()
        """
    )
    before_threads = {thread.ident for thread in threading.enumerate()}

    try:
        rc, stdout, _ = docker_utils._run_docker_cmd(
            [sys.executable, "-c", script], timeout=5, max_output_bytes=64
        )

        assert rc == 0
        assert "parent-output" in stdout
        assert "output incomplete" in stdout
        after_threads = {thread.ident for thread in threading.enumerate()}
        assert after_threads <= before_threads
    finally:
        if pid_file.exists():
            pid = int(pid_file.read_text())
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass


def test_interrupting_capture_kills_child(monkeypatch) -> None:
    processes: list[subprocess.Popen] = []
    real_popen = subprocess.Popen

    class InterruptingPopen(real_popen):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.interrupted = False
            processes.append(self)

        def wait(self, timeout=None):
            if not self.interrupted:
                self.interrupted = True
                raise KeyboardInterrupt
            return super().wait(timeout)

    monkeypatch.setattr(docker_utils.subprocess, "Popen", InterruptingPopen)
    script = "import time; time.sleep(30)"

    with pytest.raises(KeyboardInterrupt):
        docker_utils._run_docker_cmd(
            [sys.executable, "-c", script], timeout=5, max_output_bytes=64
        )

    assert processes and processes[0].poll() is not None


def test_immutable_image_identity_is_read_from_inspect(monkeypatch):
    import json
    monkeypatch.setattr(docker_utils, "_run_docker_cmd", lambda *a, **kw: (
        0, json.dumps([{"Id": "sha256:abc", "Config": {"Labels": {"fw.qemu.version": "11.1.1"}}}]), ""))
    identity = docker_utils.docker_image_identity("example:fixed")
    assert identity == {"image_id": "sha256:abc", "labels": {"fw.qemu.version": "11.1.1"}}
