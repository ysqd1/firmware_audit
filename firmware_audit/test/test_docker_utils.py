"""docker_utils 单元测试。

验证镜像名归一化:`docker image inspect` 对无 tag 镜像名(如 `binwalk`)
解析失败,必须补 `:latest`。docker_available 依赖此归一化,否则对
无 tag 镜像误判为不可用 → Step3/4 静默降级。

另验证 subprocess 编解码契约(2026-09-03 修复):subprocess.run 必须显式
encoding="utf-8" + errors="replace"。Windows 下 text=True 不指定 encoding
会用进程默认编码(gbk/UTF-8 mode,视环境),容器输出含非法字节时 readerthread
抛 UnicodeDecodeError → stdout/stderr 为 None → 下游 json.loads(None) 抛
TypeError(semgrep_scan/gitleaks_scan 实测,回归测试见 test_*_utf8_decode)。

用法:
    python firmware_audit/test/test_docker_utils.py
    python -m firmware_audit.test.test_docker_utils
"""
from __future__ import annotations

import subprocess as _subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from firmware_audit.docker import docker_utils
from firmware_audit.docker.docker_utils import _ensure_tag


def _probe_run_encoding(run_call):
    """校验一次 subprocess.run 调用点的编码契约,返回 (fails, 调用结果)。

    用真实子进程输出非法 utf-8 字节(b'\\xaf\\xaf')驱动:捕获调用 kwargs 断言
    显式 encoding/errors,同时验证该配置下真实解码不崩、stdout 不为 None
    (None 是 readerthread 解码崩溃后 communicate 遗留的信号)。
    不依赖 Docker,秒级、确定性。
    """
    fails: list[str] = []
    captured: dict = {}
    real_run = _subprocess.run

    def fake_run(cmd, **kw):
        captured.update(kw)
        code = "import sys; sys.stdout.buffer.write(b'\\xaf\\xaf')"
        return real_run([sys.executable, "-c", code], **kw)

    orig = docker_utils.subprocess.run
    docker_utils.subprocess.run = fake_run
    try:
        result = run_call()
    finally:
        docker_utils.subprocess.run = orig

    if captured.get("encoding") != "utf-8":
        fails.append(f"subprocess.run 应显式 encoding='utf-8',实际 {captured.get('encoding')!r}")
    if captured.get("errors") != "replace":
        fails.append(f"subprocess.run 应 errors='replace',实际 {captured.get('errors')!r}")
    return fails, result


def test_ensure_tag_untagged() -> list[str]:
    """无 tag 镜像名 → 补 :latest。"""
    fails: list[str] = []
    if _ensure_tag("binwalk") != "binwalk:latest":
        fails.append(f"'binwalk' 应归一化为 'binwalk:latest',实际 {_ensure_tag('binwalk')}")
    return fails


def test_ensure_tag_already_tagged() -> list[str]:
    """已带 tag → 不变。"""
    fails: list[str] = []
    for name in ("binwalk:latest", "ghidra:v2", "reg.io/img:tag"):
        if _ensure_tag(name) != name:
            fails.append(f"{name} 应保持不变,实际 {_ensure_tag(name)}")
    return fails


def test_ensure_tag_registry() -> list[str]:
    """带 registry 前缀的镜像名 → 补 :latest(不破坏 registry)。"""
    fails: list[str] = []
    if _ensure_tag("deepaudit/sandbox") != "deepaudit/sandbox:latest":
        fails.append(f"'deepaudit/sandbox' 应归一化为 ':latest',实际 {_ensure_tag('deepaudit/sandbox')}")
    return fails


def test_run_docker_utf8_decode() -> list[str]:
    """run_docker 的 subprocess.run 必须 utf-8 + replace 解码,输出 None 即解码崩溃。"""
    fails, (rc, out, err) = _probe_run_encoding(
        lambda: docker_utils.run_docker("img", ["arg"]))
    if out is None:
        fails.append("run_docker stdout 为 None(readerthread 解码崩溃遗留信号)")
    if err is None:
        fails.append("run_docker stderr 为 None(readerthread 解码崩溃遗留信号)")
    # 非法字节经 errors='replace' 不应再抛,rc 来自真实子进程退出码
    if rc != 0:
        fails.append(f"真实子进程退出码应 0,实际 {rc}")
    return fails


def test_docker_available_utf8_decode() -> list[str]:
    """docker_available 的 subprocess.run 同款 utf-8 + replace 契约。"""
    fails, available = _probe_run_encoding(lambda: docker_utils.docker_available("img"))
    # fake 子进程退出码 0,inspect 成功语义下应返回 True(闭环守护行为面)
    if available is not True:
        fails.append(f"退出码 0 时 docker_available 应返回 True,实际 {available!r}")
    return fails


def main() -> int:
    groups = [
        ("无tag补latest", test_ensure_tag_untagged()),
        ("已带tag不变", test_ensure_tag_already_tagged()),
        ("registry补latest", test_ensure_tag_registry()),
        ("run_docker utf-8解码", test_run_docker_utf8_decode()),
        ("docker_available utf-8解码", test_docker_available_utf8_decode()),
    ]
    failures = 0
    for name, fl in groups:
        if fl:
            failures += len(fl)
            for msg in fl:
                print(f"[FAIL] {name}: {msg}")
        else:
            print(f"[PASS] {name}")
    print(f"\n结果: {'全部通过' if failures == 0 else f'{failures} 个断言失败'}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
