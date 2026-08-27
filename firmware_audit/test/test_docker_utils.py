"""docker_utils 单元测试。

验证镜像名归一化:`docker image inspect` 对无 tag 镜像名(如 `binwalk`)
解析失败,必须补 `:latest`。docker_available 依赖此归一化,否则对
无 tag 镜像误判为不可用 → Step3/4 静默降级。

用法:
    python firmware_audit/test/test_docker_utils.py
    python -m firmware_audit.test.test_docker_utils
"""
from __future__ import annotations

from ..docker.docker_utils import _ensure_tag


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


def main() -> int:
    groups = [
        ("无tag补latest", test_ensure_tag_untagged()),
        ("已带tag不变", test_ensure_tag_already_tagged()),
        ("registry补latest", test_ensure_tag_registry()),
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
