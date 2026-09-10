"""容器调用替身(测试共享,票02 评审收编——rules.md「同一逻辑禁止第三个拷贝」)。

此前 test_step5_r2_tools / test_step5_fallback_tools / test_step5_binwalk_rescan
各自持有同形的 _SandboxSpy/_install 拷贝;统一收编到 ReplaySpy + patched。
非测试模块(pytest 只收集 test_*.py),双模式(独立跑/pytest)下均可 import。
"""
from __future__ import annotations


class ReplaySpy:
    """容器调用替身:按序回放 (rc, out, err),逐次记录 (args, kwargs)。

    补丁点由测试自选(r2_base.run_in_sandbox / binwalk_rescan.run_docker 等);
    每次调用记录形如 {"args": tuple, "kwargs": dict}。零调用时 .last 响亮失败
    (断言"守卫路径不付容器"靠它)。
    """

    def __init__(self, *replays):
        self.replays = list(replays)
        self.calls: list[dict] = []

    def __call__(self, *args, **kwargs):
        self.calls.append({"args": args, "kwargs": kwargs})
        return self.replays.pop(0) if self.replays else (0, "", "")

    @property
    def last(self) -> dict:
        if not self.calls:
            raise AssertionError("不应有容器调用")
        return self.calls[-1]


def patched(module, **replacements):
    """模块属性替换(测试替身注入),返回恢复函数(try/finally 配对)。

    用法:restore = patched(r2_base, run_in_sandbox=spy)
    可一次换多个属性(如 binwalk_rescan 的 run_docker + docker_available)。
    """
    orig = {name: getattr(module, name) for name in replacements}

    def _restore():
        for name, val in orig.items():
            setattr(module, name, val)

    for name, val in replacements.items():
        setattr(module, name, val)
    return _restore
