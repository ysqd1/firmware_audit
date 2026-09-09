"""票03 ghidra_decompile 单测:伪造容器产物的假 run_docker 测试基建(离线)。

假 run_docker 往输出目录写边车三件套 + 版本头(spec User Story 27),
缓存命中/版本失效重跑/sha256 去重硬链接/非 ELF 拒绝/容器参数断言全部
离线可测;Docker 门控的真 Ghidra 冒烟在 test_step5_cli_tools.py(验收锚点)。
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from firmware_audit.step5_agent.providers.tools.base import ToolContext
from firmware_audit.step5_agent.providers.tools import ghidra_decompile as gd
from firmware_audit.step5_agent.providers.tools.ghidra_decompile import (
    GhidraDecompileTool,
)

_ELF_MAGIC = b"\x7fELF" + b"\x02\x01\x01" + b"\x00" * 8
_VERSION = gd._EXTRACTINFO_VERSION


def _make_ctx(root: Path) -> ToolContext:
    (root / "extracted" / "bin").mkdir(parents=True, exist_ok=True)
    return ToolContext(process_dir=root)


def _write_elf(root: Path, rel: str, body: bytes = b"payload") -> Path:
    p = root / "extracted" / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(_ELF_MAGIC + body)
    return p


def _sidecar_c(functions: int = 3) -> str:
    return (f"// extractinfo_version: {_VERSION}\n"
            f"// decompile_success: {functions}\n"
            "// ===== Function: main @ 00400890 =====\nint main(){return 0;}\n")


class _FakeDocker:
    """run_docker 替身:解析 mounts 找 /work/output,写入边车三件套 + 版本头。

    记录每次调用的 image/args/mounts/timeout/user/env 供接口边界断言;
    fail 注入 (rc, out, err) 模拟容器失败;produce=False 模拟"rc=0 但零产出"
    (反编译空壳)。replays 不适用——按调用次序恒定行为。
    """

    def __init__(self, functions: int = 3, fail: tuple | None = None,
                 produce: bool = True):
        self.functions = functions
        self.fail = fail
        self.produce = produce
        self.calls: list[dict] = []

    def __call__(self, image, args, mounts=None, timeout=3600,
                 env=None, network=None, user=None):
        self.calls.append({"image": image, "args": list(args),
                           "mounts": list(mounts or []), "timeout": timeout,
                           "env": env, "user": user, "network": network})
        if self.fail is not None:
            return self.fail
        if not self.produce:
            return 0, "", ""
        out_dir = next(Path(m[0]) for m in (mounts or []) if m[1] == "/work/output")
        (out_dir / "decompiled.c").write_text(_sidecar_c(self.functions),
                                              encoding="utf-8")
        (out_dir / "imports.json").write_text(json.dumps(
            [{"name": "system", "plt": "0x401060", "ref_count": 0, "call_sites": []}]),
            encoding="utf-8")
        (out_dir / "strings.json").write_text(json.dumps(
            {"version": 2, "program": "x", "strings": []}), encoding="utf-8")
        # 无消费者的产物也应被工具忽略(不拷贝)
        (out_dir / "functions.json").write_text("[]", encoding="utf-8")
        (out_dir / "meta.json").write_text("{}", encoding="utf-8")
        return 0, "ExtractInfo: done", ""


def _install(fake) -> None:
    gd.run_docker = fake  # noqa: SLF001 - 工具模块内延迟导入,补丁挂模块属性


class _Restore:
    def __init__(self):
        self._orig = gd.run_docker

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        gd.run_docker = self._orig
        return False


def _unlinked_pair(a: Path, b: Path) -> bool:
    try:
        return a.samefile(b)
    except OSError:
        return False


def test_cache_hit_zero_container() -> list[str]:
    """缓存命中:.c 存在 + 版本匹配 + 成功数>0 → 直接返回已反编译,零容器。"""
    fails: list[str] = []
    fake = _FakeDocker()
    with _Restore():
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            ctx = _make_ctx(root)
            _write_elf(root, "bin/app")
            (root / "analysis" / "bin").mkdir(parents=True)
            (root / "analysis" / "bin" / "app.c").write_text(_sidecar_c(7),
                                                             encoding="utf-8")
            r = GhidraDecompileTool(ctx).execute(file_ref="bin/app")
            if not r.ok:
                fails.append(f"缓存命中应成功: {r.error}")
            elif "已反编译" not in r.text or "7 个函数" not in r.text:
                fails.append(f"命中文案异常: {r.text[:160]}")
            if fake.calls:
                fails.append("缓存命中不得调容器")
    return fails


def test_version_stale_reruns_and_overwrites() -> list[str]:
    """版本失效(旧版本/空壳 success=0)→ 触发重跑并覆盖。"""
    fails: list[str] = []
    fake = _FakeDocker(functions=5)
    with _Restore():
        gd.run_docker = fake
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            ctx = _make_ctx(root)
            _write_elf(root, "bin/app")
            ana = root / "analysis" / "bin"
            ana.mkdir(parents=True)
            # 旧版本产物(无版本标记 → 0)
            (ana / "app.c").write_text("// decompile_success: 9\nOLD", encoding="utf-8")
            r = GhidraDecompileTool(ctx).execute(file_ref="bin/app")
            if not r.ok or "已反编译(缓存命中)" in r.text:
                fails.append(f"旧版本应重跑: {r.text[:120]}")
            if len(fake.calls) != 1:
                fails.append(f"旧版本应触发一次容器: {fake.calls}")
            new_head = (ana / "app.c").read_text(encoding="utf-8").splitlines()[0]
            if f"extractinfo_version: {_VERSION}" not in new_head:
                fails.append(f"重跑应覆盖旧产物: {new_head}")

            # 空壳(版本匹配但 success=0)→ 同样重跑
            fake2 = _FakeDocker(functions=2)
            gd.run_docker = fake2
            (ana / "app.c").write_text(
                f"// extractinfo_version: {_VERSION}\n// decompile_success: 0\nx",
                encoding="utf-8")
            r2 = GhidraDecompileTool(ctx).execute(file_ref="bin/app")
            if not r2.ok or len(fake2.calls) != 1:
                fails.append(f"空壳应重跑: ok={r2.ok} calls={len(fake2.calls)}")
    return fails


def test_sha256_dedup_hardlink_and_fallback_copy() -> list[str]:
    """同内容第二路径:硬链接三件套 + dedup 索引 + Observation 注明来源;
    os.link 失败降级拷贝。"""
    fails: list[str] = []
    with _Restore():
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            ctx = _make_ctx(root)
            body = b"same-bytes"
            _write_elf(root, "bin/first", body)
            _write_elf(root, "lib/second.so", body)
            fake = _FakeDocker()
            gd.run_docker = fake
            r1 = GhidraDecompileTool(ctx).execute(file_ref="bin/first")
            if not r1.ok or len(fake.calls) != 1:
                fails.append(f"首路径应真跑容器: ok={r1.ok} calls={len(fake.calls)}")
            r2 = GhidraDecompileTool(ctx).execute(file_ref="lib/second.so")
            if not r2.ok:
                fails.append(f"去重路径应成功: {r2.error}")
                return fails
            if len(fake.calls) != 1:
                fails.append(f"同内容第二路径不得再付容器: calls={len(fake.calls)}")
            if "sha256" not in r2.text or "bin/first" not in r2.text:
                fails.append(f"Observation 应注明复用来源: {r2.text[:160]}")
            ana = root / "analysis"
            if not _unlinked_pair(ana / "lib/second.so.c", ana / "bin/first.c"):
                fails.append("第二路径 .c 应是首路径的硬链接")
            for suf in (".imports.json", ".strings.json"):
                if not (ana / f"lib/second.so{suf}").is_file():
                    fails.append(f"三件套缺 {suf}")
            idx = json.loads((ana / "dedup.json").read_text(encoding="utf-8"))
            if len(idx) != 1 or next(iter(idx.values())) != "bin/first":
                fails.append(f"dedup 索引应记首个路径: {idx}")

            # os.link 失败 → 降级拷贝(内容一致即通过)
            orig_link = os.link

            def _broken_link(src, dst, *a, **kw):
                raise OSError("cross-device")

            gd.os.link = _broken_link
            try:
                _write_elf(root, "lib/third.so", body)
                r3 = GhidraDecompileTool(ctx).execute(file_ref="lib/third.so")
                if not r3.ok or "sha256" not in r3.text:
                    fails.append(f"link 失败应降级拷贝复用: {r3.error or r3.text[:120]}")
                elif _unlinked_pair(ana / "lib/third.so.c", ana / "bin/first.c"):
                    fails.append("降级路径不应是链接(应为拷贝)")
                elif (ana / "lib/third.so.c").read_text(encoding="utf-8") \
                        != (ana / "bin/first.c").read_text(encoding="utf-8"):
                    fails.append("拷贝复用内容应一致")
            finally:
                gd.os.link = orig_link
    return fails


def test_success_path_three_sidecars_light_observation() -> list[str]:
    """成功路径:三件套落盘;functions/meta 不落盘;Observation 轻量(指针+函数数)。"""
    fails: list[str] = []
    fake = _FakeDocker(functions=4)
    with _Restore():
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            ctx = _make_ctx(root)
            _write_elf(root, "bin/app")
            gd.run_docker = fake
            r = GhidraDecompileTool(ctx).execute(file_ref="bin/app")
            if not r.ok:
                fails.append(f"成功路径应 ok: {r.error}")
                return fails
            ana = root / "analysis" / "bin"
            for suf in (".c", ".imports.json", ".strings.json"):
                if not (ana / f"app{suf}").is_file():
                    fails.append(f"三件套缺 app{suf}")
            for junk in ("app.functions.json", "app.meta.json", "app.symbols.json"):
                if (ana / junk).exists():
                    fails.append(f"无消费者产物不应拷贝: {junk}")
            if "app.c" not in r.text or "4 个函数" not in r.text:
                fails.append(f"Observation 应为指针+函数数: {r.text[:160]}")
            if len(r.text) > 400 or "int main" in r.text:
                fails.append(f"Observation 不得回 C 内容: {r.text[:200]}")
    return fails


def test_non_elf_and_escape_instant_rejection() -> list[str]:
    """非 ELF/路径越界 → 即时 ok=False 引导,零容器调用(不付 900s)。"""
    fails: list[str] = []
    fake = _FakeDocker()
    with _Restore():
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            ctx = _make_ctx(root)
            (root / "extracted" / "data").mkdir(parents=True)
            (root / "extracted" / "data" / "blob.bin").write_bytes(b"\x00\x01" * 8)
            gd.run_docker = fake
            t = GhidraDecompileTool(ctx)
            r = t.execute(file_ref="data/blob.bin")
            if r.ok or "不是 ELF" not in (r.error or ""):
                fails.append(f"非 ELF 应即时拒绝: {r.error}")
            r2 = t.execute(file_ref="../../etc/passwd")
            if r2.ok or "非法路径" not in (r2.error or ""):
                fails.append(f"越界应拒绝: {r2.error}")
            if fake.calls:
                fails.append("拒绝路径不应触发容器")
    return fails


def test_container_contract() -> list[str]:
    """容器参数断言(接口边界):ghidra 镜像/双超时/宿主 uid:gid/HOME=/tmp/挂载。"""
    fails: list[str] = []
    fake = _FakeDocker()
    with _Restore():
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            ctx = _make_ctx(root)
            _write_elf(root, "bin/app")
            gd.run_docker = fake
            GhidraDecompileTool(ctx).execute(file_ref="bin/app")
            if not fake.calls:
                fails.append("应有容器调用")
                return fails
            c = fake.calls[0]
            if c["image"] != gd.GHIDRA_IMAGE:
                fails.append(f"镜像应为 ghidra: {c['image']}")
            if c["timeout"] != 900:
                fails.append(f"容器整体超时应为 900: {c['timeout']}")
            args = c["args"]
            if "-analysisTimeoutPerFile" not in args or "300" not in args:
                fails.append(f"缺单文件分析超时 300: {args}")
            if "-postScript" not in args or "ExtractInfo.py" not in args:
                fails.append(f"缺 ExtractInfo.py postScript: {args}")
            if "-deleteProject" not in args or "-overwrite" not in args:
                fails.append(f"缺一次性工程参数: {args}")
            cont_paths = {m[1] for m in c["mounts"]}
            if not {"/work/input", "/work/output", "/work/project"} <= cont_paths:
                fails.append(f"挂载缺三固定路径: {cont_paths}")
            # 安全基线(Step5 工具统一):断网 + 输入只读(固件不可被容器写回)
            if c["network"] != "none":
                fails.append(f"容器应断网(--network none): {c['network']}")
            input_mount = next(m for m in c["mounts"] if m[1] == "/work/input")
            if input_mount[-1] != "ro":
                fails.append(f"输入挂载应为只读: {input_mount}")
            host_user = f"{os.getuid()}:{os.getgid()}" if hasattr(os, "getuid") else None
            if c["user"] != host_user:
                fails.append(f"user 应为宿主 uid:gid: {c['user']} vs {host_user}")
            if host_user and (c["env"] or {}).get("HOME") != "/tmp":
                fails.append(f"非 root 身份应注入 HOME=/tmp: {c['env']}")
    return fails


def test_failure_guides_r2_layer() -> list[str]:
    """容器失败/零产出 → ok=False,文案引导 r2 层。"""
    fails: list[str] = []
    for kwargs in ({"fail": (1, "", "ghidra boom")}, {"produce": False}):
        fake = _FakeDocker(**kwargs)
        with _Restore():
            with tempfile.TemporaryDirectory() as td:
                root = Path(td)
                ctx = _make_ctx(root)
                _write_elf(root, "bin/app")
                gd.run_docker = fake
                r = GhidraDecompileTool(ctx).execute(file_ref="bin/app")
                if r.ok:
                    fails.append(f"kwargs={kwargs} 应 ok=False")
                elif "r2_list_functions" not in (r.error or ""):
                    fails.append(f"失败文案应引导 r2 层: {r.error}")
    return fails


def test_main() -> int:
    failures = 0
    for name, fn in [
        ("cache_hit_zero_container", test_cache_hit_zero_container),
        ("version_stale_reruns_and_overwrites", test_version_stale_reruns_and_overwrites),
        ("sha256_dedup_hardlink_and_fallback_copy", test_sha256_dedup_hardlink_and_fallback_copy),
        ("success_path_three_sidecars_light_observation", test_success_path_three_sidecars_light_observation),
        ("non_elf_and_escape_instant_rejection", test_non_elf_and_escape_instant_rejection),
        ("container_contract", test_container_contract),
        ("failure_guides_r2_layer", test_failure_guides_r2_layer),
    ]:
        fl = fn()
        if fl:
            failures += len(fl)
            for msg in fl:
                print(f"[FAIL] {name}: {msg}")
        else:
            print(f"[PASS] {name}")
    print(f"\n结果: {'全部通过' if failures == 0 else f'{failures} 个断言失败'}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(test_main())
