"""深层复扫单测(票04):大体积无签名文件 finalize 前的守卫全偏移复扫。

三层:
  - gates 开关解析(STEP1_DEEP_RESCAN_MIN_BYTES / STEP1_DEEP_RESCAN)
  - 触发矩阵(fake rescanner 注入,零 Docker):只对"无容器签名"finalize 触发,
    其余 finalize 原因(文本/SDK/max_depth 终局/全树守卫/低于阈值/开关关闭)
    一律不触发;复扫每个文件至多一次(resume 不重扫);原件永存
  - _deep_rescan 函数契约(monkeypatch run_docker):副本被递给容器、-M -x dtb
    在场、三终态 ok/empty/over_guard 的清理语义(副本任何终态都不残留;ok 态
    产物目录归位标准命名,resume/重跑绝不误删成功产物)

env 隔离复用 test_gates._EnvScope(进出清 gates._invalid_warned 告警去重集,
防 bogus 值告警跨用例泄漏)。
"""
from __future__ import annotations

import tempfile
from pathlib import Path

from .. import gates
from ..step1 import step1_guided_extract
from ..step1.file_magic import FINALIZE_UNSIGNED_REASON, rule_decision
from ..step1.step1_guided_extract import (
    extract_guided,
    _deep_rescan,
    _DEEP_RESCAN_PREFIX,
    _load_manifest,
)
from .test_gates import _EnvScope

_DEEP_ENV = {"STEP1_DEEP_RESCAN_MIN_BYTES": "64",
             "STEP1_MAX_FILES_PER_EXTRACTION": None}


def _unsigned_blob(p: Path, size: int) -> Path:
    """全 0x00 字节:不撞任何魔数,也不满足文本启发式(有 NUL)。"""
    p.write_bytes(b"\x00" * size)
    return p


class FakeExtractor:
    """记录 extractor 调用;产出 ELF(下一层 finalize,不链式)。"""

    def __init__(self):
        self.calls: list[str] = []

    def __call__(self, path: Path, seq: int, parent: Path):
        self.calls.append(path.name)
        d = parent / f"{seq:06d}_{path.name}.extracted"
        d.mkdir(parents=True, exist_ok=True)
        out = d / "app.elf"
        out.write_bytes(b"\x7fELF" + b"\x00" * 60)
        return [out], "ok"


class FakeRescanner:
    """记录复扫调用;按 mode 产出(落点仿真实实现:parent/<副本名>.extracted/)。"""

    def __init__(self, mode: str = "elf"):
        self.mode = mode
        self.calls: list[tuple[str, int]] = []

    def __call__(self, path: Path, seq: int, parent: Path):
        self.calls.append((path.name, seq))
        copy = parent / f"{_DEEP_RESCAN_PREFIX}{seq:06d}_{path.name}"
        d = parent / f"{copy.name}.extracted" / "0"
        d.mkdir(parents=True, exist_ok=True)
        if self.mode == "elf":
            out = d / "inner.elf"
            out.write_bytes(b"\x7fELF" + b"\x00" * 60)
            return [out], "ok"
        if self.mode == "empty":
            return [], "empty"
        if self.mode == "over_guard":
            return [], "over_guard"
        if self.mode == "dup_cpio":
            # 模拟 -M 递归产物:inner.cpio 已被解出(同名 .extracted 非空),
            # bare.gz 是没被解出的容器(无兄弟目录)
            cpio = d / "inner.cpio"
            cpio.write_bytes(b"070701" + b"\x00" * 60)
            (d / "inner.cpio.extracted" / "0").mkdir(parents=True, exist_ok=True)
            (d / "inner.cpio.extracted" / "0" / "payload.txt").write_bytes(
                b"key=value\n" * 3)
            gz = d / "bare.gz"
            gz.write_bytes(b"\x1f\x8b" + b"\x00" * 60)
            return [cpio, gz,
                    d / "inner.cpio.extracted" / "0" / "payload.txt"], "ok"
        raise AssertionError(f"未知 mode {self.mode}")


# --- gates 开关解析 ---

def test_gates_deep_rescan_env() -> list[str]:
    fails: list[str] = []
    with _EnvScope():
        if gates.resolve_deep_rescan_min_bytes() != 4 * 1024 * 1024:
            fails.append(f"默认阈值应为 4MiB,实得 {gates.resolve_deep_rescan_min_bytes()}")
        if gates.resolve_deep_rescan_enabled() is not True:
            fails.append("缺省应开启深层复扫")
        with _EnvScope(STEP1_DEEP_RESCAN_MIN_BYTES="64"):
            if gates.resolve_deep_rescan_min_bytes() != 64:
                fails.append("env 覆盖阈值未生效")
        with _EnvScope(STEP1_DEEP_RESCAN_MIN_BYTES="bogus"):
            if gates.resolve_deep_rescan_min_bytes() != 4 * 1024 * 1024:
                fails.append("非法阈值应回落默认")
        for v in ("0", "false", "no", "off"):
            with _EnvScope(STEP1_DEEP_RESCAN=v):
                if gates.resolve_deep_rescan_enabled() is not False:
                    fails.append(f"STEP1_DEEP_RESCAN={v} 应关闭")
        for v in ("1", "true", "yes", "on"):
            with _EnvScope(STEP1_DEEP_RESCAN=v):
                if gates.resolve_deep_rescan_enabled() is not True:
                    fails.append(f"STEP1_DEEP_RESCAN={v} 应开启")
        with _EnvScope(STEP1_DEEP_RESCAN="bogus"):
            if gates.resolve_deep_rescan_enabled() is not True:
                fails.append("非法开关值应回落默认(开)")
    return fails


# --- rule_decision reason 常量锁定 ---

def test_unsigned_reason_constant() -> list[str]:
    fails: list[str] = []
    action, reason = rule_decision([])
    if action != "finalize" or reason != FINALIZE_UNSIGNED_REASON:
        fails.append(f"rule_decision([]) 的 reason 应等于常量,实得 {reason!r}")
    return fails


# --- 触发矩阵(循环层) ---

def test_deep_rescan_triggers_and_original_survives(tmp_path: Path) -> list[str]:
    """无签名 ≥ 阈值 → 复扫 1 次;原件一字节不改;产物进下一层决策;
    manifest 记 deep_rescan=ok + files。"""
    fails: list[str] = []
    with _EnvScope(**_DEEP_ENV):
        root = tmp_path / "hit"
        root.mkdir()
        fw = _unsigned_blob(root / "fw.bin", 100)
        fake = FakeExtractor()
        res = FakeRescanner("elf")
        extract_guided(fw, root / "out", max_depth=3, extractor=fake,
                       deep_rescanner=res, check_docker=False)
        if len(res.calls) != 1:
            fails.append(f"应复扫 1 次,实得 {len(res.calls)}")
        if fake.calls:
            fails.append(f"无签名固件不应进 extractor: {fake.calls}")
        if not fw.exists() or fw.stat().st_size != 100:
            fails.append("原件被改动/丢失(留树语义破坏)")
        man = _load_manifest(root / "out")
        rec = man.get("fw.bin")
        if not rec or rec.get("deep_rescan") != "ok":
            fails.append(f"manifest 缺 deep_rescan=ok: {rec}")
        if rec and not rec.get("files"):
            fails.append("manifest 复扫记录缺 files")
        if not any(r.get("reason", "").startswith("ELF") for r in man.values()):
            fails.append(f"复扫产物未进下一层决策: {man}")
    return fails


def test_deep_rescan_skips_small_signed_text(tmp_path: Path) -> list[str]:
    """低于阈值 / 有签名容器 / 文本,三种情况都不触发复扫。"""
    fails: list[str] = []
    with _EnvScope(**_DEEP_ENV):
        # ① 无签名但 50 字节 < 64 → 普通 finalize,无 deep_rescan 键
        root = tmp_path / "small"
        root.mkdir()
        fw = _unsigned_blob(root / "fw.bin", 50)
        res = FakeRescanner("elf")
        extract_guided(fw, root / "out", max_depth=3, extractor=FakeExtractor(),
                       deep_rescanner=res, check_docker=False)
        if res.calls:
            fails.append(f"低于阈值不应复扫: {res.calls}")
        rec = _load_manifest(root / "out").get("fw.bin", {})
        if "deep_rescan" in rec:
            fails.append(f"普通 finalize 不应带 deep_rescan 键: {rec}")

        # ② gzip 容器 → continue 走 extractor,复扫不参与
        root2 = tmp_path / "signed"
        root2.mkdir()
        gz = root2 / "fw.gz"
        gz.write_bytes(b"\x1f\x8b" + b"\x00" * 100)
        fake = FakeExtractor()
        res2 = FakeRescanner("elf")
        extract_guided(gz, root2 / "out", max_depth=3, extractor=fake,
                       deep_rescanner=res2, check_docker=False)
        if res2.calls:
            fails.append(f"有签名容器不应复扫: {res2.calls}")
        if not fake.calls:
            fails.append("gzip 容器应走 extractor")

        # ③ 纯文本 → product finalize,不复扫
        root3 = tmp_path / "text"
        root3.mkdir()
        tx = root3 / "conf.ini"
        tx.write_bytes(b"key=value plain text config\n" * 5)
        res3 = FakeRescanner("elf")
        extract_guided(tx, root3 / "out", max_depth=3, extractor=FakeExtractor(),
                       deep_rescanner=res3, check_docker=False)
        if res3.calls:
            fails.append(f"文本文件不应复扫: {res3.calls}")
    return fails


def test_deep_rescan_disabled_by_env(tmp_path: Path) -> list[str]:
    """STEP1_DEEP_RESCAN=0 → 大而无签名也维持现状(直接 finalize,不复扫)。"""
    fails: list[str] = []
    with _EnvScope(STEP1_DEEP_RESCAN_MIN_BYTES="64", STEP1_DEEP_RESCAN="0"):
        root = tmp_path / "off"
        root.mkdir()
        fw = _unsigned_blob(root / "fw.bin", 100)
        res = FakeRescanner("elf")
        extract_guided(fw, root / "out", max_depth=3, extractor=FakeExtractor(),
                       deep_rescanner=res, check_docker=False)
        if res.calls:
            fails.append(f"开关关闭不应复扫: {res.calls}")
        rec = _load_manifest(root / "out").get("fw.bin", {})
        if rec.get("action") != "finalize" or "deep_rescan" in rec:
            fails.append(f"开关关闭应退回普通 finalize: {rec}")
    return fails


def test_deep_rescan_respects_max_depth(tmp_path: Path) -> list[str]:
    """最后一层(d+1 == max_depth)不复扫:产物没有可决策的下一层,纯浪费。"""
    fails: list[str] = []
    with _EnvScope(**_DEEP_ENV):
        root = tmp_path / "deep1"
        root.mkdir()
        fw = _unsigned_blob(root / "fw.bin", 100)
        res = FakeRescanner("elf")
        extract_guided(fw, root / "out", max_depth=1, extractor=FakeExtractor(),
                       deep_rescanner=res, check_docker=False)
        if res.calls:
            fails.append(f"max_depth=1 时不应复扫: {res.calls}")
    return fails


def test_deep_rescan_sdk_excluded(tmp_path: Path) -> list[str]:
    """SDK 容器 finalize 不触发复扫。"""
    fails: list[str] = []
    with _EnvScope(**_DEEP_ENV):
        tree = tmp_path / "sdk"
        sdk = tree / "usr" / "local" / "lib" / "python3.8" / "dist-packages" / "x"
        sdk.mkdir(parents=True)
        _unsigned_blob(sdk / "blob.bin", 100)
        res = FakeRescanner("elf")
        extract_guided(tree, tree, max_depth=3, extractor=FakeExtractor(),
                       deep_rescanner=res, check_docker=False, scan_tree=True)
        if res.calls:
            fails.append(f"SDK 容器不应复扫: {res.calls}")
        man = _load_manifest(tree)
        if not any("SDK" in r.get("reason", "") for r in man.values()):
            fails.append(f"SDK 记录缺失: {man}")
    return fails


def test_deep_rescan_over_total_excluded(tmp_path: Path) -> list[str]:
    """全树守卫触发后,后续无签名大文件不再复扫(scan_tree 两个大文件,上限收紧)。"""
    fails: list[str] = []
    with _EnvScope(**_DEEP_ENV, STEP1_MAX_TOTAL_FILES="1"):
        tree = tmp_path / "over"
        tree.mkdir()
        _unsigned_blob(tree / "a.bin", 100)
        _unsigned_blob(tree / "b.bin", 100)
        res = FakeRescanner("elf")
        extract_guided(tree, tree, max_depth=3, extractor=FakeExtractor(),
                       deep_rescanner=res, check_docker=False, scan_tree=True)
        if len(res.calls) != 1:
            fails.append(f"全树守卫后应只剩 1 次复扫,实得 {len(res.calls)}: {res.calls}")
    return fails


def test_deep_rescan_dup_sibling_not_reextracted(tmp_path: Path) -> list[str]:
    """防重复解包(票04 e2e 发现):复扫产物中已有非空同名 .extracted 的容器
    不再重解(-M 已递归解出);无兄弟目录的容器照常路由(7z 兜底机会保留)。"""
    fails: list[str] = []
    with _EnvScope(**_DEEP_ENV):
        root = tmp_path / "dup"
        root.mkdir()
        fw = _unsigned_blob(root / "fw.bin", 100)
        fake = FakeExtractor()
        res = FakeRescanner("dup_cpio")
        extract_guided(fw, root / "out", max_depth=4, extractor=fake,
                       deep_rescanner=res, check_docker=False)
        # inner.cpio(有非空兄弟)不得进 extractor;bare.gz(无兄弟)应进
        if any("inner.cpio" in n for n in fake.calls):
            fails.append(f"已有解包产物的容器被重解: {fake.calls}")
        if not any("bare.gz" in n for n in fake.calls):
            fails.append(f"无兄弟目录的容器应照常路由: {fake.calls}")
        man = _load_manifest(root / "out")
        dup = [k for k, r in man.items()
               if k.endswith("inner.cpio")
               or k.endswith("inner.cpio.extracted/0/payload.txt")]
        # inner.cpio 与 payload.txt 都应有 finalize 决策(一个"跳过重解",一个文本)
        if len(dup) != 2:
            fails.append(f"复扫产物决策记录缺失: {sorted(k for k in man if 'inner' in k or 'bare' in k)}")
        if dup and not any("跳过重解" in man[k].get("reason", "") for k in dup):
            fails.append(f"缺'跳过重解'记录: { {k: man[k]['reason'] for k in dup} }")
    return fails


def test_deep_rescan_resume_not_repeated(tmp_path: Path) -> list[str]:
    """resume:已 done 的复扫记录跳过(不重复复扫),且成功复扫产物绝不被
    入口清残留误删(2026-09-10 评审发现:清理误删 = 静默丢 rootfs,假阴性)。"""
    fails: list[str] = []
    with _EnvScope(**_DEEP_ENV):
        root = tmp_path / "resume"
        root.mkdir()
        fw = _unsigned_blob(root / "fw.bin", 100)
        res1 = FakeRescanner("elf")
        extract_guided(fw, root / "out", max_depth=3, extractor=FakeExtractor(),
                       deep_rescanner=res1, check_docker=False)
        if len(res1.calls) != 1:
            fails.append(f"首次应复扫 1 次,实得 {len(res1.calls)}")
        products = sorted((root / "out").rglob("inner.elf"))
        if len(products) != 1 or not products[0].is_file():
            fails.append(f"首次运行后产物缺失: {products}")

        res2 = FakeRescanner("elf")
        extract_guided(fw, root / "out", max_depth=3, extractor=FakeExtractor(),
                       deep_rescanner=res2, check_docker=False)
        if res2.calls:
            fails.append(f"resume 后不应重复复扫: {res2.calls}")
        survivors = sorted((root / "out").rglob("inner.elf"))
        if survivors != products:
            fails.append(f"resume/重跑误删成功复扫产物: {survivors}(原 {products})")
    return fails


# --- _deep_rescan 函数契约(monkeypatch run_docker,零 Docker) ---

def test_deep_rescan_contract_ok(tmp_path: Path) -> list[str]:
    """ok 态:副本(非原件)被递给容器,args 带 -M/-x dtb;产物目录归位标准
    命名(去簿记前缀);副本与前缀目录零残留;原件不动。"""
    fails: list[str] = []
    ws = tmp_path / "ws"
    ws.mkdir()
    fw = _unsigned_blob(ws / "fw.bin", 100)
    seen: dict[str, object] = {}

    def fake_run_docker(image, args, mounts=None, env=None, timeout=0, **kw):
        seen["args"] = list(args)
        seen["timeout"] = timeout
        parent = mounts[0][0]
        container_file = args[args.index("-e") + 2]  # ["-e","-M",<file>,...]
        name = container_file.rsplit("/", 1)[-1]
        d = parent / f"{name}.extracted" / "0"
        d.mkdir(parents=True, exist_ok=True)
        (d / "inner.elf").write_bytes(b"\x7fELF" + b"\x00" * 60)
        return 0, "", ""

    old = step1_guided_extract.run_docker
    step1_guided_extract.run_docker = fake_run_docker
    try:
        files, status = _deep_rescan(fw, 0, ws)
    finally:
        step1_guided_extract.run_docker = old
    if status != "ok" or len(files) != 1:
        fails.append(f"应 ok 且 1 产物,实得 ({len(files)}, {status})")
    args = seen.get("args", [])
    if "-M" not in args or "dtb" not in args:
        fails.append(f"args 缺 -M / -x dtb: {args}")
    if seen.get("timeout") != 600:
        fails.append(f"timeout 应 600,实得 {seen.get('timeout')}")
    container_file = args[args.index("-e") + 2] if args else ""
    if "_deeprescan_" not in container_file:
        fails.append(f"递给容器的应是副本: {container_file}")
    if not fw.exists() or fw.stat().st_size != 100:
        fails.append("原件被改动/丢失")
    # 产物已归位标准命名;前缀目录与副本文件都不残留
    if files and files[0].parent.parent != ws / "000000_fw.bin.extracted":
        fails.append(f"产物未归位标准命名: {files[0]}")
    if list(ws.rglob(f"{_DEEP_RESCAN_PREFIX}*")):
        fails.append(f"前缀残留: {list(ws.rglob(f'{_DEEP_RESCAN_PREFIX}*'))}")
    return fails


def test_deep_rescan_contract_empty_and_over_guard(tmp_path: Path) -> list[str]:
    """empty/over_guard 态:产物目录残渣与副本都清干净,原件永存。"""
    fails: list[str] = []
    with _EnvScope(**_DEEP_ENV):
        # empty:容器无产出
        ws = tmp_path / "ws_empty"
        ws.mkdir()
        fw = _unsigned_blob(ws / "fw.bin", 100)

        def fake_empty(image, args, mounts=None, env=None, timeout=0, **kw):
            return 0, "", ""

        old = step1_guided_extract.run_docker
        step1_guided_extract.run_docker = fake_empty
        try:
            files, status = _deep_rescan(fw, 0, ws)
        finally:
            step1_guided_extract.run_docker = old
        if status != "empty" or files:
            fails.append(f"无产出应 empty,实得 ({len(files)}, {status})")
        if sorted(p.name for p in ws.glob("*")) != [fw.name]:
            fails.append(f"empty 后应只剩原件,实得 {sorted(p.name for p in ws.glob('*'))}")

        # over_guard:产出超单次上限
        ws2 = tmp_path / "ws_over"
        ws2.mkdir()
        fw2 = _unsigned_blob(ws2 / "fw2.bin", 100)

        def fake_over(image, args, mounts=None, env=None, timeout=0, **kw):
            parent = mounts[0][0]
            name = args[args.index("-e") + 2].rsplit("/", 1)[-1]
            d = parent / f"{name}.extracted" / "0"
            d.mkdir(parents=True, exist_ok=True)
            for i in range(2):
                (d / f"f{i}").write_bytes(b"x")
            return 0, "", ""

        with _EnvScope(STEP1_MAX_FILES_PER_EXTRACTION="1"):
            old = step1_guided_extract.run_docker
            step1_guided_extract.run_docker = fake_over
            try:
                files, status = _deep_rescan(fw2, 1, ws2)
            finally:
                step1_guided_extract.run_docker = old
        if status != "over_guard" or files:
            fails.append(f"超限应 over_guard,实得 ({len(files)}, {status})")
        if not fw2.exists() or fw2.stat().st_size != 100:
            fails.append("over_guard 后原件被改动/丢失(原文件永不丢被破坏)")
        if sorted(p.name for p in ws2.glob("*")) != [fw2.name]:
            fails.append(f"over_guard 后应只剩原件,实得 {sorted(p.name for p in ws2.glob('*'))}")
    return fails


# --- 双模式入口 ---

def test_main() -> int:
    failures = 0
    with tempfile.TemporaryDirectory(prefix="test_step1_deep_rescan_") as tmp:
        tmp_path = Path(tmp)
        groups = [
            ("gates 开关与阈值", test_gates_deep_rescan_env()),
            ("reason 常量锁定", test_unsigned_reason_constant()),
            ("触发:命中+原件永存", test_deep_rescan_triggers_and_original_survives(tmp_path)),
            ("触发:小文件/签名/文本豁免", test_deep_rescan_skips_small_signed_text(tmp_path)),
            ("触发:开关关闭", test_deep_rescan_disabled_by_env(tmp_path)),
            ("触发:max_depth 底层豁免", test_deep_rescan_respects_max_depth(tmp_path)),
            ("触发:SDK 豁免", test_deep_rescan_sdk_excluded(tmp_path)),
            ("触发:全树守卫豁免", test_deep_rescan_over_total_excluded(tmp_path)),
            ("防重复:兄弟目录已解不重解", test_deep_rescan_dup_sibling_not_reextracted(tmp_path)),
            ("resume 不重复复扫+产物存活", test_deep_rescan_resume_not_repeated(tmp_path)),
            ("契约:ok 态", test_deep_rescan_contract_ok(tmp_path)),
            ("契约:empty/over_guard", test_deep_rescan_contract_empty_and_over_guard(tmp_path)),
        ]
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
    raise SystemExit(test_main())
