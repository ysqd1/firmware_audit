"""引导解包器单测:M1 纯函数(file_magic)+ M2 循环(step1_guided_extract)。

覆盖 2026-08-13 评审定稿的关键边界:
  - preclassify 二分:容器绝不提前归 product(评审批评 2 的回归锁定)
  - rule_decision 是容器裁决者,与 preclassify 无重叠
  - fdt 永不进 extractor
"""
from __future__ import annotations

import os
import tempfile
from pathlib import Path

from ..step1 import step1_guided_extract
from ..step1.file_magic import (
    sniff_magic,
    shannon_entropy,
    preclassify,
    rule_decision,
)
from ..step1.step1_guided_extract import (
    extract_guided,
    _binwalk_extract_one,
    _load_manifest,
    _save_manifest,
    _MANIFEST_NAME,
)
import contextlib


# --- M1: sniff_magic ---

def test_sniff_magic() -> list[str]:
    fails: list[str] = []
    cases = [
        (b"\x7fELF" + b"\x00" * 60,  ["elf"]),
        (b"\x1f\x8b" + b"\x00" * 60, ["gzip"]),
        (b"\xfd7zXZ\x00" + b"\x00" * 60, ["xz"]),
        (b"BZh" + b"9" * 60,         ["bzip2"]),
        (b"\x37\x7a\xbc\xaf\x27\x1c" + b"\x00" * 60, ["7z"]),
        (b"PK\x03\x04" + b"\x00" * 60, ["zip"]),
        (b"ANDROID!" + b"\x00" * 60, ["bootimg"]),
        (b"\xd0\x0d\xfe\xed" + b"\x00" * 60, ["fdt_be"]),
        (b"\xed\xfe\x0d\xd0" + b"\x00" * 60, ["fdt_le"]),
        (b"MZ" + b"\x00" * 60,       ["pe"]),
        # tar: ustar 在偏移 257
        (b"\x00" * 257 + b"ustar" + b"\x00" * 10, ["tar"]),
        # ext4: 0xEF53 在偏移 0x438
        (b"\x00" * 0x438 + b"\x53\xef" + b"\x00" * 10, ["ext4"]),
        # 文本启发式
        (b"hello world this is plain text file content\n" * 3, ["text"]),
        # 空数据
        (b"", []),
        # 高熵无 NUL 但不全可打印 → 无签名
        (bytes(range(256)) + bytes(range(256)) + bytes(range(256)) + bytes(range(256)), []),
    ]
    for data, want in cases:
        got = sniff_magic(data)
        if got != want:
            fails.append(f"sniff_magic({data[:16]!r}) -> {got},期望 {want}")
    return fails


def test_sniff_magic_lzma_false_positive() -> list[str]:
    """lzma 4 字节防误报:5d 00 00 需第四字节 0x00。"""
    fails: list[str] = []
    # 真实 lzma 头:5d 00 00 00
    if sniff_magic(b"\x5d\x00\x00\x00" + b"\x00" * 60) != ["lzma"]:
        fails.append("真实 lzma 头应命中 lzma")
    # 误报防护:5d 00 00 后跟非 0(如 0x01)不应命中 lzma
    if "lzma" in sniff_magic(b"\x5d\x00\x00\x01" + b"\x00" * 60):
        fails.append("5d 00 00 01 不应命中 lzma(防误报)")
    return fails


# --- M1: shannon_entropy ---

def test_shannon_entropy() -> list[str]:
    fails: list[str] = []
    if shannon_entropy(b"") != 0.0:
        fails.append("空数据熵应为 0")
    if abs(shannon_entropy(b"\x00" * 4096)) > 0.001:
        fails.append("全 0x00 熵应≈0")
    if abs(shannon_entropy(bytes(range(256)) * 16) - 8.0) > 0.01:
        fails.append(f"均匀分布熵应≈8,实得 {shannon_entropy(bytes(range(256))*16):.3f}")
    return fails


# --- M1: preclassify 二分(评审批评 2 的回归锁定) ---

def test_preclassify_binary() -> list[str]:
    fails: list[str] = []
    cases = [
        (["elf"], "product", "ELF→product"),
        (["pe"], "product", "PE→product"),
        (["text"], "product", "文本→product"),
        (["fdt_be"], "skip", "fdt→skip"),
        (["fdt_le"], "skip", "fdt 小端→skip"),
        (["gzip"], "container", "gzip→container(交 rule_decision,不得提前 product)"),
        (["bootimg"], "container", "bootimg→container"),
        ([], "container", "无签名→container(不得提前 product)"),
    ]
    for sigs, want, desc in cases:
        got = preclassify(sigs)
        if got != want:
            fails.append(f"preclassify({sigs}) -> {got},期望 {want} ({desc})")
    return fails


# --- M1: rule_decision 容器裁决 ---

def test_rule_decision() -> list[str]:
    fails: list[str] = []
    continue_sigs = ["gzip", "xz", "lzma", "lz4", "zstd", "bzip2",
                     "cpio", "cpio_newc", "cpio_odc", "tar", "7z", "zip",
                     "squashfs", "cramfs", "jffs2", "ubifs", "ubi",
                     "ext4", "fat",
                     "bootimg", "vendor_boot", "uimage"]
    for s in continue_sigs:
        action, _ = rule_decision([s])
        if action != "continue":
            fails.append(f"rule_decision([{s}]) -> {action},期望 continue")
    finalize_sigs = ["elf", "pe", "text"]
    for s in finalize_sigs:
        action, _ = rule_decision([s])
        if action != "finalize":
            fails.append(f"rule_decision([{s}]) -> {action},期望 finalize")
    # 无签名 → finalize(留树,Step5 strings_query 兜底)
    action, reason = rule_decision([])
    if action != "finalize":
        fails.append(f"rule_decision([]) -> {action},期望 finalize")
    # fdt → skip
    action, _ = rule_decision(["fdt_be"])
    if action != "skip":
        fails.append(f"rule_decision([fdt_be]) -> {action},期望 skip")
    return fails


# --- M2: 主循环(fake extractor,不依赖 Docker) ---

class FakeExtractor:
    """可控 fake:按 mode 产出文件,记录调用参数供断言。

    mode:
        "gzip_chain"  每次产出 1 个 gzip 魔数文件(下一层继续)
        "elf"         每次产出 1 个 ELF 文件(下一层 finalize)
        "fdt"         每次产出 1 个 fdt 魔数文件(应被 preclassify skip)
        "over_guard"  产出超限,返回 over_guard(模拟 extractor 内部守卫)
    """

    def __init__(self, mode: str = "gzip_chain"):
        self.mode = mode
        self.calls: list[tuple[str, int, bytes]] = []  # (name, seq, head4)

    def __call__(self, path: Path, seq: int, parent: Path) -> tuple[list[Path], str]:
        head = b""
        with contextlib.suppress(OSError):
            head = path.read_bytes()[:4]
        self.calls.append((path.name, seq, head))

        d = parent / f"{seq:06d}_{path.name}.extracted"
        d.mkdir(parents=True, exist_ok=True)
        if self.mode == "gzip_chain":
            (d / "next.gz").write_bytes(b"\x1f\x8b" + b"\x00" * 60)
        elif self.mode == "elf":
            (d / "app.elf").write_bytes(b"\x7fELF" + b"\x00" * 60)
        elif self.mode == "fdt":
            (d / "fdt.bin").write_bytes(b"\xd0\x0d\xfe\xed" + b"\x00" * 60)
        elif self.mode == "over_guard":
            # 模拟 extractor 内部守卫检测(真实实现在 _binwalk_extract_one):
            # 产出超限后删除并返回 over_guard。不真的创建 50001 个文件
            # (Windows 小文件写入 5 万次极慢,测试不依赖真实产物)。
            return [], "over_guard"
        # 收集产出
        files = [f for f in d.rglob("*") if f.is_file()]
        return files, "ok"


def _mk_firmware(tmp: Path, name: str = "mini.bin", content: bytes = b"") -> Path:
    p = tmp / name
    p.write_bytes(content if content else b"\x1f\x8b" + b"\x00" * 60)  # 默认 gzip
    return p


def test_extract_guided_loop_terminates(tmp_path: Path) -> list[str]:
    """gzip 链每层产出 gzip → 应一直解到 max_depth 后终局 finalize,不卡死。"""
    fails: list[str] = []
    root = tmp_path / "t1"
    root.mkdir()
    fw = _mk_firmware(root)
    out = root / "out"
    fake = FakeExtractor("gzip_chain")
    result = extract_guided(fw, out, max_depth=3, extractor=fake, check_docker=False)

    if result is None:
        fails.append("extract_guided 返回 None")
    # max_depth=3:循环层 0/1/2,第 3 层(层2)决策时终局 warning 不解,
    # 故 extractor 调用 = max_depth - 1 = 2
    if len(fake.calls) != 2:
        fails.append(f"fake 调用 {len(fake.calls)} 次,期望 2(max_depth=3 链)")
    # 每层产出的 gzip 应留在树里,未被吞
    gz_files = [f for f in out.rglob("*.gz") if f.is_file()]
    if len(gz_files) < 2:
        fails.append(f"树里 gzip 文件 {len(gz_files)} 个,期望 >=2")
    # manifest 存在且第 3 层有 finalize 终局记录
    man = _load_manifest(out)
    if not man:
        fails.append("manifest 为空")
    return fails


def test_extract_guided_fdt_never_extracted(tmp_path: Path) -> list[str]:
    """fdt 魔数文件绝不能进 extractor(preclassify skip)。"""
    fails: list[str] = []
    root = tmp_path / "t2"
    root.mkdir()
    fw = _mk_firmware(root)
    out = root / "out"
    fake = FakeExtractor("fdt")  # 产出 fdt → 下一层应被 skip,不再解
    extract_guided(fw, out, max_depth=3, extractor=fake, check_docker=False)

    # 第 1 次调用解 gzip(合法);第 2 次调用若发生,传进来的必是 fdt(非法)
    for name, seq, head in fake.calls:
        if head == b"\xd0\x0d\xfe\xed":
            fails.append(f"fdt 文件被传入 extractor: {name}(seq {seq})")
    if not fake.calls:
        fails.append("fake 从未被调用(gzip 也应被解)")
    return fails


def test_extract_guided_over_guard(tmp_path: Path) -> list[str]:
    """产出超限 → over_guard,不崩,manifest 记录。"""
    fails: list[str] = []
    root = tmp_path / "t3"
    root.mkdir()
    fw = _mk_firmware(root)
    out = root / "out"
    fake = FakeExtractor("over_guard")
    result = extract_guided(fw, out, max_depth=3, extractor=fake, check_docker=False)

    if result is None:
        fails.append("extract_guided 返回 None(over_guard 不应使主流程失败)")
    man = _load_manifest(out)
    recs = [r for r in man.values() if "50000" in r.get("reason", "")]
    if not recs:
        fails.append(f"manifest 无 over_guard 记录: {man}")
    return fails


def test_binwalk_guard_env_consumed(tmp_path: Path) -> list[str]:
    """STEP1_MAX_FILES_PER_EXTRACTION 消费接线(工单 03):_binwalk_extract_one
    的单次产出守卫按 env 判限——收紧 → over_guard 删产物;缺省 → 默认放行。"""
    fails: list[str] = []
    env_name = "STEP1_MAX_FILES_PER_EXTRACTION"

    def fake_run_docker(image, args, mounts=None, env=None, timeout=0, **kw):
        # 模拟 binwalk 解出 3 个文件:产物目录 <parent>/<文件名>.extracted
        parent = mounts[0][0]
        name = args[args.index("-e") + 1].rsplit("/", 1)[-1]
        d = parent / f"{name}.extracted"
        d.mkdir(parents=True, exist_ok=True)
        for i in range(3):
            (d / f"f{i}").write_bytes(b"x")
        return 0, "", ""

    ws = tmp_path / "ws"
    ws.mkdir()
    old_env = os.environ.get(env_name)
    old_fn = step1_guided_extract.run_docker
    step1_guided_extract.run_docker = fake_run_docker
    try:
        fw = ws / "blob.bin"
        fw.write_bytes(b"\x1f\x8b" + b"\x00" * 60)
        os.environ[env_name] = "2"
        files, status = _binwalk_extract_one(fw, 0, ws)
        if status != "over_guard" or files:
            fails.append(f"上限 2 时 3 文件应 over_guard,got ({len(files)}, {status})")
        if (ws / "000000_blob.bin.extracted").exists():
            fails.append("over_guard 应删除该次产物")

        fw2 = ws / "blob2.bin"
        fw2.write_bytes(b"\x1f\x8b" + b"\x00" * 60)
        os.environ.pop(env_name, None)
        files, status = _binwalk_extract_one(fw2, 1, ws)
        if status != "ok" or len(files) != 3:
            fails.append(f"缺省(默认 5 万)3 文件应放行,got ({len(files)}, {status})")
    finally:
        step1_guided_extract.run_docker = old_fn
        if old_env is None:
            os.environ.pop(env_name, None)
        else:
            os.environ[env_name] = old_env
    return fails


def test_total_guard_env_consumed(tmp_path: Path) -> list[str]:
    """STEP1_MAX_TOTAL_FILES 消费接线(工单 03):收紧 → 全树守卫触发,后续
    候选 finalize 不再解包;缺省 → 同场景不触发。"""
    fails: list[str] = []

    class ManyExtractor:
        """一次产出 3 个 gzip 文件(gzip 链下一层仍会 continue)。"""

        def __init__(self):
            self.calls = 0

        def __call__(self, path: Path, seq: int, parent: Path):
            self.calls += 1
            d = parent / f"{seq:06d}_{path.name}.extracted"
            d.mkdir(parents=True, exist_ok=True)
            files = []
            for i in range(3):
                f = d / f"f{i}.gz"
                f.write_bytes(b"\x1f\x8b" + b"\x00" * 60)
                files.append(f)
            return files, "ok"

    env_name = "STEP1_MAX_TOTAL_FILES"
    old = os.environ.get(env_name)
    try:
        root = tmp_path / "tight"
        root.mkdir()
        fw = _mk_firmware(root)
        fake = ManyExtractor()
        os.environ[env_name] = "2"
        extract_guided(fw, root / "out", max_depth=3, extractor=fake,
                       check_docker=False)
        man = _load_manifest(root / "out")
        guarded = [r for r in man.values()
                   if r.get("reason") == "全树文件数守卫"]
        if not guarded:
            fails.append(f"上限 2 时首批 3 文件应触发全树守卫: {man}")
        if fake.calls != 1:
            fails.append(f"触发守卫后不应继续解包,extractor 调用 {fake.calls} 次,期望 1")

        root2 = tmp_path / "loose"
        root2.mkdir()
        fw2 = _mk_firmware(root2)
        fake2 = ManyExtractor()
        os.environ.pop(env_name, None)
        extract_guided(fw2, root2 / "out", max_depth=3, extractor=fake2,
                       check_docker=False)
        man2 = _load_manifest(root2 / "out")
        if any(r.get("reason") == "全树文件数守卫" for r in man2.values()):
            fails.append("缺省(默认 20 万)同场景不应触发全树守卫")
        if fake2.calls < 2:
            fails.append(f"缺省下应继续解包嵌套容器,extractor 调用 {fake2.calls} 次,期望 >=2")
    finally:
        if old is None:
            os.environ.pop(env_name, None)
        else:
            os.environ[env_name] = old
    return fails


def test_manifest_roundtrip_and_corrupt(tmp_path: Path) -> list[str]:
    """manifest 往返一致;损坏 JSON → 空 dict 不崩。"""
    fails: list[str] = []
    out = tmp_path / "out"
    out.mkdir()
    data = {"a.bin": {"seq": 1, "action": "continue", "done": True}}
    _save_manifest(out, data)
    loaded = _load_manifest(out)
    if loaded != data:
        fails.append(f"manifest 往返不一致: {loaded}")
    # 损坏 JSON
    (out / _MANIFEST_NAME).write_text("{broken json", encoding="utf-8")
    if _load_manifest(out) != {}:
        fails.append("损坏 manifest 应返回空 dict")
    return fails


def test_extract_guided_resume(tmp_path: Path) -> list[str]:
    """断点续传:已 done 的候选跳过(不重复解),未 done 的正常解。"""
    fails: list[str] = []
    root = tmp_path / "t5"
    root.mkdir()
    fw = _mk_firmware(root)
    out = root / "out"
    fake = FakeExtractor("elf")
    extract_guided(fw, out, max_depth=2, extractor=fake, check_docker=False)
    first_calls = len(fake.calls)
    if first_calls != 1:
        fails.append(f"首次运行 fake 调用 {first_calls},期望 1")

    # 再次运行:所有候选已 done → 不应再调 extractor
    fake2 = FakeExtractor("elf")
    extract_guided(fw, out, max_depth=2, extractor=fake2, check_docker=False)
    if fake2.calls:
        fails.append(f"resume 后 fake 又被调用: {fake2.calls}")
    return fails


# --- M2b: scan_tree 树扫描模式(2026-08-14 新增) ---

def test_scan_tree_extracts_nested_container(tmp_path: Path) -> list[str]:
    """scan_tree:树内 gzip 容器被解开落树根,Step2 剥前缀逻辑路径正确。"""
    fails: list[str] = []
    tree = tmp_path / "tree"
    tree.mkdir()
    # 树内嵌套容器: usr/lib/modules/data.tar.gz(gzip)
    (tree / "usr" / "lib" / "modules").mkdir(parents=True)
    gz = tree / "usr" / "lib" / "modules" / "data.tar.gz"
    gz.write_bytes(b"\x1f\x8b" + b"\x00" * 60)  # gzip 魔数
    # 无魔数文件: finalize 留树,不被改名
    (tree / "etc").mkdir()
    (tree / "etc" / "passwd").write_text("root:x:0:0\n", encoding="utf-8")
    # 伪造 manifest 的 renamed_to(模拟之前解过的容器本体)
    _save_manifest(tree, {"old_rel": {"seq": 9, "action": "continue",
                                      "renamed_to": "000009_old.gz", "done": True}})
    (tree / "000009_old.gz").write_bytes(b"\x1f\x8b" + b"\x00" * 10)  # 已改名本体

    fake = FakeExtractor("elf")  # 产出 ELF → 解 1 次后 finalize,不链式
    result = extract_guided(tree, tree, max_depth=3, extractor=fake,
                            check_docker=False, scan_tree=True)

    if result is None:
        fails.append("scan_tree 返回 None")
    # 嵌套 gzip 应被解(1 次),renamed_to 文件不应再解,passwd 是文本不解
    if len(fake.calls) != 1:
        fails.append(f"fake 调用 {len(fake.calls)} 次,期望 1(只有 data.tar.gz)")
    for name, seq, head in fake.calls:
        if name == "000009_old.gz":
            fails.append("renamed_to 文件被重复解包")
        if name == "passwd":
            fails.append("文本文件 passwd 不应被解")
    # 产物落树根: <seq>_data.tar.gz.extracted/
    extracted = [d for d in tree.rglob("*.extracted") if d.is_dir()]
    if not extracted:
        fails.append("解包产物目录未生成")
    return fails


def test_scan_tree_skips_python_sdk(tmp_path: Path) -> list[str]:
    """scan_tree:dist-packages 下 gzip 不解包(391 botocore gz 场景)。"""
    fails: list[str] = []
    tree = tmp_path / "tree2"
    sdk = tree / "usr" / "local" / "lib" / "python3.8" / "dist-packages" / "botocore"
    sdk.mkdir(parents=True)
    # 391 个 botocore endpoint-rule-set gz(只造 3 个代表)
    for i in range(3):
        (sdk / f"endpoint-rule-set-{i}.json.gz").write_bytes(
            b"\x1f\x8b" + b"\x00" * 60)
    # 非 SDK 容器: 树根 data.gz 应被解
    (tree / "data.gz").write_bytes(b"\x1f\x8b" + b"\x00" * 60)

    fake = FakeExtractor("elf")  # 产出 ELF → 解 1 次后 finalize
    extract_guided(tree, tree, max_depth=3, extractor=fake,
                   check_docker=False, scan_tree=True)

    # 只有非 SDK 的 data.gz 被解(1 次),3 个 botocore gz 都不解
    if len(fake.calls) != 1:
        fails.append(f"fake 调用 {len(fake.calls)} 次,期望 1(只有 data.gz)")
    for name, seq, head in fake.calls:
        if "json.gz" in name:
            fails.append(f"Python SDK 容器被解包: {name}")
    return fails


def test_sdk_skip_segment_match_single_file(tmp_path: Path) -> list[str]:
    """SDK 跳过是段级匹配:单文件模式固件文件名含 site-packages 不应被吞(2026-08-14 评审 #1)。"""
    fails: list[str] = []
    root = tmp_path / "t6"
    root.mkdir()
    # 固件文件名叫 site-packages.tar.gz(巧合命名,非 SDK 路径)
    fw = root / "site-packages.tar.gz"
    fw.write_bytes(b"\x1f\x8b" + b"\x00" * 60)
    out = root / "out"
    fake = FakeExtractor("elf")
    extract_guided(fw, out, max_depth=3, extractor=fake,
                   check_docker=False)  # 单文件模式(非 scan_tree)

    # 单文件模式 rel = "site-packages.tar.gz",段级匹配 "/site-packages/" 不命中
    # → 应正常解包(1 次),而非被 SDK 规则吞掉(0 次)
    if len(fake.calls) != 1:
        fails.append(f"fake 调用 {len(fake.calls)} 次,期望 1(单文件模式固件应被解包)")
    return fails


def test_scan_tree_resume_renamed(tmp_path: Path) -> list[str]:
    """scan_tree + manifest:renamed_to 文件不再重复解包。"""
    fails: list[str] = []
    tree = tmp_path / "tree3"
    tree.mkdir()
    gz = tree / "data.gz"
    gz.write_bytes(b"\x1f\x8b" + b"\x00" * 60)
    # 预置 manifest: data.gz 已 done(renamed_to=000007_data.gz)
    _save_manifest(tree, {
        "data.gz": {"seq": 7, "depth": 0, "action": "continue",
                    "renamed_to": "000007_data.gz", "done": True,
                    "files": ["000007_data.gz.extracted/0/out.bin"]},
    })
    (tree / "000007_data.gz").write_bytes(b"\x1f\x8b" + b"\x00" * 60)
    (tree / "000007_data.gz.extracted" / "0").mkdir(parents=True)
    (tree / "000007_data.gz.extracted" / "0" / "out.bin").write_bytes(b"x")

    fake = FakeExtractor("elf")
    extract_guided(tree, tree, max_depth=3, extractor=fake,
                   check_docker=False, scan_tree=True)

    # data.gz 已 done → 不重解;renamed 文件排除 → 不重解;产物 out.bin 是 ELF → finalize
    if fake.calls:
        fails.append(f"resume 后 fake 又被调用: {fake.calls}")
    return fails


def test_main() -> int:
    failures = 0
    with tempfile.TemporaryDirectory(prefix="test_step1_guided_") as tmp:
        tmp_path = Path(tmp)
        groups = [
            ("sniff_magic 魔数命中", test_sniff_magic()),
            ("lzma 4 字节防误报", test_sniff_magic_lzma_false_positive()),
            ("shannon_entropy 边界", test_shannon_entropy()),
            ("preclassify 二分边界", test_preclassify_binary()),
            ("rule_decision 容器裁决", test_rule_decision()),
            ("主循环 gzip 链终止", test_extract_guided_loop_terminates(tmp_path)),
            ("fdt 永不进 extractor", test_extract_guided_fdt_never_extracted(tmp_path)),
            ("over_guard 守卫", test_extract_guided_over_guard(tmp_path)),
            ("单次上限env接线", test_binwalk_guard_env_consumed(tmp_path)),
            ("全树上限env接线", test_total_guard_env_consumed(tmp_path)),
            ("manifest 往返与损坏", test_manifest_roundtrip_and_corrupt(tmp_path)),
            ("断点续传 resume", test_extract_guided_resume(tmp_path)),
            ("scan_tree 解嵌套容器", test_scan_tree_extracts_nested_container(tmp_path)),
            ("scan_tree 跳过 Python SDK", test_scan_tree_skips_python_sdk(tmp_path)),
            ("scan_tree resume renamed", test_scan_tree_resume_renamed(tmp_path)),
            ("SDK 跳过段级匹配", test_sdk_skip_segment_match_single_file(tmp_path)),
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
