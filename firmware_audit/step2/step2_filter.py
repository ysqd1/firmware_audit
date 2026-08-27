"""Step2 - 过滤。

白/黑名单双层过滤,排除标准 Linux 系统文件,保留该审计的内容。
"""
from __future__ import annotations

import hashlib
import re
import time
from pathlib import Path

# binwalk 递归解包产生的嵌套前缀形如:
#   nano14-backup-SANITIZED.tar.xz.extracted/0/decompressed.bin.extracted/0/etc/passwd
# 名单(usr/share, etc/passwd, home/unitree ...)是针对"逻辑固件路径"定义的,
# 直接对 rel_path 做 startswith 永不命中。先剥掉所有 <name>.extracted/<N>/ 前缀。
# 偏移子目录:旧 binwalk 是数字(0/1/...),3.1.1 是 hex(13DE7F0、2919000)。
# 只剥数字会卡在 hex 树 → 白名单全 miss(实测 part05_B_kernel 61 万条目树)。
# 7z 兜底(引导解包器 binwalk 无 extractor 的容器走 7z 扁平解包)无偏移段:
#   <seq>_x.cpio.extracted/etc/passwd —— 偏移目录可缺省。
_EXTRACTED_PREFIX_RE = re.compile(r"^[^/]+\.extracted/(?:[0-9A-Fa-f]+/)?")

# DTB 节点分解噪声:binwalk 对设备树(fdt)递归分解,每个节点/属性一个文件,
# 路径段形如 <节点名>@<hex地址>(bus@0、aconnect@2a41000、rail@vdd_soc、bin@1599)。
# 属性文件平均 16B 纯硬件描述,无审计价值,数量可达数十万(实测 part05 树中
# 绝大多数),在过滤最前排除,连内容哈希都省了。固件文件系统路径几乎不含
# "<名>@<地址>" 段(内核模块/rootfs 均为普通路径),误伤风险可忽略。
_DTB_NODE_SEGMENT_RE = re.compile(r"[^/]+@[^/]+")


def _is_dtb_node(rel_path: str) -> bool:
    """路径含 <名>@<地址> 段(设备树分解节点)→ 应排除。"""
    return bool(_DTB_NODE_SEGMENT_RE.search(rel_path))

# binwalk 对内嵌文件系统(如 squashfs/cpio/jffs2)解出 <fstype>-root 目录:
#   xxx.squashfs.extracted/0/squashfs-root/etc/passwd
#   xxx.cpio.extracted/0/cpio-root/etc/passwd
# 这些 root 目录名(带可选 -N 后缀)也剥掉,否则白名单(etc/passwd)匹配不到。
# 用 <name>-root 通配,覆盖 squashfs-root/cpio-root/jffs2-root/cramfs-root 等。
_ROOT_PREFIX_RE = re.compile(r"^[^/]+-root(?:-\d+)?/")


def _logical_path(rel_path: str) -> str:
    """剥掉 binwalk 嵌套前缀,返回固件内的逻辑路径。

    反复剥 <name>.extracted/<N>/ 与 <fstype>-root/ 前缀直到不再变化。
    例: foo.tar.xz.extracted/0/decompressed.bin.extracted/0/etc/passwd -> etc/passwd
    例: root.squashfs.extracted/0/squashfs-root/etc/passwd -> etc/passwd
    非解包路径(无上述段)原样返回,兼容单测与已扁平化场景。
    """
    rel = rel_path
    while True:
        new = _EXTRACTED_PREFIX_RE.sub("", rel, count=1)
        if new != rel:
            rel = new
            continue
        new = _ROOT_PREFIX_RE.sub("", rel, count=1)
        if new != rel:
            rel = new
            continue
        return rel


# --- 名单从 profile 加载 ---
# 名单(白/黑/系统信任库/系统标准配置)按"逻辑固件路径"定义,外置到
# profiles/<name>.yaml。为什么外置: 换宇树其他机型(如 Yocto/其他构建系统)的
# 固件,路径可能不同,只需新增 profile,不改代码。不做自动探测,显式加载。
_PROFILE_DIR = Path(__file__).resolve().parent.parent / "profiles"
_DEFAULT_PROFILE = "nano-ubuntu"

# Step1 解包完成的断点续跑标记,写在 extracted/ 下(main.py 写入)。
# 它不是固件内容,过滤时必须跳过,否则被当普通文本文件送审。
# 与 main.py 的 _STEP1_DONE_MARKER 保持一致(避免循环 import,故此处重复定义)。
_STEP1_DONE_MARKER = ".step1_done"

# 引导解包器的断点续传 manifest(step1_guided_extract.py 写入)。同样不是
# 固件内容,过滤时必须跳过。
_GUIDED_MANIFEST = "guided_extract.json"


def _load_profile(name: str) -> dict:
    """读取 profile yaml,返回名单 dict;缺文件/解析失败回退空 dict(失败不崩)。

    注意: 返回空 dict 会触发 configure() 的"保持上次状态"保护,但若 pyyaml 缺失,
    模块级名单初始即空,Step2 会退化为"几乎全放行",数千个 ELF 涌入 Step4 造成
    数小时时长与 OOM 风险。因此 pyyaml 缺失必须醒目告警,不能静默。
    """
    try:
        import yaml
    except ImportError:
        print("[Step2] 警告: pyyaml 未安装,profile 名单未加载,过滤将退化为放行!")
        print("[Step2] 提示: 请执行 pip install -r firmware_audit/requirements.txt 修复")
        return {}
    path = _PROFILE_DIR / f"{name}.yaml"
    if not path.is_file():
        print(f"[Step2] 警告: profile 文件不存在: {path.name},名单未加载,过滤将退化为放行!")
        return {}
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception as e:
        print(f"[Step2] 警告: profile 解析失败({path.name}): {e},名单未加载,过滤将退化为放行!")
        return {}


def _profile_list(key: str) -> list:
    """从当前 profile 取名单;缺失时回退空列表(不崩)。"""
    return _PROFILE.get(key) or []


# 当前生效的 profile(默认 nano-ubuntu)。configure() 会重载并更新下面的模块级名单。
_PROFILE = _load_profile(_DEFAULT_PROFILE)

BLACKLIST_DIRS = _profile_list("BLACKLIST_DIRS")
BLACKLIST_PATTERNS = _profile_list("BLACKLIST_PATTERNS")
WHITELIST_DIRS = _profile_list("WHITELIST_DIRS")
WHITELIST_ETC = _profile_list("WHITELIST_ETC")
SYSTEM_TRUST_DIRS = _profile_list("SYSTEM_TRUST_DIRS")
SYSTEM_STD_DIRS = _profile_list("SYSTEM_STD_DIRS")
BUILD_ARTIFACT_PATTERNS = _profile_list("BUILD_ARTIFACT_PATTERNS")


def configure(profile_name: str) -> None:
    """加载指定 profile 并更新模块级名单。

    step3_classify 在函数体内查找全局 SYSTEM_TRUST_DIRS,configure 后即便已被
    import 也立即生效(全局名在调用时解析)。

    非线程安全:单进程顺序调用。同一进程多次 run_pipeline(不同 target/不同
    profile)时,必须显式传入 profile;若传了不存在的 profile,本函数保持上次
    有效名单不变(不把模块级名单清空),避免跨调用污染。
    """
    new_profile = _load_profile(profile_name)
    # profile 不存在/解析失败时 _load_profile 返回空 dict。此时不修改模块级名单,
    # 保持上次有效状态——否则误传 profile 名会把 WHITELIST_DIRS 等清空,后续
    # 过滤全部放行(所有文件默认保留),埋下高误报隐患。
    if not new_profile:
        return
    global _PROFILE, BLACKLIST_DIRS, BLACKLIST_PATTERNS
    global WHITELIST_DIRS, WHITELIST_ETC, SYSTEM_TRUST_DIRS, SYSTEM_STD_DIRS
    global BUILD_ARTIFACT_PATTERNS
    _PROFILE = new_profile
    BLACKLIST_DIRS = _profile_list("BLACKLIST_DIRS")
    BLACKLIST_PATTERNS = _profile_list("BLACKLIST_PATTERNS")
    WHITELIST_DIRS = _profile_list("WHITELIST_DIRS")
    WHITELIST_ETC = _profile_list("WHITELIST_ETC")
    SYSTEM_TRUST_DIRS = _profile_list("SYSTEM_TRUST_DIRS")
    SYSTEM_STD_DIRS = _profile_list("SYSTEM_STD_DIRS")
    BUILD_ARTIFACT_PATTERNS = _profile_list("BUILD_ARTIFACT_PATTERNS")


# --- 证书/密钥/脚本/配置扩展名(通用,不随固件型号变化,故留在代码里) ---
CERT_EXTENSIONS = {
    ".pem", ".key", ".crt", ".cer", ".pub", ".gpg", ".asc", ".p12", ".pfx",
}

SCRIPT_EXTENSIONS = {
    ".py", ".sh", ".bash", ".zsh", ".cpp", ".c", ".h", ".hpp", ".cc",
    ".js", ".lua", ".rb", ".pl", ".php",
}

CONFIG_EXTENSIONS = {
    ".conf", ".cfg", ".ini", ".yaml", ".yml", ".json", ".toml", ".env",
    ".service", ".mount", ".socket",
}


def _is_system_trust(rel_path: str) -> bool:
    """判断逻辑路径是否落在系统信任库目录下。"""
    logical = _logical_path(rel_path)
    for d in SYSTEM_TRUST_DIRS:
        if logical == d or logical.startswith(d + "/"):
            return True
    return False


def _is_whitelisted(rel_path: str) -> bool:
    """白名单优先级最高,命中即保留。

    匹配基于"逻辑固件路径"(已剥掉 binwalk 的 .extracted/N/ 嵌套前缀)。
    """
    logical = _logical_path(rel_path)
    # 宇树定制目录
    for w in WHITELIST_DIRS:
        if logical == w or logical.startswith(w + "/"):
            return True
    # etc 敏感配置
    for w in WHITELIST_ETC:
        if logical == w or logical.startswith(w + "/"):
            return True
    return False


def _is_blacklisted(rel_path: str) -> bool:
    """黑名单命中即排除。基于逻辑固件路径匹配。"""
    logical = _logical_path(rel_path)
    for b in BLACKLIST_DIRS:
        if logical.startswith(b + "/") or logical == b:
            return True
    for p in BLACKLIST_PATTERNS:
        if p in logical:
            return True
    return False


def _is_build_artifact(rel_path: str) -> bool:
    """逻辑路径是否命中构建中间产物(CMake/Make 缓存与元数据)。

    命中即排除,优先级高于白名单。只匹配明确构建产物,不含 .a/.o(可能有审计价值)。
    """
    logical = _logical_path(rel_path)
    for p in BUILD_ARTIFACT_PATTERNS:
        if p in logical:
            return True
    return False


def _is_system_std(rel_path: str) -> bool:
    """逻辑路径是否落在系统标准配置目录下(发行版模板/样例,审计无价值)。

    与 SYSTEM_TRUST_DIRS 不同: 信任库只"标记"不删除(证书仍可查);
    系统标准配置直接排除,降低 Step3/Step4 无效扫描与误报。
    白名单(WHITELIST_ETC)优先于本名单,故必须保留的敏感配置不受影响。
    """
    logical = _logical_path(rel_path)
    for d in SYSTEM_STD_DIRS:
        if logical == d or logical.startswith(d + "/"):
            return True
    return False


def _has_cert_extension(name: str) -> bool:
    return Path(name).suffix.lower() in CERT_EXTENSIONS


def _quick_content_hash(f: Path) -> str | None:
    """读文件前 4KB 做快速哈希(小文件全读),供双副本去重 key 使用。

    双副本是 binwalk 对同一原始文件(如 etc/passwd)的两份字节完全一致的拷贝,
    前 4KB 哈希足以区分/配对。读失败(权限/损坏)返回 None,调用方据此跳过去重。
    """
    try:
        with open(f, "rb") as fh:
            data = fh.read(4096)
    except OSError:
        return None
    return hashlib.sha1(data).hexdigest()


def _dedup(kept: list[Path], extracted_root: Path) -> list[Path]:
    """双副本去重:剔除 binwalk 递归解包造成的同一逻辑文件的多份拷贝。

    binwalk 递归解包会把压缩流刻成 decompressed.bin,再把它解出整个 rootfs 副本,
    于是同一逻辑文件出现两份(如 etc/passwd):
      1. nano..tar.xz.extracted/0/etc/passwd
      2. nano..tar.xz.extracted/0/decompressed.bin.extracted/0/etc/passwd
    经 _logical_path 都映射到 etc/passwd,导致 Step3/4 处理量翻倍、Step5 报告重复。

    key = (逻辑路径, 内容快速哈希)。同一 key 只留一份,优先保留物理路径最短
    (更接近根、非 decompressed.bin 嵌套)的那份。返回去重后的列表。
    """
    # key -> 当前择优保留的下标(final 中)
    seen: dict[tuple[str, str], int] = {}
    final: list[Path] = []
    dup_count = 0
    for f in kept:
        h = _quick_content_hash(f)
        if h is None:
            final.append(f)  # 读不了一致内容的文件,不去重
            continue
        try:
            rel = str(f.relative_to(extracted_root)).replace("\\", "/")
        except ValueError:
            rel = f.name
        key = (_logical_path(rel), h)
        prev = seen.get(key)
        if prev is None:
            seen[key] = len(final)
            final.append(f)
            continue
        dup_count += 1
        prev_f = final[prev]
        try:
            prev_rel = str(prev_f.relative_to(extracted_root)).replace("\\", "/")
        except ValueError:
            prev_rel = prev_f.name
        if len(rel) < len(prev_rel):
            final[prev] = f  # 新文件物理路径更短,替换
    if dup_count:
        print(f"[Step2] 去重: {dup_count} 个重复文件")
    return final


# ELF 内容级去重: 仅对"库/模块"类 ELF 生效(见 _dedup_by_content)
_ELF_DUP_SUFFIXES = (".so", ".ko", ".elf")


def _is_elf_dup_candidate(name: str) -> bool:
    """是否为 ELF 内容去重的候选: .so/.so.N/.ko/.elf 或 .so.N.M。

    .so 家族是 Linux 符号链接约定,解包时常被复制成实体副本
    (libddsc.so / libddsc.so.0 / libglog.so.0.5.0),内容全同。
    只去重库/模块类,不去重 .bin/.out(可能同名同内容但语义不同)。
    """
    n = name.lower()
    if n.endswith(_ELF_DUP_SUFFIXES):
        return True
    # .so.N 或 .so.N.M(如 libddsc.so.0、libglog.so.0.5.0)
    if ".so." in n and n.rpartition(".so.")[2].replace(".", "").isdigit():
        return True
    return False


def _is_base_name(a: str, b: str) -> bool:
    """a 是否比 b 更"基础"(更接近符号链接目标名)。

    择优规则: libddsc.so 优于 libddsc.so.0 优于 libddsc.so.0.5.0。
    即: .so 结尾(无版本号)> 版本段更短。返回 True 表示 a 应保留。
    """
    if a == b:
        return False
    # .so 结尾(无版本号)最基础
    a_base = a.lower().endswith(".so")
    b_base = b.lower().endswith(".so")
    if a_base != b_base:
        return a_base
    # 都带版本号: 版本段短者优先(libddsc.so.0 < libddsc.so.0.5.0)
    a_ver = a.lower().split(".so.")[-1] if ".so." in a.lower() else ""
    b_ver = b.lower().split(".so.")[-1] if ".so." in b.lower() else ""
    return len(a_ver) < len(b_ver)


def _dedup_by_content(kept: list[Path]) -> list[Path]:
    """ELF 内容级去重: md5 相同的库副本只留一份(基础名优先)。

    背景: Linux 库的符号链接约定(.so → .so.N → .so.N.M)在固件解包时
    常被复制成内容完全相同的实体文件(libddsc.so / .so.0 全同,实测
    target/1 有 16 组 17 个)。Step4 对每份都跑 Ghidra 是双倍浪费时间
    (libddsc.so 单跑 268s)。

    与 _dedup 的区别: _dedup 按 (逻辑路径, 哈希) 去 binwalk 双副本
    (同一逻辑文件两份);本函数按 (内容哈希) 去不同名的相同库。

    仅对库/模块类 ELF(.so/.ko/.elf)生效: 文本/配置不同名但同内容
    有独立语义(如多处复制),误删风险大,不去重。

    key = 前 4KB 哈希(实测与全文 md5 一致,libddsc 等抽查全同)。
    """
    seen: dict[str, int] = {}  # content_hash -> final 下标
    final: list[Path] = []
    dup_count = 0
    for f in kept:
        if not _is_elf_dup_candidate(f.name):
            final.append(f)
            continue
        h = _quick_content_hash(f)
        if h is None:
            final.append(f)  # 读不了不去重
            continue
        prev = seen.get(h)
        if prev is None:
            seen[h] = len(final)
            final.append(f)
            continue
        dup_count += 1
        prev_f = final[prev]
        # 基础名优先: libddsc.so 优于 libddsc.so.0
        if _is_base_name(f.name, prev_f.name):
            final[prev] = f
    if dup_count:
        print(f"[Step2] ELF 内容去重: {dup_count} 个库副本(保留基础名 .so)")
    return final


def _sanity_check_whitelist(kept: list[Path], extracted_root: Path) -> None:
    """健全性断言:_logical_path 剥前缀失败时的静默失效兜底。

    若 binwalk 版本/固件结构变化导致命名一变,正则剥不掉 .extracted/N/ 前缀,
    白名单会静默全 miss → 所有文件落"默认保留"分支,过滤变空操作且无提示。
    这里统计白名单目录/敏感配置的实际命中数,为 0 时打印醒目警告。
    仅警告不中断(失败不崩原则)。
    """
    hit_dirs = 0
    hit_etc = 0
    for f in kept:
        try:
            rel = str(f.relative_to(extracted_root)).replace("\\", "/")
        except ValueError:
            rel = f.name
        logical = _logical_path(rel)
        for w in WHITELIST_DIRS:
            if logical == w or logical.startswith(w + "/"):
                hit_dirs += 1
                break
        for w in WHITELIST_ETC:
            if logical == w or logical.startswith(w + "/"):
                hit_etc += 1
                break
    if WHITELIST_DIRS and hit_dirs == 0:
        print(f"[Step2] 提示: 白名单目录 {', '.join(WHITELIST_DIRS)} 0 命中。"
              "若该分区是 kernel/dtb/recovery(非完整系统),此为预期;"
              "若应含 rootfs,请检查 binwalk 输出结构")
    if WHITELIST_ETC and hit_etc == 0:
        print(f"[Step2] 提示: 白名单敏感配置 {', '.join(WHITELIST_ETC)} 0 命中。"
              "若该分区是 kernel/dtb/recovery(非完整系统),此为预期;"
              "若应含 rootfs,请检查 binwalk 输出结构")


def filter_files(extracted_root: Path, profile: str | None = None) -> list[Path]:
    """遍历解包目录,返回该审计的文件路径列表。

    Args:
        extracted_root: binwalk 解包根目录
        profile: profile 名(见 profiles/)。None 用默认 nano-ubuntu。

    Returns:
        通过过滤的文件路径列表(绝对路径)
    """
    if profile:
        configure(profile)
    extracted_root = Path(extracted_root).resolve()
    kept: list[Path] = []
    total = 0
    dtb_skipped = 0
    _t0 = time.monotonic()
    _last_report = 0

    for f in extracted_root.rglob("*"):
        total += 1
        # 进度输出:大规模解包树(实测 part05_B_kernel 61.6 万条目)遍历耗时长,
        # 每 5000 条报告一次,避免"看起来卡死"(曾误判为死机后 Ctrl+C 中断)。
        if total - _last_report >= 5000:
            print(f"[Step2] 已遍历 {total} 条目({time.monotonic() - _t0:.0f}s, "
                  f"DTB 过滤 {dtb_skipped})...")
            _last_report = total
        # Step1 断点续传标记(main.py 写的 .step1_done)不是固件内容,
        # 不送审,否则浪费一次分类/扫描。常量与 main.py 保持一致。
        if f.name == _STEP1_DONE_MARKER:
            continue
        # 引导解包器 manifest(step1_guided_extract.py 写)同理不送审。
        if f.name == _GUIDED_MANIFEST:
            continue
        # binwalk 可能创建损坏的符号链接,Windows 下 is_file 会抛 OSError
        try:
            if not f.is_file():
                continue
        except OSError:
            continue
        try:
            rel = str(f.relative_to(extracted_root)).replace("\\", "/")
        except ValueError:
            continue

        # 0. DTB 节点分解噪声优先排除(设备树属性文件,数十万级,无审计价值)
        if _is_dtb_node(rel):
            dtb_skipped += 1
            continue

        # 1. 构建中间产物优先排除(如 CMakeCache.txt/.cmake/.make/.map/.md5)。
        #    有"优先于白名单"语义: home/unitree 虽是白名单整目录,但构建产物是
        #    明确垃圾,不应保留;而 .sh/.py/.yaml/.h 等定制文件不受影响,仍全保留。
        if _is_build_artifact(rel):
            continue

        # 1. 白名单优先(厂商定制 + etc 敏感配置),任何降噪不得误伤
        if _is_whitelisted(rel):
            kept.append(f)
            continue

        # 2. 证书/密钥强制保留
        if _has_cert_extension(f.name):
            kept.append(f)
            continue

        # 3. 系统标准配置目录排除(发行版模板/样例,审计无价值)
        if _is_system_std(rel):
            continue

        # 4. 黑名单排除
        if _is_blacklisted(rel):
            continue

        # 5. 其他文件:默认保留(让 Step3 分类决定是否跳过)
        #    主要是非系统脚本/配置/ELF,这些在这里放行
        kept.append(f)

    if dtb_skipped:
        print(f"[Step2] 排除 DTB 节点文件: {dtb_skipped} 个(设备树分解噪声)")

    # 双副本去重:binwalk 递归解包会把同一逻辑文件解出两份(等/passwd 等),
    # 剔除重复,只留物理路径最短的那份。不影响白名单/证书强制保留语义。
    kept = _dedup(kept, extracted_root)

    # ELF 内容级去重: md5 相同的库副本(libddsc.so/.so.0)只留基础名一份,
    # 避免 Step4 对每份都跑 Ghidra 双倍浪费时间(实测 16 组 17 个)。
    # 在 _dedup 之后: 先按逻辑路径去双副本,再按内容去同库不同名。
    kept = _dedup_by_content(kept)

    # 健全性断言:白名单若一个都没命中,怀疑剥前缀失败(仅警告不中断)。
    _sanity_check_whitelist(kept, extracted_root)

    print(f"[Step2] 过滤完成(profile={profile or _DEFAULT_PROFILE}): {total} -> {len(kept)} 文件")
    return kept
