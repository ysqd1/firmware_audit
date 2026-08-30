"""Step3 - 分类。

用 Docker binwalk 镜像里的 file 命令批量识别文件类型,按类型分流。
分类用 file 硬编码,不用 LLM。
"""
from __future__ import annotations

import tempfile
from pathlib import Path

from ..docker.docker_utils import run_docker, docker_available
from ..models import FileInfo
from ..file_rules import is_system_trust, logical_path
from ..step2.step2_filter import (
    SCRIPT_EXTENSIONS,
    CONFIG_EXTENSIONS,
)

BINWALK_IMAGE = "binwalk"
CONTAINER_ROOT = "/work/root"
CONTAINER_WS = "/work/ws"


# --- Crypto 分类辅助 ---
#
# file 命令对密码学材料的输出模式(实测固件样本归纳):
#   "PEM certificate"                   → X.509 PEM 证书
#   "Certificate, Version=3"            → X.509 DER 证书(file 不带 PEM 字样)
#   "OpenSSH ... public key"            → OpenSSH 公钥
#   "OpenSSH ... private key"           → OpenSSH 私钥(file 输出可能为 OpenSSH private key)
#   "OpenPGP Public Key"                → OpenPGP/GPG 公钥
#   "PGP public key block"              → PGP ASCII armored
#   "PKCS12"                            → PKCS#12 证书包
# 扩展名兜底(file 未识别时):
#   .pem/.crt/.cer/.der → x509;  .pub → public_key;  .key → private_key
#   .gpg/.asc → gpg;  .p12/.pfx → pkcs12

# file 输出关键词 -> crypto 类型(按优先级,file 输出最准)
# 优先级: private key > public key > x509 证书。
# 为什么私钥要独立成类: GNU file 对 RSA 私钥输出 "PEM RSA private key",
# 旧名单按 "pem rsa" 误归 crypto_x509,而 Step4 只按证书解析私钥必然失败
# (parse_error,is_private 恒为 False),固件审计最核心的私钥对象被忽略。
# 注意: OpenSSH 元组在 private key 元组之前,故 "OpenSSH private key" 仍归 ssh;
# private key 元组里的 "openssh private key" 是兜底,实际不会先命中。
_CRYPTO_FILE_KEYWORDS = [
    # (关键词列表,                      匹配类型)
    (("pkcs12", "pkcs#12"),          "crypto_pkcs12"),
    (("openssh",),                   "crypto_ssh"),       # OpenSSH 公/私钥都先归 ssh,Step4 再细分
    (("openpgp", "pgp public key"),  "crypto_gpg"),
    (("pem private key", "pem rsa private key", "pem ec private key",
      "pem dsa private key", "openssh private key", "private key"), "crypto_private_key"),
    (("pem public key", "pem rsa public key", "pem ec public key",
      "pem dsa public key", "openssh public key"), "crypto_public_key"),
    (("pem certificate",),           "crypto_x509"),      # PEM 证书(file 输出 PEM certificate)
    (("certificate", "version="),    "crypto_x509"),      # DER 证书(file 输出 Certificate, Version=3)
]

# 扩展名兜底(file 未识别时)
_CRYPTO_EXT_MAP = {
    ".pem": "crypto_x509",
    ".crt": "crypto_x509",
    ".cer": "crypto_x509",
    ".der": "crypto_x509",
    ".pub": "crypto_public_key",
    ".key": "crypto_private_key",
    ".gpg": "crypto_gpg",
    ".asc": "crypto_gpg",
    ".p12": "crypto_pkcs12",
    ".pfx": "crypto_pkcs12",
}


def _classify_crypto(file_output: str, suffix: str) -> str:
    """识别密码学材料细分类型。

    优先用 file 命令输出(最准),其次用扩展名兜底。
    返回 crypto_* 类型字符串,非密码学文件返回空字符串。

    注意: 不再用单一的 cert 类型。所有密码学相关文件都归 crypto_*。
    file 识别不出的密码学扩展名文件归 crypto_unknown,绝不归 unknown,
    避免 Step5 漏审。
    """
    out = file_output.lower()

    # 1. file 命令关键词匹配(优先)
    for keywords, ctype in _CRYPTO_FILE_KEYWORDS:
        for kw in keywords:
            if kw in out:
                return ctype

    # 2. 扩展名兜底(file 没识别但扩展名是密码学相关)
    #    关键:仅当 file 输出为空或未给出明确类型信号时才兜底。
    #    file 明确识别为纯文本(实测 etc/brlapi.key 是 ASCII text,33 字节)时
    #    绝不当 crypto,否则 Step4 会错误当私钥解析。
    if suffix in _CRYPTO_EXT_MAP:
        if any(t in out for t in ("text", "ascii", "utf-8", "json", "xml")):
            return ""
        return _CRYPTO_EXT_MAP[suffix]

    # 3. 既无 file 识别也无扩展名 → 不是密码学文件
    return ""


def _classify_one(file_output: str, suffix: str) -> str:
    """根据 file 命令输出 + 扩展名判定类型。

    返回: elf_exec / elf_lib / script / source / config / text /
          crypto_x509 / crypto_ssh / crypto_gpg / crypto_pkcs12 /
          crypto_private_key / crypto_public_key / crypto_unknown /
          unknown

    Crypto 细分原因: 固件里密码学材料格式多样(PEM/DER/OpenSSH/OpenPGP/PKCS12),
    file 命令已能精确区分。Step3 若全部归 cert,Step4 只能按 PEM 解析,
    导致 OpenSSH/GPG/DER 全部失败(实测 152/293 个 unknown_pem)。
    细分后 Step4 可按类型 dispatch 到对应 parser。
    """
    out = file_output.lower()

    # ELF 细分(优先级最高,避免 ELF 误判为 crypto)
    if "elf" in out:
        if "shared object" in out or "relocatable" in out:
            return "elf_lib"
        if "executable" in out:
            return "elf_exec"
        return "elf_lib"  # 其他 ELF 归入 lib

    # --- Crypto 细分(file 输出优先,扩展名兜底)---
    crypto_type = _classify_crypto(file_output, suffix)
    if crypto_type:
        return crypto_type

    # 脚本(file 说 script,或扩展名命中)
    if "script" in out and "text" in out:
        return "script"
    if "python" in out:
        return "script"
    if "shell" in out or "bash" in out or "zsh" in out:
        return "script"
    if suffix in SCRIPT_EXTENSIONS:
        return "script" if suffix in {".py", ".sh", ".bash", ".zsh", ".js", ".lua", ".rb", ".pl", ".php"} else "source"

    # 配置(扩展名)
    if suffix in CONFIG_EXTENSIONS:
        return "config"

    # 普通文本
    if "text" in out or "ascii" in out or "utf-8" in out or "json" in out or "xml" in out:
        return "text"

    return "unknown"


def classify(files: list[Path], extracted_root: Path) -> list[FileInfo]:
    """对过滤后的文件列表分类,返回 FileInfo 列表。

    用 Docker file 命令批量识别,失败时降级为纯扩展名分类。

    Args:
        files: Step2 过滤后的文件路径列表
        extracted_root: 解包根目录(用于算 rel_path 和挂载)

    Returns:
        FileInfo 列表
    """
    extracted_root = Path(extracted_root).resolve()

    if not files:
        print("[Step3] 无文件可分类")
        return []

    # 构造相对路径列表,写入临时 filelist
    rel_paths = []
    path_map: dict[str, Path] = {}  # rel -> abs
    for f in files:
        try:
            rel = str(f.relative_to(extracted_root)).replace("\\", "/")
            rel_paths.append(rel)
            path_map[rel] = f
        except ValueError:
            continue

    # 调 Docker file -f 批量识别
    file_outputs: dict[str, str] = {}
    use_docker = docker_available(BINWALK_IMAGE)

    if use_docker and rel_paths:
        # 用临时目录挂载 filelist(单文件挂载在 Windows Docker 不可靠)
        with tempfile.TemporaryDirectory() as tmpdir:
            filelist_path = Path(tmpdir) / "filelist.txt"
            # 必须 LF 换行 + 无 BOM,否则 Linux 容器里 file 把 \r 当文件名一部分
            filelist_path.write_bytes("\n".join(rel_paths).encode("utf-8"))

            args = ["-f", f"{CONTAINER_WS}/filelist.txt"]
            mounts = [
                (extracted_root, CONTAINER_ROOT),
                (Path(tmpdir), CONTAINER_WS),
            ]
            rc, stdout, stderr = run_docker(
                BINWALK_IMAGE,
                args,
                mounts=mounts,
                entrypoint="file",
                workdir=CONTAINER_ROOT,
                timeout=600,
            )
            if rc == 0:
                for line in stdout.splitlines():
                    if ":" in line:
                        rel, desc = line.split(":", 1)
                        rel = rel.strip()
                        # file 可能输出 ./relpath,去掉 ./
                        if rel.startswith("./"):
                            rel = rel[2:]
                        file_outputs[rel] = desc.strip()
            else:
                print(f"[Step3] Docker file 失败(退出码 {rc}),降级纯扩展名分类")
                if stderr:
                    print(f"[Step3] stderr: {stderr[:500]}")
                use_docker = False
    elif not use_docker:
        print("[Step3] Docker 不可用,降级纯扩展名分类")

    # 构建 FileInfo
    fileinfos: list[FileInfo] = []
    type_counts: dict[str, int] = {}
    trust_count = 0

    for rel, abs_path in path_map.items():
        suffix = Path(rel).suffix.lower()
        file_out = file_outputs.get(rel, "")
        # file -f 批量模式下个别文件偶发 "cannot open"(实测 en.hex 一次出现,
        # 直接 file 正常;属环境临时问题,但须有兜底不静默归 unknown)。
        # .hex 是 Intel HEX 固件(ASCII 文本),归 text(Step4 分诊的 text 嗅探
        # 会把它捞出来转二进制);其他按空输出处理(归 unknown → Step4 分诊)。
        if "cannot open" in file_out or "no such file" in file_out:
            file_out = "ASCII text" if suffix == ".hex" else ""
        ftype = _classify_one(file_out, suffix)

        try:
            size = abs_path.stat().st_size
        except (OSError, ValueError):
            size = 0

        fi = FileInfo(
            path=str(abs_path),
            rel_path=rel,
            type=ftype,
            size=size,
            subtype=file_out,
            is_system_trust=is_system_trust(logical_path(rel)),
        )
        fileinfos.append(fi)
        type_counts[ftype] = type_counts.get(ftype, 0) + 1
        if fi.is_system_trust:
            trust_count += 1

    # 统计
    summary = ", ".join(f"{t}={c}" for t, c in sorted(type_counts.items()))
    print(f"[Step3] 分类完成: {len(fileinfos)} 文件 ({summary})")
    if trust_count:
        print(f"[Step3] 其中系统信任库文件 {trust_count} 个(已标记 is_system_trust,非厂商凭证)")
    return fileinfos
