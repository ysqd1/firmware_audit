"""Step1 - 解包(旧 binwalk -Me 递归解包,现为兜底函数)。

主路径是 step1_guided_extract.py 的引导解包器;本模块的 -Me 递归解包
仅在引导解包器失败时由 main.py 调用兜底(见 main.py Step1 调用段)。
"""
from __future__ import annotations

from pathlib import Path

from ..docker.docker_utils import run_docker, docker_available

BINWALK_IMAGE = "binwalk"
CONTAINER_INPUT_DIR = "/work/input"
CONTAINER_OUTPUT_DIR = "/work/output"


def extract(firmware_path: Path, output_dir: Path) -> Path | None:
    """用 binwalk -Me 解包固件(兜底,引导解包器失败时由 main.py 调用)。

    Args:
        firmware_path: 固件文件路径
        output_dir: 解包输出目录(会创建)

    Returns:
        解包根目录(output_dir/extractions),失败返回 None
    """
    firmware_path = Path(firmware_path).resolve()
    output_dir = Path(output_dir).resolve()

    if not firmware_path.is_file():
        print(f"[Step1] 固件不存在: {firmware_path}")
        return None

    if not docker_available(BINWALK_IMAGE):
        print(f"[Step1] Docker未打开或镜像不可用: {BINWALK_IMAGE}")
        return None

    output_dir.mkdir(parents=True, exist_ok=True)

    # binwalk -Me <file> -d <output_dir>
    # 镜像 entrypoint 是 binwalk,直接传参
    # 文件挂载到 /work/input,output 挂载到 /work/output
    args = [
        "-Me",
        f"{CONTAINER_INPUT_DIR}/{firmware_path.name}",
        "-d", CONTAINER_OUTPUT_DIR,
    ]
    mounts = [
        (firmware_path.parent, CONTAINER_INPUT_DIR),
        (output_dir, CONTAINER_OUTPUT_DIR),
    ]

    print(f"[Step1] binwalk -Me {firmware_path.name}")
    rc, stdout, stderr = run_docker(
        BINWALK_IMAGE, args, mounts=mounts, timeout=3600
    )

    if rc != 0:
        print(f"[Step1] binwalk 失败(退出码 {rc})")
        print(stderr[:2000])
        return None

    # binwalk -d 直接输出到 output_dir,创建 <filename>.extracted/ 子目录
    # 不额外创建 extractions 子目录
    if not output_dir.exists() or not any(output_dir.iterdir()):
        print(f"[Step1] 输出目录为空: {output_dir}")
        return None

    print(f"[Step1] 解包完成 -> {output_dir}")
    return output_dir


def verify(extractions_root: Path) -> bool:
    """验证解包结果:目录存在且含文件。"""
    extractions_root = Path(extractions_root)
    if not extractions_root.is_dir():
        return False
    for _ in extractions_root.rglob("*"):
        return True
    return False
