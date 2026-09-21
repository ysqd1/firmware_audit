#!/usr/bin/env bash
# 冒烟宿主驱动(票 03):解析工作区 target/6、target/8 的 squashfs-root,
# 挂进 firm_audit/qemu-exec 容器跑 smoke_test.sh。缺任一依赖明确报错退出,不静默。
#
# 用法: firmware_audit/docker/qemu-exec/run_smoke.sh
# 路径可用环境变量覆盖: TGT6_ROOT=<squashfs-root> TGT8_ROOT=<squashfs-root>
set -euo pipefail
cd "$(dirname "$0")"

. ./pins.env

REPO_ROOT="../../../"
TGT6_ROOT="${TGT6_ROOT:-$REPO_ROOT/target/6/process/extracted/000000_DIR890LA1_FW111b02_20170519_beta01.bin.extracted/1C0094/squashfs-root}"
TGT8_ROOT="${TGT8_ROOT:-$REPO_ROOT/target/8/process/extracted/000000_openwrt-19.07.0-ath79-generic-tplink_archer-c7-v2-squashfs-sysupgrade.bin.extracted/185BC4/squashfs-root}"

if ! docker image inspect "$QEMU_EXEC_IMAGE" >/dev/null 2>&1; then
    echo "FAIL: 镜像 $QEMU_EXEC_IMAGE 不存在。先运行 build_image.sh。" >&2
    exit 1
fi
for pair in "tgt6:$TGT6_ROOT:usr/sbin/nvram" "tgt8:$TGT8_ROOT:bin/busybox"; do
    name="${pair%%:*}"; rest="${pair#*:}"; root="${rest%%:*}"; bin="${rest#*:}"
    if [ ! -x "$root/$bin" ]; then
        echo "FAIL: target/$name 冒烟二进制不存在: $root/$bin(解包树缺失?)" >&2
        exit 1
    fi
done

docker run --rm --network none --entrypoint bash \
    -v "$PWD/smoke_test.sh":/smoke.sh:ro \
    -v "$(cd "$TGT6_ROOT" && pwd)":/work/tgt6:ro \
    -v "$(cd "$TGT8_ROOT" && pwd)":/work/tgt8:ro \
    "$QEMU_EXEC_IMAGE" /smoke.sh
