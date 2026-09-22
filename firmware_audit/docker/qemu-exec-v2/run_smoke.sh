#!/usr/bin/env bash
# 票 16:执行镜像冒烟(宿主驱动;镜像无 shell,逐条直接 argv 调用)。
# 覆盖:版本/身份可查询、形状隔离(无 sh/dash)、ARM32 LE 与 MIPS32 BE
# 真实固件样本在 proot+qemu 下执行、补丁拒绝面在镜像内成立。
# 用法: run_smoke.sh(可 TGT6_SQUASH/TGT8_SQUASH 覆盖样本根)
set -u -o pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$DIR/pins.env"
IMG=$QEMU_EXEC_V2_IMAGE
REPO=$(cd "$DIR/../../.." && pwd)
TGT6_SQUASH=${TGT6_SQUASH:-$REPO/target/6/process/extracted/000000_DIR890LA1_FW111b02_20170519_beta01.bin.extracted/1C0094/squashfs-root}
TGT8_SQUASH=${TGT8_SQUASH:-$REPO/target/8/process/extracted/000000_openwrt-19.07.0-ath79-generic-tplink_archer-c7-v2-squashfs-sysupgrade.bin.extracted/185BC4/squashfs-root}

pass=0; fail=0
check() { # check <名称> <期望rc> <实际rc> <输出> <断言grep模式>
    local name=$1 want=$2 got=$3
    if [ "$got" != "$want" ]; then echo "FAIL $name (rc=$got 期望 $want)"; fail=$((fail+1)); return; fi
    if [ $# -ge 5 ]; then
        if ! echo "$4" | grep -q -- "$5"; then echo "FAIL $name (输出缺 '$5')"; fail=$((fail+1)); return; fi
    fi
    echo "PASS $name"; pass=$((pass+1))
}

echo "== 1 版本与身份(镜像内直接 argv 查询) =="
qemu_v=$(docker run --rm --network none --entrypoint /usr/local/bin/qemu-arm-static "$IMG" --version 2>&1); rc=$?
check "qemu-arm version 查询" 0 $rc "$qemu_v" "version 11.1.1"
mips_v=$(docker run --rm --network none --entrypoint /usr/local/bin/qemu-mips-static "$IMG" --version 2>&1); rc=$?
check "qemu-mips version 查询" 0 $rc "$mips_v" "version 11.1.1"
proot_v=$(docker run --rm --network none --entrypoint /usr/local/bin/proot "$IMG" --version 2>&1); rc=$?
check "proot version 查询" 0 $rc "$proot_v" "PRoot Developers"
# 镜像已剥离 shell/cat 等,BUILD-INFO 用 docker cp 读出(docker cp 走 daemon,不经容器内程序)
cid=$(docker create "$IMG")
info=$(docker cp "$cid":/usr/local/share/BUILD-INFO.txt - 2>/dev/null | tar -xO 2>/dev/null)
docker rm "$cid" >/dev/null
check "BUILD-INFO 镜像内可读" 0 $? "$info" "proot=5.4.0"
if echo "$info" | grep -q "qemu=11.1.1"; then echo "PASS BUILD-INFO 记录 qemu 钉值"; pass=$((pass+1));
else echo "FAIL BUILD-INFO 缺 qemu 钉值"; fail=$((fail+1)); fi

echo "== 2 形状隔离(剥离后无 shell/常规工具;以 docker 错误为证) =="
dash_probe=$(docker run --rm --network none --entrypoint /usr/bin/test "$IMG" -e /usr/bin/dash 2>&1); rc=$?
# test 已被剥离 → 容器内无 test 可执行即证明剥离生效;dash 不存在由工具测试覆盖
check "镜像内无 test(dash/uname 等同批剥离)" 127 $rc "$dash_probe" "no such file"
docker run --rm --network none --entrypoint /usr/local/bin/llscan "$IMG" count > /tmp/llscan-count.txt 2>&1
lrc=$?; lsout=$(cat /tmp/llscan-count.txt); rm -f /tmp/llscan-count.txt
check "llscan 可执行(匹配 0 进程)" 0 $lrc "$lsout" "^0$"

echo "== 3 ARM32 LE 真实样本(target/6 nvram,proot+qemu 显式) =="
S=$(mktemp -d)
mkdir -p "$S/runtime"
v=$(docker run --rm --network none -e PROOT_TMP_DIR=/session/stub --tmpfs /session/stub:rw,exec \
    -v "$TGT6_SQUASH":/session/firmware:ro -v "$S/runtime":/session/runtime:rw \
    --entrypoint /usr/bin/timeout "$IMG" -k 5 60 \
    /usr/local/bin/proot --mixed-mode on --kill-on-exit \
    -q /usr/local/bin/qemu-arm-static -r /session/firmware \
    -b /session/runtime:/tmp -b /dev/null -b /dev/zero -b /dev/random -b /dev/urandom \
    /usr/sbin/nvram 2>&1); rc=$?
check "ARM nvram usage" 0 $rc "$v" "usage: nvram"

echo "== 4 ARM 派生链(固件 sh 派生静态子,原链语义) =="
v=$(docker run --rm --network none -e PROOT_TMP_DIR=/session/stub --tmpfs /session/stub:rw,exec \
    -v "$TGT6_SQUASH":/session/firmware:ro -v "$S/runtime":/session/runtime:rw \
    --entrypoint /usr/bin/timeout "$IMG" -k 5 60 \
    /usr/local/bin/proot --mixed-mode on --kill-on-exit \
    -q /usr/local/bin/qemu-arm-static -r /session/firmware \
    -b /session/runtime:/tmp -b /dev/null -b /dev/zero -b /dev/random -b /dev/urandom \
    /bin/busybox sh -c "/bin/busybox echo smoke-derived-arm" 2>&1); rc=$?
check "ARM 派生链" 0 $rc "$v" "smoke-derived-arm"

echo "== 5 MIPS32 BE 真实样本(target/8 busybox) =="
v=$(docker run --rm --network none -e PROOT_TMP_DIR=/session/stub --tmpfs /session/stub:rw,exec \
    -v "$TGT8_SQUASH":/session/firmware:ro -v "$S/runtime":/session/runtime:rw \
    --entrypoint /usr/bin/timeout "$IMG" -k 5 60 \
    /usr/local/bin/proot --mixed-mode on --kill-on-exit \
    -q /usr/local/bin/qemu-mips-static -r /session/firmware \
    -b /session/runtime:/tmp -b /dev/null -b /dev/zero -b /dev/random -b /dev/urandom \
    /bin/busybox echo smoke-mips-ok 2>&1); rc=$?
check "MIPS busybox echo" 0 $rc "$v" "smoke-mips-ok"

echo "== 6 边界拒绝面(镜像内:guest 派生原生执行被 proot 补丁拒绝) =="
v=$(docker run --rm --network none -e PROOT_TMP_DIR=/session/stub --tmpfs /session/stub:rw,exec \
    -v "$TGT6_SQUASH":/session/firmware:ro -v "$S/runtime":/session/runtime:rw \
    --entrypoint /usr/bin/timeout "$IMG" -k 5 60 \
    /usr/local/bin/proot --mixed-mode on --kill-on-exit \
    -q /usr/local/bin/qemu-arm-static -r /session/firmware \
    -b /session/runtime:/tmp -b /dev/null -b /dev/zero -b /dev/random -b /dev/urandom \
    /bin/busybox sh -c "/host-rootfs/usr/local/bin/qemu-arm-static --version" 2>&1); rc=$?
check "guest 借 /host-rootfs 执行容器 qemu 被拒" 255 $rc "$v" "Invalid ELF image"

rm -rf "$S"
echo "-----"
echo "smoke: pass=$pass fail=$fail"
[ "$fail" -eq 0 ]
