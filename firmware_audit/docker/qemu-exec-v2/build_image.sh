#!/usr/bin/env bash
# 票 16:构建 PRoot 5.4.0 + QEMU 11.1.1 执行镜像(firm_audit/qemu-exec:p540q1111)。
# 流程:src-cache 缺失时下载 → 宿主侧 sha256+尺寸校验(钉值见 pins.env)→
# 组装临时构建上下文(硬链接,免 141MB 目录直传)→ docker build。
# GPG 签名复核(qemu 发布签名,指纹 CEACC9E1…F108B584)证据见
# investigation/proot540-qemu1111-2026-09-22/logs/80-download-sources.txt。
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$DIR/pins.env"
SRC_CACHE="$DIR/src-cache"
mkdir -p "$SRC_CACHE"

fetch() { # fetch <url> <dest>
    local url=$1 dest=$2
    if [ -f "$dest" ]; then return 0; fi
    echo "[build] 下载 $url"
    curl -sS --fail -o "$dest" "$url" \
        || { echo "[build] 下载失败:$url(官方源不可达时人工核实后更新 pins.env,不静默换源)" >&2; exit 1; }
}

QEMU_FILE="qemu-$QEMU_VERSION.tar.xz"
fetch "$QEMU_URL" "$SRC_CACHE/$QEMU_FILE"

echo "[build] sha256 + 尺寸校验(钉值)"
echo "$QEMU_TARBALL_SHA256  $SRC_CACHE/$QEMU_FILE" | sha256sum -c -
[ "$(stat -c %s "$SRC_CACHE/$QEMU_FILE")" = "$QEMU_TARBALL_SIZE" ] \
    || { echo "[build] qemu tarball 尺寸不符(期望 $QEMU_TARBALL_SIZE)" >&2; exit 1; }
# proot 钉值副本入库(上游 auto-archive 非字节稳定,见 pins.env),同样强校验
echo "$PROOT_TARBALL_SHA256  $DIR/$PROOT_TARBALL" | sha256sum -c -
echo "$PROOT_PATCH_SHA256  $DIR/$PROOT_PATCH" | sha256sum -c -

CTX=$(mktemp -d)
trap 'rm -rf "$CTX"' EXIT
cp "$DIR/Dockerfile" "$DIR/llscan.c" "$DIR/$PROOT_PATCH" "$DIR/$PROOT_TARBALL" "$CTX/"
ln "$SRC_CACHE/$QEMU_FILE" "$CTX/$QEMU_FILE"

echo "[build] docker build($QEMU_EXEC_V2_IMAGE;QEMU 静态构建约 10-25 分钟)"
docker build -f "$CTX/Dockerfile" -t "$QEMU_EXEC_V2_IMAGE" "$CTX"

echo "[build] 完成:$(docker image inspect -f '{{.Id}}' "$QEMU_EXEC_V2_IMAGE")"
docker image inspect -f '{{range .Config.Labels}}{{println .}}{{end}}' "$QEMU_EXEC_V2_IMAGE" | grep '^fw\.' || true
echo "[build] 冒烟:run_smoke.sh(需 target/6、target/8 解包树)"
