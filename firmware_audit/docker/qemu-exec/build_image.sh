#!/usr/bin/env bash
# 构建 QEMU 执行镜像 firm_audit/qemu-exec(票 03:镜像构建脚本入库)。
#
# 用法: firmware_audit/docker/qemu-exec/build_image.sh
# 前置: 基础镜像 firm_audit/sandbox:latest 已存在(缺失给指引,不自动全量重建
#        ——基座全量构建含 r2 编译段,需外网且易断,见 Dockerfile.binwalk 教训)。
# .deb: deb-cache/ 已有则直接校验使用(复用下载缓存);缺失时按 pins.env 双源
#        URL 下载(主 aliyun,备 deb.debian.org),sha256 不符即中止,不静默换包。
set -euo pipefail
cd "$(dirname "$0")"

. ./pins.env

# 1. 基础镜像在位
if ! docker image inspect "$BASE_IMAGE" >/dev/null 2>&1; then
    echo "FAIL: 基础镜像 $BASE_IMAGE 不存在。先按 firmware_audit/docker/sandbox/Dockerfile 构建基座。" >&2
    exit 1
fi

# 2. .deb 就位:缓存命中直接用;缺失则逐源"下载→校验",坏件即删、回退下一源,
#    双源全失败才中止(校验不过绝不换包或跳过)
DEB_PATH="deb-cache/$QEMU_USER_STATIC_DEB"
verify_deb() {
    echo "$QEMU_USER_STATIC_DEB_SHA256  $1" | sha256sum -c - >/dev/null \
        && [ "$(stat -c %s "$1")" = "$QEMU_USER_STATIC_DEB_SIZE" ]
}
if [ -f "$DEB_PATH" ] && ! verify_deb "$DEB_PATH"; then
    echo "[build] 缓存 .deb 校验不过,删除坏件重新下载: $DEB_PATH"
    rm -f "$DEB_PATH"
fi
if [ ! -f "$DEB_PATH" ]; then
    mkdir -p deb-cache
    for url in "$DEB_POOL_URL_ALIYUN" "$DEB_POOL_URL_DEBIAN"; do
        echo "[build] 下载 $url"
        if curl -sfL --retry 3 -o "$DEB_PATH" "$url" && verify_deb "$DEB_PATH"; then
            break
        fi
        rm -f "$DEB_PATH"
    done
fi
if [ ! -f "$DEB_PATH" ]; then
    echo "FAIL: .deb 不可获取(双源均失败或校验不过): $QEMU_USER_STATIC_DEB。" >&2
    echo "      换源/换版本需先改 pins.env 并重新核实校验值,不得静默换包。" >&2
    exit 1
fi
echo "[build] .deb 校验通过: $QEMU_USER_STATIC_DEB (sha256 ${QEMU_USER_STATIC_DEB_SHA256:0:16}…)"

# 4. 构建:基座镜像 ID(.Id,本地构建镜像无 RepoDigests,票 01 存档同口径)
#    记进镜像内 BUILD-INFO;版本 tag 取 Debian 修订号(最后一个 + 之后,
#    tag 语法不收 epoch 冒号与 +)
BASE_IMAGE_ID=$(docker image inspect --format '{{.Id}}' "$BASE_IMAGE")
VERSION_TAG="${QEMU_USER_STATIC_VERSION##*+}"
docker build \
    --build-arg "BASE_IMAGE_ID=$BASE_IMAGE_ID" \
    --label "org.opencontainers.image.base.name=$BASE_IMAGE" \
    --label "fw.firm-audit.qemu-user-static.version=$QEMU_USER_STATIC_VERSION" \
    --label "fw.firm-audit.qemu-user-static.deb-sha256=$QEMU_USER_STATIC_DEB_SHA256" \
    -t "$QEMU_EXEC_IMAGE:latest" \
    -t "$QEMU_EXEC_IMAGE:$VERSION_TAG" \
    .

echo "[build] 完成: $QEMU_EXEC_IMAGE:latest (= :$VERSION_TAG)"
docker image ls "$QEMU_EXEC_IMAGE"
