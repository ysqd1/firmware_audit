# QEMU 执行镜像(票 03,qemu-user-mode-experiments)——票 05 起真实集成测试的底座。
#
# 路线(票 01 调查定案):沙箱基座派生层 + 专用 tag,能力隔离是结构性的——
# sandbox_verify 留 firm_audit/sandbox(实测物理无 qemu),qemu 只在本镜像。
# 版本钉死依据:bullseye-security 池 deb11u5 已 404、bullseye LTS 已结束,
# bullseye(main) 实际可装最新 = 1:5.2+dfsg-11+deb11u3(钉值单一来源 = pins.env)。
#
# 构建:走 deb-cache 内离线 .deb(sha256 双重校验:宿主侧 + 镜像内),
# 不依赖构建期网络与 apt 源存续(.deb 可能从镜像源消失,security 池先例)。
# ENTRYPOINT 保持基座值(analyzeHeadless,继承不覆盖),调用侧显式覆盖,
# 与现有 CLI 工具模式一致。宿主 binfmt 零接触:--no-install-recommends 同款
# 语义下 binfmt-support 不安装,postinst 容器守卫短路(票 01 实测)。
ARG BASE_IMAGE_DIGEST=unknown
FROM firm_audit/sandbox:latest

# ARG 在 FROM 前声明只作用于 FROM 行;RUN 要用必须在 FROM 后重新声明
ARG BASE_IMAGE_DIGEST=unknown

COPY pins.env /tmp/fw-qemu-pins.env
COPY deb-cache/qemu-user-static_5.2+dfsg-11+deb11u3_amd64.deb /tmp/qemu-user-static.deb

# sha256 校验(值取自 pins.env)→ 离线安装 → 基线与版本落盘(镜像内可查询,票 03 AC1)
RUN mkdir -p /usr/local/share/fw-qemu-exec \
    && . /tmp/fw-qemu-pins.env \
    && echo "${QEMU_USER_STATIC_DEB_SHA256}  /tmp/qemu-user-static.deb" | sha256sum -c - \
    && dpkg -i /tmp/qemu-user-static.deb \
    && printf 'base_image=%s\nbase_digest=%s\nqemu_user_static=%s\ndeb_sha256=%s\ndeb_size=%s\nbuilt_utc=%s\n' \
         "${BASE_IMAGE}" "${BASE_IMAGE_DIGEST}" "${QEMU_USER_STATIC_VERSION}" \
         "${QEMU_USER_STATIC_DEB_SHA256}" "${QEMU_USER_STATIC_DEB_SIZE}" \
         "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
         > /usr/local/share/fw-qemu-exec/BUILD-INFO.txt \
    && dpkg-query -W -f='installed: ${Version}\n' qemu-user-static \
    && qemu-arm-static --version | head -1 \
    && qemu-mips-static --version | head -1 \
    && rm -f /tmp/qemu-user-static.deb /tmp/fw-qemu-pins.env
