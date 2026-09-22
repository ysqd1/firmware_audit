# 票 16:PRoot 5.4.0 + QEMU 11.1.1 执行镜像(执行会话与原固件派生链底座)。
#
# 与票 03 的 5.2 镜像(firmware_audit/docker/qemu-exec,历史对照)完全独立:
# 双源码钉值构建、基础镜像按 digest 钉定、proot 应用 mixed_mode 继承本地补丁
# (运行时拒绝机制,证据见 investigation/proot540-qemu1111-2026-09-22/)。
# 最终层做"形状隔离"剥离:后端必需可执行(timeout/sleep/proot/qemu×2/llscan)
# 之外全部删除——guest 经 /host-rootfs 等别名物理找不到未授权容器原生程序。
# 钉值单一来源:pins.env(漂移由 test_qemu_exec_v2_image.py 守护)。
# 构建上下文由 build_image.sh 组装(临时目录硬链接源码缓存,避免 141MB 上下文)。

# ---- 阶段 1:QEMU 11.1.1 静态构建(官方 tarball,sha256 钉值) ----
FROM debian:bookworm@sha256:f37a335e82bca302e955fa39f9dfe28f1be618f016f8a2b56318e5a5111afc26 AS qemubuild
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      build-essential ninja-build python3 python3-pip pkg-config libglib2.0-dev xz-utils ca-certificates \
    && pip3 install --break-system-packages -q 'meson>=1.5' \
    && rm -rf /var/lib/apt/lists/*
COPY qemu-11.1.1.tar.xz /tmp/qemu.tar.xz
RUN echo "079ffbff8a7111bbc89022107cbabf3bbfd614d5fc9d7cc675991196aca12482  /tmp/qemu.tar.xz" | sha256sum -c - \
    && mkdir /src && tar -xJf /tmp/qemu.tar.xz -C /src --strip-components=1
WORKDIR /build
RUN /src/configure --static --prefix=/usr/local \
      --target-list=arm-linux-user,mips-linux-user \
      --disable-system --disable-tools --disable-docs \
    && ninja -j"$(nproc)" \
    && ninja install

# ---- 阶段 2:PRoot 5.4.0 源码构建(上游 tag + mixed_mode 继承补丁)+ llscan ----
FROM debian:bookworm-slim@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251 AS toolsbuild
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      build-essential libtalloc-dev patch && rm -rf /var/lib/apt/lists/*
COPY proot-5.4.0.tar.gz /tmp/proot.tar.gz
COPY proot-mixed-mode-inherit.patch /tmp/proot-mixed-mode.patch
RUN echo "29248aac2a7ce10c3bd5ee5602742ec33b2532310ff9cf73b79f3c133e5a5f68  /tmp/proot.tar.gz" | sha256sum -c - \
    && echo "d55abd0d8c0adb86d8a264368664fb4fbf0ea8273a27681119295bd126f41cdd  /tmp/proot-mixed-mode.patch" | sha256sum -c - \
    && cd /tmp && tar xzf proot.tar.gz && cd proot-5.4.0 \
    && patch -p1 --forward < /tmp/proot-mixed-mode.patch \
    && cd src && make -j"$(nproc)" && make install PREFIX=/usr/local
COPY llscan.c /tmp/llscan.c
RUN gcc -O2 -Wall -o /usr/local/bin/llscan /tmp/llscan.c

# ---- 阶段 3:运行基(digest 钉定 + 形状隔离剥离 + 身份档案) ----
FROM debian:bookworm-slim@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251
LABEL fw.qemu.version="11.1.1" \
      fw.qemu.tarball.sha256="079ffbff8a7111bbc89022107cbabf3bbfd614d5fc9d7cc675991196aca12482" \
      fw.proot.version="5.4.0" \
      fw.proot.tarball.sha256="29248aac2a7ce10c3bd5ee5602742ec33b2532310ff9cf73b79f3c133e5a5f68" \
      fw.proot.patch.sha256="d55abd0d8c0adb86d8a264368664fb4fbf0ea8273a27681119295bd126f41cdd" \
      fw.qemu.build.params="--static --target-list=arm-linux-user,mips-linux-user --disable-system --disable-tools --disable-docs" \
      fw.base.digest="sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251" \
      fw.boundary="proot-mixed-mode-inherit+strip(deny-by-absence)" \
      org.opencontainers.image.title="firm_audit qemu-exec p540q1111"
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      libtalloc2 && rm -rf /var/lib/apt/lists/*
COPY --from=qemubuild /usr/local/bin/qemu-arm /usr/local/bin/qemu-arm-static
COPY --from=qemubuild /usr/local/bin/qemu-mips /usr/local/bin/qemu-mips-static
COPY --from=toolsbuild /usr/local/bin/proot /usr/local/bin/proot
COPY --from=toolsbuild /usr/local/bin/llscan /usr/local/bin/llscan
RUN printf 'image=firm_audit/qemu-exec:p540q1111\nproot=5.4.0-upstream-v5.4.0-tag+mixed-mode-inherit-patch\nproot-tarball-sha256=29248aac2a7ce10c3bd5ee5602742ec33b2532310ff9cf73b79f3c133e5a5f68\nproot-patch-sha256=d55abd0d8c0adb86d8a264368664fb4fbf0ea8273a27681119295bd126f41cdd\nqemu=11.1.1-official-tarball-static\nqemu-tarball-sha256=079ffbff8a7111bbc89022107cbabf3bbfd614d5fc9d7cc675991196aca12482\nqemu-build-params=--static --target-list=arm-linux-user,mips-linux-user --disable-system --disable-tools --disable-docs\nbase=debian:bookworm-slim@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251\nboundary=proot-mixed-mode-inherit+strip(deny-by-absence)\n' \
       > /usr/local/share/BUILD-INFO.txt && chmod 0444 /usr/local/share/BUILD-INFO.txt
# 形状隔离剥离必须单独成层且放在最后:本层内不再 exec 任何外部命令
# (前一层已删过一次 127 的教训);尾斜杠穿透 usrmerge 符号链接。
# 保留:timeout/sleep(/usr/bin)+ /usr/local/bin 四件套;其余可执行文件
# 与符号链接全删——guest 经 /host-rootfs 等别名物理找不到未授权程序。
RUN find /usr/sbin/ -mindepth 1 -maxdepth 1 -delete \
    && find /usr/bin/ -mindepth 1 -maxdepth 1 ! -name timeout ! -name sleep -delete
CMD ["/bin/sleep", "infinity"]
