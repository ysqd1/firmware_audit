# firmware_audit 通用沙箱(原 ghidra 镜像重命名而来)
#
# 内容:DeepAudit sandbox 全工具(file/strings/python3/semgrep/...)+ Ghidra 11.3.2
#       + JDK 21 + fdisk 包(sfdisk/fdisk/blkid 等分区工具)
# 用途:
#   - step0 分区交叉验证(sfdisk -d 导出分区表,与手写解析逐项对比)
#   - 其他需要通用命令环境的场景(不用动 binwalk/ghidra 专用镜像)
# 注意: ghidra 反编译请用精简后的 ghidra 镜像(step4 并行容器,体积小、内存占用低)
#
# 历史坑:
#   - Debian bullseye 的 util-linux 是拆包版:sfdisk/fdisk 在独立的 "fdisk" 包,
#     装 util-linux 只有 blkid/mount/agetty 等,没有 sfdisk
#   - 基础镜像的 ENV PATH 被 ghidra 覆盖成只有 JDK/Ghidra 路径,系统命令
#     不在 PATH → 这里显式补全系统路径
FROM firm_audit/sandbox:latest

ENV PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:${JAVA_HOME}/bin:${GHIDRA_INSTALL_DIR}/support:${PATH}"

# 本机有外网,apt 可直接装 fdisk 包(sfdisk 是标准分区工具,~170KB)
RUN apt-get update \
    && apt-get install -y --no-install-recommends fdisk \
    && rm -rf /var/lib/apt/lists/*

# Agent 工具层依赖(2026-08-17):checksec / cve-bin-tool / radare2
# - checksec: bullseye apt 无此包,COPY slimm609 脚本(依赖 readelf/objdump,镜像已有)
# - cve-bin-tool: pip 装;CVE 数据库不烘进镜像,运行时 volume 挂载宿主 cache
# - radare2: bullseye apt 源无此包(实测 no installation candidate),源码编译安装
COPY checksec /usr/local/bin/checksec
RUN chmod +x /usr/local/bin/checksec \
    && pip3 install --no-cache-dir cve-bin-tool
# r2 的 sys/install.sh 是"软链安装"(symstall):/usr/local 下的 bin/lib/pkgconfig
# 全是指向构建目录的符号链接,删构建目录前必须解引用成真实文件,否则全部悬空。
# 源码包在宿主机预先下载进构建上下文(容器内 git clone GitHub 会被网络掐断,不可靠)
COPY radare2-5.9.8.tar.gz /tmp/radare2.tar.gz
RUN tar -xzf /tmp/radare2.tar.gz -C /tmp \
    && cd /tmp/radare2-5.9.8 \
    && CS_COMMIT_ARCHIVE=1 sys/install.sh \
    && find /usr/local -type l | while read -r f; do \
           case "$(readlink "$f")" in \
               /tmp/radare2*) cp -L "$f" "$f.deref" && mv "$f.deref" "$f" || true ;; \
           esac; \
       done \
    && cd /usr/local/lib \
    && for f in *.so.5.9.8; do b=${f%.so.5.9.8}; ln -sf "$f" "$b.so.5.9"; ln -sf "$f" "$b.so"; done \
    && rm -rf /tmp/radare2-5.9.8 /tmp/radare2.tar.gz

# 原镜像(DeepAudit)的 semgrep 是坏的:site-packages/semgrep/bin/ 混入了
# Windows DLL(iconv.dll/libcrypto-3.dll 等),semgrep-core Linux 二进制从未存在,
# `semgrep --version` 直接报 "Failed to find semgrep-core"。
# 重装版本选择(2026-08-17 容器内实测):
#   - 1.162.0:PyPI 预编译 wheel 是 manylinux_2_35(glibc 2.35),bullseye 是 glibc 2.31,
#     pip 匹配不到 wheel 退回 sdist 现场构建,产物里 semgrep-core 仍需 glibc 2.35,运行即崩
#   - 1.100.0:最后一代 manylinux2014(glibc 2.17)平台 wheel,实测可用
#   - 必须带依赖装(不能 --no-deps):opentelemetry 链是运行时 import 硬依赖
#   - opentelemetry 依赖 pkg_resources,setuptools>=81 已移除它 → 先 pin setuptools<81
#   - 基础镜像遗留孤儿包 opentelemetry-instrumentation-threading 0.58b0(Required-by 为空)
#     与 semgrep 依赖的 0.46b0 系版本冲突,卸载消除 pip3 check 噪音
RUN pip3 install --no-cache-dir "setuptools<81" \
    && pip3 install --no-cache-dir semgrep==1.100.0 \
    && pip3 uninstall -y opentelemetry-instrumentation-threading
# agent 全部用本地规则文件扫描,关掉 registry metrics 上报
ENV SEMGREP_SEND_METRICS=off

# binwalk 刻意不装(2026-08-18 实测定案,勿再尝试):
#   - pip 版是停更的 2.1.0,Python 3.11 import 即崩
#   - v3 Rust 二进制需 GLIBC 2.39,bullseye 基座只有 2.31,跨镜像复制不可行
#   - Step5 binwalk_rescan 直接用 binwalk 专用镜像(保留不动)
# binwalk_rescan 工具挂载 extracted 到专用镜像只读扫签名。

# 冗余工具链清理(2026-08-17 确认删除):流水线与 agent 工具层对以下零依赖,共约 1.35GB
# - openjdk-11/17(apt 装):JAVA_HOME=/opt/jdk-21(Ghidra 11.3.2 要求 21),11/17 无人引用;
#   裸 java 命令原本被 alternatives 指到 17,purge 后软链 /usr/local/bin/java -> jdk-21 消歧
# - Rust(rustup:/usr/local/rustup + /usr/local/cargo,605M):semgrep-core 是 OCaml 静态二进制,无 Rust 依赖
# - Go(/usr/local/go,244M)+ gosec(/usr/local/bin/gosec):gosec 不在 agent 工具清单
# 注意:本层删除只影响运行时视图;镜像体积缩小依赖后续 export/import 压扁(见 rules.md)
RUN apt-get purge -y \
        openjdk-11-jdk-headless openjdk-11-jre-headless \
        openjdk-17-jdk-headless openjdk-17-jre-headless \
    && apt-get autoremove -y \
    && rm -rf /usr/local/rustup /usr/local/cargo /usr/local/go /usr/local/bin/gosec \
    && ln -sf /opt/jdk-21/bin/java /usr/local/bin/java \
    && rm -rf /var/lib/apt/lists/*
