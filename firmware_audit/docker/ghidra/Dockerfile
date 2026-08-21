## Ghidra Headless 反编译镜像
## 用途: 对 ELF 二进制做反编译 + 程序信息提取
## 用法: docker run --rm -v <input>:/work/input -v <output>:/work/output ghidra <binary>
##
## 用 deepaudit/sandbox 做基础(本地已有,内置 wget + unzip)。
## Ghidra 11.3.2 要求 JDK 21+(application.java.min=21),
## 基础镜像只有 JDK 17,所以 COPY 本地 JDK 21 tar 包进来用。
## Ghidra zip 也已下载到本地,COPY 进去(避免构建时慢速下载)。
## ExtractInfo.py 是 Jython 脚本,由 Ghidra 内置解释器运行,不需要宿主 python3。
FROM deepaudit/sandbox:latest

ARG GHIDRA_VERSION="11.3.2"
ARG GHIDRA_INSTALL_DIR="/opt/ghidra"
ARG JDK21_INSTALL_DIR="/opt/jdk-21"

# COPY 本地已下载的 Ghidra zip + JDK 21 tar(避免构建时网络下载)
COPY ghidra_11.3.2_PUBLIC.zip /tmp/ghidra.zip
COPY jdk21.tar.gz /tmp/jdk21.tar.gz

# 解压 Ghidra + JDK 21(deepaudit/sandbox 默认非 root,需切换)
USER root
RUN unzip -q /tmp/ghidra.zip -d /opt \
    && mv /opt/ghidra_${GHIDRA_VERSION}_PUBLIC ${GHIDRA_INSTALL_DIR} \
    && rm /tmp/ghidra.zip \
    && tar xzf /tmp/jdk21.tar.gz -C /opt \
    && mv /opt/jdk-21.* ${JDK21_INSTALL_DIR} \
    && rm /tmp/jdk21.tar.gz

# 复制提取脚本到 Ghidra 脚本目录
COPY ExtractInfo.py ${GHIDRA_INSTALL_DIR}/Ghidra/Features/Decompiler/ghidra_scripts/ExtractInfo.py

# 用 JDK 21 替代基础镜像的 JDK 17(Ghidra 11.3.2 最低要求)
ENV GHIDRA_INSTALL_DIR=${GHIDRA_INSTALL_DIR}
ENV JAVA_HOME=${JDK21_INSTALL_DIR}
ENV PATH="${JDK21_INSTALL_DIR}/bin:${GHIDRA_INSTALL_DIR}/support:${PATH}"

WORKDIR /work

# 默认入口: 由 step4_decompile.py 通过 entrypoint 覆盖调用 analyzeHeadless
ENTRYPOINT ["analyzeHeadless"]
