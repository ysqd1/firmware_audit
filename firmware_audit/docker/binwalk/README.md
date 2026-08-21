# binwalk 镜像

第三方源码位于 `./binwalk/`(binwalk v3,ReFirmLabs Rust 重写)。
官网无官方 Docker 镜像,必须本地构建。

构建:

```bash
bash build_docker.sh
```

打 tag:`binwalk`。
> 注意:第三方源码自带的 `binwalk/binwalk/build_docker.sh` 打的是 `binwalkv3`,
> 与代码 `BINWALK_IMAGE="binwalk"` 不匹配,请使用本目录的 `build_docker.sh`。