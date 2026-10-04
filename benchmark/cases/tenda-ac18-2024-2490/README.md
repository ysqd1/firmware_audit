# benchmark/cases/tenda-ac18-2024-2490/ — 案例暂存(公开侧)

> 公开侧目录:固件原始获取物 + 运行配置,无任何答案内容。
> GT 不在本目录,在 `benchmark/ground_truth/tenda-ac18-2024-2490.json`(答案侧,隔离)。

## 固件原始获取物(firmware/)

- 文件:`US_AC18V1.0BR_V15.03.05.05_multi_TD01.zip` — Tenda 官方下载页原始包(用户人工下载,自动渠道当时全被 403)
- 内含固件 bin sha256:`81670748a21ad8b8cd48a17a151d6b1947c498c2e180645c3b35efa369b453e9`(与 `target/7/` 顶层固件逐字节一致;bin 内嵌 squashfs 与 Karonte 数据集 `1C9E90.squashfs` 逐字节同源)
- 获取日期:2026-09-20

## 运行配置

- `profile.json` — 版本化预算与运行参数(schema_version 1;初始预算,非成绩)

## 布局约定(票 16 接线对齐此布局)

`profile.json` + `firmware/`(原始获取物)+ 本 README;GT 与参考答案材料(`benchmark/reference/`)永不入本目录。

## 沿革

- 本目录曾直接存放 zip 与解压产物(2026-09-20 人工下载当时);布局统一后固件移入 `firmware/`,解压产物删除(bin 已验证与 target/7 一致,zip 内同源)。
- 早期的 fallback(rootfs 重打包 tar.xz)已被官方 bin 取代并移除;两者 rootfs 内容同源,无信息差异。
- Windows 下载标记文件(Zone.Identifier)已随布局统一清理。
