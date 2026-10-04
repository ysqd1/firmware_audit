# 02: binwalk_rescan 幽灵扫描修复

**What to build:** Step5 的透视镜工具不再对没发生过的扫描报"0 命中":宿主侧预检 file_ref 必须真实存在于解包树(不存在 → ok=False 引导性报错"文件不在解包树,用 list_files 确认");stderr 的打开/读取失败标记(实测 "Failed to open/read",v3 此场景退出码仍为 0)一律判失败并如实回喂。工具注释记录该实测坑。规则出处:spec(binwalk-extractable-align)。

**Blocked by:** None (can start immediately;与票01 不同层,无冲突)

**Status:** ready-for-human

- [x] 不存在文件 → ok=False 引导性报错,零容器调用
- [x] stderr 失败注入 → ok=False(退出码 0 也拦)
- [x] 正常识别路径行为不变(回归);mock 沙箱单测 + Docker 门控真跑各一
- [x] 全套件绿

## Comments

**2026-09-10 implement**(工单完成,待人工验收):

- **修复落点**(`binwalk_rescan.py`):①宿主侧预检——`resolve_within` 解析后 `is_file()` 校验,不存在 → ok=False"文件不在解包树:…(binwalk 未执行;用 list_files 确认实际路径)",零容器调用;目录/非常规文件同款拦截(文案"不是常规文件");预检置于 `docker_available` 之前(纯宿主检查先行,无 Docker 环境也能看到真相)。②stderr 失败判定——`_OPEN_READ_FAIL_MARKERS = ("failed to open", "failed to read")` 小写包含匹配(实测 "Failed to open/read" 及大小写变体),命中即 ok=False 如实回喂 stderr 原文(含容器路径与失败原因),退出码 0 也拦。③实测坑入注释:模块 docstring 记录"v3 打不开目标 rc=0、失败只打 stderr → 0 命中假观察"及两层防御。
- **TDD**:先写 mock 测试复现幽灵扫描(缺失文件 → 容器被调 → rc=0 → ok=True"签名复扫/无签名命中",4 断言红),实现后转绿。
- **测试**:新 `test_step5_binwalk_rescan.py`(mock 层 5 用例:预检零容器/stderr 注入拦截/正常识别回归/干净 0 命中仍合法/rc!=0 回归;双模式);`test_step5_cli_tools.py::test_binwalk_rescan` 真跑补缺失文件断言(Docker+target/1 在场实弹验证通过);顺手更正该测试过时注释("沙箱直跑+回退"→"专用镜像直跑")。
- **评审修复**(两轴并行评审,全部采纳):P1 三拷贝禁令(rules.md)——替身脚手架第 3 份拷贝,收编共享 `test/replay_spy.py`(ReplaySpy + patched),r2_tools/fallback_tools 两文件同步迁移,断言点位改 kwargs/位置索引后全绿;P2"如实回喂"断言偏弱("Failed"几乎必中)→ 改断言 stderr 原文容器路径;P2 目录目标误报"文件不在解包树"→ 区分"不是常规文件";P3 binwalk_rescan.py 工作副本 CRLF → 归一 LF;P3 替身死默认值 timeout=3600 → 随收编消失。
- **评审判断记录**:docker_available 后移属票面外错误路径变更(无 Docker+缺失文件时报错从"镜像不可用"变"文件不在解包树"),判为"宿主预检先行"的自然读法,采纳保留;`_make_ctx` 同形 4 份不收编——各文件夹具数据不同(ELF/边车/fw.bin),非"同一逻辑",参数化合并反而制造 Speculative Generality。
- 全套件 330 passed + 2 skipped(基线 324+2;新增 mock 6 项收集,Docker 在场全部真跑)。
