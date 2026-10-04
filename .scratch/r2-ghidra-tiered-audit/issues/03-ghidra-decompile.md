# 03: ghidra_decompile——幂等缓存 + sha256 去重 + 边车三件套

**What to build:** Step5 唯一 Ghidra 入口:对单个 ELF 反编译并落盘边车三件套(.c/.strings.json/.imports.json),供 r2 层信息不够时深读。缓存语义:目标 .c 存在且头部 extractinfo_version 匹配 → 零容器直接返回"已反编译";版本失效 → 重跑覆盖;同内容不同路径 → sha256 查 dedup 索引命中,把已有边车硬链接到新路径(os.link 失败降级拷贝),Observation 注明复用来源。非 ELF 即时引导性拒绝(不付 900s 容器);Observation 只回指针 + 函数数,不回 C 内容。容器沿用原批量反编译现制:ghidra 镜像、单文件分析超时 300、容器整体超时 900、宿主 uid:gid。反编译脚本本体零改动、版本号不涨(老工件天然是缓存)。规则出处:ADR-0010、spec(User Stories 11-17、28)。

测试基建(prefactor):本票先立"伪造容器产物的假 run_docker"(往输出目录写边车三件套 + 版本头),缓存/去重/失效逻辑全部离线可测;另有 Docker 门控真 Ghidra 冒烟作验收锚点。

**Blocked by:** None (can start immediately;实作顺序建议排在 02 之后,减少提示词/权限矩阵测试的同文件冲突)

**Status:** ready-for-human

- [x] 缓存命中:假 run_docker 断言零容器调用,直接返回"已反编译"
- [x] 版本失效:版本头不匹配触发重跑并覆盖
- [x] sha256 去重:同内容第二路径硬链接三件套 + dedup 索引更新 + Observation 注明来源;os.link 失败降级拷贝(注入失败验证)
- [x] 成功路径:三件套落盘,functions/meta 不落盘;Observation 轻量(指针 + 函数数)
- [x] 非 ELF/路径越界即时 ok=False 引导,零容器调用
- [x] 容器参数断言(镜像/双超时/宿主 uid:gid);权限矩阵仅 analysis+verification;提示词工具清单更新
- [x] Docker 门控冒烟:target/1 小 ELF 三件套完整,二次调用缓存命中
- [x] 全套件绿

## Comments

**2026-09-09 implement**(工单完成,待人工验收):

- 新 `ghidra_decompile.py`(注册表 + analysis/verification 两 CFG 授权;recon 不授):`_run` 四段——elf_guard(复用票01,非 ELF/越界/缺失即时拒绝零容器)→ 缓存判定(`_cache_valid`=.c 头部 extractinfo_version 匹配 **且** decompile_success>0,防空壳永久跳过;版本失效/空壳 → 重跑覆盖)→ sha256 去重(`analysis/dedup.json` 索引 sha→首个反编译 rel,命中且有效则 `_materialize` 硬链接三件套、os.link OSError 降级 copy2、Observation 注明"内容与 X 相同(sha256 比对)")→ 容器(`_run_ghidra`,Step4 现制:ghidra 镜像、`-analysisTimeoutPerFile 300`、docker timeout=900、宿主 uid:gid、HOME=/tmp、`-deleteProject -overwrite`、临时工程)。成功才登记 dedup 索引。
- 边车三件套只拷 `.c/.imports.json/.strings.json`;functions/meta/symbols 不拷(无工具消费者)。Observation 轻量:指针 + 函数数,data 带 cache=hit/dedup/miss;失败文案引导 r2 层(r2_list_functions/r2_disassemble_function/r2_xref_query)。
- 写路径防御纵深:guard 拒 .. 之后产物路径再经 resolve_within 收口 analysis/ 之下。本工具成为 Step5 唯一写审计工件的工具。
- 测试基建:新 `test_step5_ghidra_tool.py` 7 项离线——`_FakeDocker` 解析 mounts 找 /work/output 写三件套+版本头,另支持 fail=(rc,out,err) 与 produce=False(rc=0 零产出)两失败注入;补丁点=工具模块顶层导入的 `gd.run_docker`(方法内延迟导入会打不中,已规避);os.link 失败用真 os.link 替换注入(finally 恢复)。8 断言组覆盖工单全部验收项。cli_tools 增真 Ghidra 冒烟(tmp 工作区拷 target/1 的 6KB vlc dummy 插件,三件套完整+二次缓存命中;本环境 Docker 不可用自动 skip)。权限矩阵断言扩入 ghidra_decompile。全套件 323 passed + 15 skipped。

**2026-09-09 code-review 采纳修复**(两轴评审,标准轴 P1/P2/P3):

- **P1 安全基线**:容器调用补 `network="none"` 断网 + 输入挂载 `(host.parent, /work/input, "ro")` 只读(Step5 工具统一基线;Step4 时代 rw 豁免不继承);`test_container_contract` 增 network/ro 两条断言防基线漂移。
- **P2 路径收口**:dedup.json 反查值 `first_rel` 经 `resolve_within(analysis_dir, …)` 收口后再构造探测/物化路径(索引损坏/被手改时不把 analysis/ 外的宿主文件物化进边车位)。
- **P3**:`_FakeDocker` 与白名单细节——func_or_addr 白名单收紧为 `[A-Za-z0-9_.:-]`(r2 的 `$ <>` 有重定向/变量语义,真实目标形态用不到;改动落 r2_base,见票01 范围)。
- 未采纳(判断类,记档):build_filtered_overview 全树 rglob 加上限——概览语义需要全量计数,每次运行一次、非正确性问题,不加。
