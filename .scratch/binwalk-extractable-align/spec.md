# Spec: binwalk 可解集对齐(引导解包路由对齐 + 幽灵扫描修复 + target/4 验收)

Status: ready-for-agent
日期:2026-09-10
设计共识:本会话 grilling Q1-Q10 全部定稿(用户逐条拍板)。规则出处:本 spec;架构背景见 CONTEXT.md"引导解包"、file_rules/step1 既有注释。前序:ADR-0010/0011(r2 两级分析 + Step2-4 退役)已落地,target/4 e2e 暴露本缺口。

## Problem Statement

维护者审计厂商加密固件(D-Link DIR-882,SHRS 魔数)时,流水线产出零内容树:引导解包器的识别表只有 33 项常见格式,SHRS 不在其中,文件被 finalize 留树,**从未递给 binwalk——尽管 binwalk 3.1.1 镜像内置 SHRS 识别与解密**(实测一条命令解出 13MB 镜像 → uImage → 递归解出 18 个顶层目录的完整 rootfs)。空树上 Step5 照常运转,烧掉约 300 万 token 产出一份"解包阻塞"的空报告;零内容守卫(上轮补的)虽然会在未来拦住空树,但"能解却被留树"的能力缺口仍在。

同时,Step5 recon 的透视镜工具(binwalk_rescan)存在幽灵扫描缺陷:binwalk v3 对打不开的文件**退出码仍为 0**、ERROR 只打在 stderr,工具只看退出码与 stdout,于是对解包树里不存在的文件返回 ok=True"分析了 1 个文件(0 命中)"——target/4 e2e 里 recon 的"0 签名"观察全部是假象。

更深层:识别表落后于 binwalk 签名库这一落差**没有任何机制能发现**,镜像升级悄悄引入新可解签名时会重演 target/4。

## Solution

三件事:

1. **对齐表**:把引导解包器的路由与 binwalk 可解签名集**机械对齐**——从 vendor 源码(仓库内)提取全部"有 extractor"签名的魔数(72 个),落成静态对齐表(签名名/魔数字节/偏移/出处备注),与既有识别表、容器裁决合并;另立**显式忽略清单**(决定不路由的签名 + 理由)。binwalk 解不了的厂商魔数,直接明确终止报"解不了"。
2. **漂移守护**:Docker 门控测试解析 `binwalk -L`,断言"每个可解签名 ∈ 对齐表 ∪ 忽略清单"——镜像升级新增签名时测试变红,表永不悄悄落后。
3. **幽灵扫描修复**:binwalk_rescan 宿主侧预检文件存在 + stderr 失败判定,agent 的观察不再建立在没发生过的扫描上。

验收:target/4 旧工作区归档改名后重跑(两阶段,先 `--no-step5`),Step1 解出全量 rootfs。

## User Stories

1. As 审计工程师, 我要让 SHRS 这类厂商加密固件在 Step1 就被自动解包,so that 审计覆盖真实固件内容而不是产出"解包阻塞"空报告。
2. As 审计工程师, 我要路由表覆盖 binwalk 能解的每一个格式,so that 不再出现"binwalk 能解、我们留树"的能力缺口。
3. As 维护者, 我要漂移守护测试在镜像升级引入新可解签名时变红,so that 表与镜像能力的落差永远机械可见、不会悄悄复发 target/4。
4. As 审计工程师, 遇到 binwalk 也解不了的厂商魔数,我要流水线明确终止并报"解不了",so that 不再有静默空转烧 token。
5. As recon agent, 我调 binwalk_rescan 时若文件不在解包树要收到引导性报错,so that 我的观察全部建立在真实发生的扫描上。
6. As analysis agent, 我要 rescan 的 stderr 错误被识别为失败,so that 不会把"没扫"当成"扫了 0 命中"来引用。
7. As 维护者, 我要 target/4 的空转审计工件归档保留,so that "空转 vs 真审计"的对比证据可回溯(升级链红线的实测也在里面)。
8. As 维护者, 我要两阶段验收(先 --no-step5),so that 解包层改动的验证不烧 LLM 预算。
9. As 审计工程师, target/4 重跑后我要在 extracted/ 看到 rootfs 实体(etc/passwd、www/ 等),so that 对齐表的效果有机械可查的证据。
10. As 维护者, 忽略清单的每一条要带理由,so that 后人可以复核"当初为什么不管它"。
11. As 维护者(或未来的提问者), "为什么不全交 binwalk"的答案要写在引导解包器代码的 docstring 里,so that 这个反复被问到的问题在现场就有答案(静默失败/容器成本/fdt 旧疾三条实证)。
12. As agent, binwalk 解不了的不透明文件维持既有语义(留树 + strings_query 兜底 + 全树零内容时守卫终止),so that 既有纪律不回退。
13. As 维护者, 对齐表每条要带出处备注(如 SHRS = D-Link 私有加密、binwalk ≥3.1 内置解密),so that 表是自解释的知识库而不只是开关列表。
14. As 无 Docker 环境的 CI, 漂移守护与真解包测试要自动 skip,so that 测试套件在任何环境不红。
15. As 审计工程师, 既有 33 项格式(gzip/squashfs/ext4/uimage 等)的路由行为不变,so that 对齐是纯增量、不回退。
16. As 维护者, 漂移守护要对齐的是**当前镜像**的真实能力(运行时解析 binwalk -L),so that 断言对象是事实而非又一份会过时的清单。
17. As 审计工程师, 固件内部的裸 ext4/jffs2 等文件系统文件仍按既有路径路由,so that 分区/文件系统审计能力不受影响。
18. As 维护者, 术语要统一(识别表/容器裁决/对齐表/binwalk 签名库),so that spec、代码注释、CONTEXT.md 说的是同一套话。
19. As 审计工程师, 幽灵扫描修复后,recon 对 target/4 这类工作区会立刻看到"文件不在解包树"的真相,so that 误导性观察链(0 签名→可按名解析)不再出现。
20. As 维护者, 对齐表与忽略清单的同级守护测试要有双模式(独立跑 + pytest 收集)兼容,so that 与仓库测试基建一致。

## Implementation Decisions

**对齐表(票01)**:

- 形态:静态声明表,条目 = {binwalk 签名名, 魔数字节, 偏移, 出处备注};数据来源 = 仓库内 vendor 源码的 magic 定义函数(形式规整,可机械提取)交叉核对 `binwalk -L` 的 72 个可解签名;与既有识别表、容器裁决集合并去重。基线:binwalk 3.1.1(当前镜像)。
- 消费:识别层命中对齐表魔数 → 容器裁决判 continue → 既有提取器(`binwalk -e` 单层 + 7z 兜底 + 产出闸门)负责解密与落盘。条目粒度**只到"交 binwalk"**,不设外部解密命令字段——binwalk 解不了的厂商魔数,维持 finalize,由零内容守卫终止并报"解不了"(含厂商加密头指引);真需要外部解密器时立新票。
- 忽略清单:extractor 为 None 的签名天然不入表;extractor 非空但决定不路由的,逐条列名 + 理由。
- 前缀匹配 vs binwalk 深度校验的差异无害:多付一次空容器后走既有留树路径。
- 命名纪律:识别表(魔数→签名名)/ 容器裁决(签名名→是否继续解)/ 对齐表(与 binwalk 可解集对齐的路由声明)/ binwalk 签名库(执行器的知识,非我们所维护)。
- docstring:引导解包器模块注释承载"为什么不全交 binwalk"三理由(binwalk v3 失败方式是静默成功——rc=0 空输出,今日两度实测;每文件一容器成本 30 万文件级不可行;fdt 61.6 万节点旧疾)。

**幽灵扫描修复(票02)**:

- 宿主侧预检:file_ref 解析后必须真实存在于解包树,否则 ok=False 引导性报错("文件不在解包树,用 list_files 确认")。
- 失败判定:stderr 含打开/读取失败标记(实测 "Failed to open/read")→ 一律 ok=False,不信任 v3 退出码;工具注释记录此实测坑。

**验收与文档**:

- target/4 旧工作区归档改名(不删),全新重跑 `--no-step5`:Step1 解出含 etc/、www/ 的全量 rootfs;Step5 真跑择机单独触发(不属本 spec 验收)。
- CONTEXT.md"引导解包"词条补一句(解包路由与 binwalk 可解集对齐、漂移守护防落后);不立 ADR(可逆、权衡在代码 docstring)。

## Testing Decisions

只测外部行为:给定工作区状态与输入,断言路由判定、解包产物、ToolResult 的 ok/text/error;不断言表项的内部排列。

- **纯函数层(既有缝)**:识别/裁决函数对对齐表新签名的命中与路由(魔数样本即表项本身);fdt 硬跳过、ELF/文本 product、既有 33 项行为不变的回归。先例:step1 引导解包既有单测(fake extractor 注入点)。
- **漂移守护(Docker 门控,既有缝)**:解析真实镜像 `binwalk -L` 输出,断言可解签名集 ⊆ 对齐表 ∪ 忽略清单;无 Docker 自动 skip(与 cli_tools 门控先例一致)。
- **工具 execute 层(既有缝)**:binwalk_rescan 的 mock 容器测试——不存在文件 → ok=False 引导文案;stderr 失败注入 → ok=False;正常识别 → 现行为不变。先例:test_step5_r2_tools 的替身补丁模式。
- **门控 e2e**:真 SHRS 解包(target/4 存在时):binwalk 一条命令解出 decrypted.bin 并识别 uImage。终验以手动归档重跑为准(结论贴票评论)。

## Out of Scope

- "顶层不透明文件先咨询 binwalk"的演进方向(v1 不实现,注册表注释留档;第二个未知魔数案例出现时立票)。
- 外部解密命令字段 / 自建解密器框架(Q9 定案:binwalk 解不了就直接报解不了)。
- agent 端"按需解包"工具(Step5 落盘边界不动,ADR-0010)。
- Step5 真跑验收(择机单独,涉及真金预算)。
- 其他厂商魔数的逆向(SHRS 由 binwalk 内置,白捡;新方案要逆向时另议)。
- binwalk 上游贡献(对齐在我们的表完成,v3 扩展是 Rust 上游 PR,周期长收益边际)。

## Further Notes

- 关键实测锚点(2026-09-10):`binwalk -e` 对 target/4 一条命令解出 13MB decrypted.bin → uImage(MIPS32/LZMA)→ `-e -M` 全量 rootfs(bin/etc/lib/www 18 顶层目录);binwalk v3 对不存在文件 rc=0 + "Analyzed 1 file"(幽灵扫描实锤);target/4 空转成本 ~300 万 token。
- 前置依赖:零内容守卫已在(master,498f712);本 spec 落地后它从"唯一防线"退为"最后防线"。
- 参考资源:dlink-decrypt PoC(本例不需要,binwalk 内置已覆盖)、EMBA 对齐思路(社区同方向实践)。

## Addendum 2026-09-10(票03 验收 + 范围扩展,用户拍板)

- 票03 实测:对齐表链路(SHRS→解密→uImage→lzma)全部到位、零内容守卫不再触发;但 rootfs 实体(etc/、www/)未物化——它藏在内核内嵌 initramfs 深处(gzip@0x6221C8→cpio),offset-0 对齐表路由结构性到不了(票01 交接预警命中)。
- 原 Out of Scope 第一条("顶层不透明文件先咨询 binwalk")的触发条件成立:target/4 的 18.6MB 内核镜像"头部无签名 finalize 留树"即活案例,且实证 `binwalk -e -M -x dtb` 可解出全量 rootfs(19 顶层目录/1310 文件)。
- 用户拍板:**范围扩展立增强票 04**(finalize 前大体积无签名文件守卫全偏移复扫);票03 按"manifest 解密链到位"口径关闭。
