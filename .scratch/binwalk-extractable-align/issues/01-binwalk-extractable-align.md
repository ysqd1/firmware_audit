# 01: binwalk 可解集对齐表 + 漂移守护

**What to build:** 引导解包器的路由与 binwalk 签名库的可解集(72 个 extractor≠None 签名,基线 3.1.1)机械对齐:对齐表条目 = {binwalk 签名名, 偏移, 魔数字节, 出处备注},由 vendor 源码 magic 定义提取、人工过一遍,与既有识别表/容器裁决合并去重;显式忽略清单逐条带理由;识别命中即路由给既有提取器(`binwalk -e` 单层 + 7z 兜底)。binwalk 解不了的厂商魔数维持 finalize,零内容守卫终止文案更新为"可解集已对齐仍零内容"口径(SHRS 已能解,不能再当反例)。Docker 门控漂移测试解析真实镜像 `binwalk -L`,断言可解签名集 ⊆ 对齐表 ∪ 忽略清单 ∪ 既有名映射。模块 docstring 承载"为什么不全交 binwalk"三理由(静默失败/容器成本/fdt 旧疾)。规则出处:spec(binwalk-extractable-align)。

**Blocked by:** None (can start immediately)

**Status:** ready-for-human

- [x] 对齐表落地:72 个可解签名逐一入表或入忽略清单(带理由),SHRS 为其中一条;既有 33 项格式行为不变(回归)
- [x] 新签名命中路由验证:至少 SHRS/arcadyan/yaffs2 等代表条目走 fake extractor 的路由单测
- [x] 漂移守护(Docker 门控):解析 `binwalk -L`,可解集 ⊆ 对齐表 ∪ 忽略清单 ∪ 名映射;无 Docker 自动 skip;双模式兼容
- [x] 零内容守卫文案更新(不再举 SHRS 为不可解反例);docstring 三理由落地
- [x] 全套件绿

## Comments

**2026-09-10 implement**(工单完成,待人工验收):

- 新 `align_table.py`:ALIGN_TABLE 34 个签名(多魔数签名展开多行,共 60 行条目)+ IGNORE_LIST 20 条(逐条理由);覆盖记账 72 = 18 既有别名 + 34 对齐 + 20 忽略。备注即知识:SHRS 条目注明"D-Link 私有加密,target/4 实测,binwalk ≥3.1 内置解密"。显式忽略的代表:dtb(fdt 旧疾永不解包)、srecord(文本型,与 ADR-0011 分诊知识同轨)、encfw(魔数是动态 ID 表无法静态提取)、媒体/证书类(审计对象非容器)、mbr(与 fat 同魔数位已覆盖)、dmg(koly 尾块 offset-0 锚定不适用)。
- 消费:`sniff_magic` 扫对齐表(offset 0 与非 0 统一切片语义);`rule_decision` 容器集 = 核心集 ∪ ALIGN_NAMES;`main` 零内容守卫文案改"可解集已对齐仍零内容——binwalk 不识别该固件"(SHRS 反例移除,配套测试断言同步)。
- 魔数来源:vendored 源码 `signatures/*.rs` 的 `magic()` 函数机械提取(字节串 + hex 数组两种形态),与 `binwalk -L` 的 72 可解名清单求交;8 个非平凡形态人工处理(arcadyan 函数名不同/iso9660 偏移 0x8001/pchrom/uefi_pi_volume 偏移 40/vxworks_symtab 6 弱魔数/srecord×2 文本型/encfw 动态表)。
- 漂移守护(`test_step1_align.py`,Docker 门控):解析真实镜像 `binwalk -L` 断言可解集覆盖;踩了两个解析坑已修——"Extractable signatures: 72" 尾巴行被当成签名(数字尾过滤)、dxbc 漏登忽略清单(测试当场抓出,守护本身首次运行就证明了自己)。
- **实弹验证**:拷贝 target/4 固件真跑引导解包,manifest 三层链条:`fw.bin: continue(容器签名 shrs)` → `decrypted.bin: continue(uimage)` → `decompressed.bin: finalize 留树`(18.6MB 内核镜像,头部无表内魔数)。**SHRS 已从"零内容树"变为"解出 18.6MB 可审计内容"**。
- **留档给票03**:rootfs 实体(etc/passwd、www/)未物化——它在内核 initramfs 深处,binwalk 全偏移扫描能到(offset-0 表到不了),`binwalk -e -M` 实测可解出 18 顶层目录。票03 验收口径需二选一:接受"decompressed.bin 在树 + Step5 strings/r2 可审"为到位标准,或立增强票(initramfs/cpio 深层路由)。
- 全套件 324 passed + 2 skipped(基线 317+2;对齐路由 6 项 + 漂移守护 1 项新增,Docker 在场全部真跑)。

**2026-09-10 code-review 采纳修复**(标准轴评审,6 条锚定错误 + 窗口 + 假绿):

- **P1 锚定错误×6**:arcadyan(0x68)/dkbs(7)/apfs(0x20)/dms(4)/pchrom(16)/vxworks_symtab(8) 六条误用 offset-0——vendor parser 要求魔数出现在各自 MAGIC_OFFSET 处,offset-0 匹配必被 binwalk 拒绝(真实文件永不路由 + 无关文件白烧双容器,双向皆坏)。已按 vendor MAGIC_OFFSET 修正。
- **P1 iso9660 差一**:0x8001 → **0x8000**(9 字节魔数含前导类型字节,扇区 16 起始)。
- **P2-1 嗅探窗口**:生产嗅探只读前 4KB,≥4096 的锚定条目(iso9660@0x8000)生产不可达,而测试直喂全长数据掩盖了这一点。修复:嗅探窗口改 `_SNIFF_WINDOW = max(4096, 对齐表最大锚点+魔数长)`——未来新锚点自动适配。
- **P2-2 假绿漏洞**:漂移守护在"-L 输出格式漂移导致解析空集"时断言空转通过。加哨兵:解析结果必须非空且含已知签名 shrs,否则守护响亮失败。
- **P3**:csman 弱魔数文本误报的"空产出留树兜底"承诺钉进测试(continue 路由 + 循环级原文件不丢);efigpt/uefi_pi_volume 补对称负例;测试布局改按真实锚定构造。
- 未采纳:P3 提交信息行数笔误(54 条非 60 行)——历史提交不改写,本条即为更正记录。
- 修复后全套件 324 passed + 2 skipped。
