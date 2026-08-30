# firmware_audit 代码冗余清理与优化对比说明（2026-08-29）

> 范围：`firmware_audit/` 生产源码 + 测试（不含 DeepAudit 参考库、docker 镜像构建脚本中的第三方工具）。
> 方法：ruff 0.16.5 静态扫描（F/SIM 冗余类）+ 手动逐处核验；**只做无行为变化的等价变换**。
> 验证：`pytest` 全量 176 passed + 10 skipped（与优化前一致）、70 个业务模块 import 冒烟通过、冗余类扫描全部清零。

---

## 1. 清理内容分类统计

| 类别 | 数量 | 说明 | 处理 |
|---|---|---|---|
| F401 未使用导入 | 5 | step0_preprocess(`os`)、run_step5(`ALL_CONFIGS`/`run_agent`)、test_security_hardening(`json`/`os`) | 删除 |
| F841 未使用变量 | 1 | test_orchestrator `tr2`（仅副作用调用） | 删赋值保留调用 |
| F541 无占位 f-string | 6 | prompts/list_files/ghidra test_decompile | 去 `f` 前缀 |
| SIM105 try-pass → `contextlib.suppress` | 约 10 | step0×2、step1×1、step4×5、test×2 | 等价改写 |
| SIM110 for-return-bool → `any(...)` | 5 | step2_filter×4、step4×1（惰性短路语义一致） | 等价改写 |
| SIM102 嵌套 if → 单 if+and | 8 | step0_split_img | 等价合并 |
| SIM103 条件直返 / 分支合并 | 2 | step0_split_img（rootfs/recovery 两行合并）；step4 | 合并；1 处拒绝（见 §3） |
| SIM108/SIM201/SIM117（test 风格） | 3 | test_step5_react/pipeline/llm | 等价改写 |
| **合计** | **约 40 处** | | |

## 2. 代表性改动对比

**① 死循环扫描 → any（step2_filter.py::_is_blacklisted）**
```python
# 优化前
for p in BLACKLIST_PATTERNS:
    if p in logical:
        return True
return False
# 优化后
return any(p in logical for p in BLACKLIST_PATTERNS)
```

**② 重复分支合并（step0_split_img.py::should_extract）**
```python
# 优化前:两条几乎相同的判定
if kind == "rootfs" and size <= max_size_bytes:
    return True
if kind == "recovery" and size <= max_size_bytes:
    return True
# 优化后
if kind in ("rootfs", "recovery") and size <= max_size_bytes:  # noqa: SIM103
    return True
```

**③ 无占位 f-string（list_files.py 截断提示）**
```python
# 优化前
text += (f"\n...(已达上限被截断,...")
# 优化后
text += ("\n...(已达上限被截断,...")
```

## 3. 明确不做/拒绝的事项（含理由）

| 项 | 理由 |
|---|---|
| `ExtractInfo.py` F821（`getScriptArgs`/`currentProgram`/`basestring`/`unicode`） | Ghidra Jython 环境注入全局/py2 兼容，**必须存在**；文件头加 `# ruff: noqa: F821` 显式声明，不改代码 |
| step0_split_img `should_extract` 尾段 SIM103 直返 | 函数是多守卫提前 return 结构，直返会破坏前置 SKIP/必提分支的可读性 → 加 noqa 拒绝 |
| orchestrator 溯源回填 SIM105 | try-except-pass 承载"回填失败不阻塞"的明确语义注释，压成 suppress 会丢意图 → 加 noqa 拒绝 |
| ruff 默认 130 项风格规则（E/W/I：引号/换行/import 排序） | 纯风格、非冗余，自动 fix 会产生大 diff 噪音且不改变可读性本质，本轮不追（如需可另开风格统一任务） |
| 行为性重构（如改函数签名/合并模块） | 超出"冗余清理"目标，且引入回归风险，不做 |

## 4. 验证结果

| 验证项 | 结果 |
|---|---|
| pytest 全量（优化前 → 优化后） | 176+10 SKIP → **176+10 SKIP（一致）** |
| 冗余类扫描（F401/F841/F541/F821/SIM102/103/105/108/110/117/201/PIE790） | 34 → **All checks passed** |
| 全业务模块 import 冒烟 | 70 模块全部可导入 |
| 运行效率 | 等价变换（any 惰性短路、suppress 同 try 开销），无性能差异 |

## 5. 结论

完成对 40 处冗余的清理与逻辑简化：删除未用导入/变量 6 处、无占位 f-string 6 处、for→any 5 处、嵌套 if 合并 8 处、try-pass 规范化约 10 处；对 3 处"lint 建议与可读性/语义冲突"的位置显式 noqa 声明并说明理由。全部改为无行为变化的等价写法，全量测试无回归，执行效率不变。