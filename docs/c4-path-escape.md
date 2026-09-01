# C4 架构体检落地:收敛工具层路径逃逸检查到 resolve_within

> 日期:2026-08-31
> 来源:`/improve-codebase-architecture` 体检候选 C4(Strong,安全相关)
> 关联:CONTEXT.md 术语(逻辑路径 / 白名单根)、rules.md(失败不崩 / 零第三方依赖)、C3 file_rules(同为"规则分叉收敛")

---

## 一、背景:体检发现的问题

Step5 工具层里,"file_ref 解析后必须仍在某根目录之下"这个**安全判定**,被**同一句逻辑复制了 6 处**,且各处的边界处理开始分叉:

```python
# 原各处的同一句 containment 判定(复制粘贴)
if p != root and root not in p.parents:
    ...
```

| # | 位置 | 白名单根 | 越界返回 |
|---|---|---|---|
| 1 | `base.resolve_analysis_file` | `process/analysis/` | `None`(静默) |
| 2 | `cli_base.container_path` | `extracted/` | `None`(静默) |
| 3 | `read_file._run` | `process/` | 报错 `路径越界` |
| 4 | `list_files._run` | `process/` | 报错 `路径越界` |
| 5 | `search_code._resolve_scope` | `process/`(默认 extracted/) | `None`(静默) |
| 6 | `binwalk_rescan._run` | `extracted/` | 报错 `非法路径` |

**问题**:
1. **规则分叉**:同一句逻辑复制 6 份,后续改动极易改一处漏五处(安全判定最忌讳这个)。
2. **根目录自身处理不一致**:有的地方(`resolve_analysis_file`)把根目录本身也当越界拒掉,有的(`list_files`)把 `.`/空串放行成根。
3. **None 参数契约靠隐式 `.strip()` 抛错**:`container_path(None)` / `resolve_analysis_file(None, ...)` 靠 `AttributeError` 被 `execute()` 统一捕获成"失败不崩"。收敛时若改成 `(ref or "")` 会把 None 静默转空串,空串通过 containment 后真的去碰 Docker——这是**真实回归**(见 §三)。

---

## 二、方案:`resolve_within` 收敛原语

在 `base.py` 新增唯一入口,其余 6 处全部改调它:

```python
def resolve_within(root: Path, ref: str | None) -> Path | None:
    """把 ref(相对路径,可能带 \\ 分隔)解析为 root 下的绝对路径;越界返回 None。"""
    base = Path(root).resolve()
    r = str(ref or "").strip().replace("\\", "/")
    if not r:
        return None
    cand = (base / r).resolve()
    if cand != base and base not in cand.parents:
        return None
    return cand
```

**语义约定**:
- 相对子路径 → 返回绝对路径。
- `.` / 根本身 → 返回根(containment 允许等于根;`list_files` 上游对 `.`/空串显式映射 root,行为不变)。
- `..` 越界 / 绝对路径 / Windows 盘符 → `None`。
- 空串 / `None` → `None`(不静默转 root)。
- **None 参数的原契约由各调用方保留**:`container_path`/`binwalk_rescan`/`resolve_analysis_file` 仍先 `file_ref.strip()`(None 抛 `AttributeError`,由 `execute()` 统一捕获为失败不崩)。这是有意为之——**None 是"参数缺失"而非"空路径"**,不应静默变成合法引用。

**6 处调用点改造**:
| 处 | 改法 | 行为保持 |
|---|---|---|
| `resolve_analysis_file` | `cand = resolve_within(base, ref + suffix)` | 越界 None;None 参数 AttributeError |
| `container_path` | `if resolve_within(root, ref) is None: return None` | 越界 None;None 参数 AttributeError |
| `read_file` | `.`/空串→root,其余 `resolve_within` | 越界报错;空串列根(原行为) |
| `list_files` | `.`/空串→root,其余 `resolve_within` | 越界报错;`.`,空串=根(原行为) |
| `search_code._resolve_scope` | `target = resolve_within(root, ref) if ref else root` | 越界 None(静默)→ 显式 directory 时报错 |
| `binwalk_rescan` | `if resolve_within(root, ref) is None: return ...` | 越界报错;None 参数 AttributeError |

---

## 三、收敛过程中的一个真实回归(cautionary)

初版把 `container_path` 的 `file_ref.strip()` 改成了 `(file_ref or "").strip()`,试图"宽容 None"。结果:

- `test_malformed_inputs` 期望 `file_ref=None` 返回 `AttributeError` 开头错误,而空串通过了 containment → 真的去跑 Docker → 超时 → `checksec 退出码 1` 报错。**测试立刻红了。**

教训:
1. **宽容参数会掩盖"缺参"这个真实错误**。None 应快速失败,不该被转成空串去执行。
2. **收敛重复逻辑时,每个调用点的异常契约也要一并 preserve**,不能只抄 containment 判定。

---

## 四、验证

- 新增单测 `test_resolve_within`(`test_security_hardening.py`):固化 `.`/空/None/`..`/绝对路径/盘符的边界语义。
- 既有越界测试全绿:`test_security_hardening`(resolve_analysis_file 越界)、`test_step5_parsing.test_container_path_security`(container_path 穿越)、`test_step5_tools`(read_file/list_files/search_code 越界)、`test_step5_cli_tools`(checksec/binwalk 越界)。
- `test_read_file` 补 None 缺参快速失败 guard(C4 回归护栏)。
- **全量 217 passed, 2 skipped**(比 C3 的 208 passed / 10 skipped 多出新增测试;skip 变化来自 Docker 镜像门控)。

---

## 五、code-review 追认(2026-08-31,两轴审查后)

对 C4 diff 跑了 `/code-review`(Standards + Spec 双轴并行 sub-agent),追认修复:

1. **`read_file(path=None)` 契约回归**(Spec 轴抓到,最重):初版 `(path or "")` 把 None 静默转空串→根→`ok=True` 列目录,违背"None 应快速失败"铁律。已修为 `path.strip()`(None 抛 `AttributeError` 由 execute 兜底),并补 `test_read_file` guard。
2. **`resolve_within` docstring 矛盾**(两轴都抓):docstring 原写"根目录本身→None",代码实际对 `.` 返回根。已修 docstring 明确:根自身合法、空/越界/绝对→None。
3. **空串行为变更未披露**(两轴都抓):`container_path("")`/`binwalk_rescan("")` 原放行到挂载根,现拒绝——是收紧但未声明。已补 docstring 注明。
4. **基线气味评估**(判断项):`resolve_within` 保留 `ref: str|None`(空引用拒绝语义自洽,调用方定报错方式);空串"→根"决策散 read_file/list_files/search_code 三处属残余,边际收益小,不动。

> 审查结论:两轴无硬违规遗留;最严重项(`read_file` None 回归)已修并加测试。

---

## 六、端到端验证(2026-09-01,`/verify`)

对 `target/1`(nano-ubuntu 固件)跑了两轮:

**D1 全流程 `python -m firmware_audit.main target/1`(exit 0)**
- Step2 过滤 `5541 → 2047 文件`,名单从 profile 加载(C3 核心);`etc/init.d`/`etc/ssh` 等该审的进入送审集,不再被当标准目录跳过。
- Step3 分类 2047、Step4 ELF=522(续传复用)全跑通,不透明分诊 225 全覆盖。
- 但 Step5 三子 Agent **skipped**(旧工件在),C4 工具层未真跑。

**D2 `run_step5 --force`(强制三子 Agent 真跑,exit 0)**
- recon 20 轮、analysis 多轮真跑:调 `list_files`×13、`read_file`×15、`search_code`×5、`semgrep_scan`×1。
- **C4 关键验证:所有 Agent 传入的合法路径(`extracted/...`/`analysis/...`/`agent/0_recon/survey.json`)零越界误报** —— `resolve_within` 没有误杀任何真实调用,收敛等价。
- Agent 误传参数(read_file 收到 `recursive`、semgrep 收到拼碎 JSON)→ 工具层 `TypeError` 被 execute 兜底"失败不崩",防御正常。
- analysis 中途 LLM API 连续失败(空回复×2 + HTTP 307×1)→ 重试 4 次全败 → **按 ADR-0002 干净终止,exit 0,不降级不崩** —— 实证了 ADR-0002 的"API 失败立即终止"。
- 局限:verification 子 Agent 与 `container_path`/`checksec`/`binwalk`/`cve_bin_tool_scan` 未在真实调用中触发(API 307 故障中断);这些在单测有越界覆盖。

---

## 七、遗留

- `list_files.py:34` `if "path" in kw and kw["path"]` 的 RUF019 提示(既有,非本次引入)。
- `base.py:83` `execute()` 的 `except Exception`(BLE001 提示)是"失败不崩"铁律的体现,不改。
- C4 收敛后,下一步候选:**C1**(拆 Step4 `decompile()` 1046 行入口 + 提测试覆盖,用户明确想)。
