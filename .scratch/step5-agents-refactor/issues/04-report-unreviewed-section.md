# 04: 报告未复核疑点独立区段

**What to build:** 报告生成器把 `verified=None` 的 finding(未进入 verification 前 K 条的疑点)放入**独立区段**(标记 ⚠ 未复核),不混入已验证区;这些疑点的 confidence 保留 analysis 初值,报告明确标注"未经复核,confidence 为 analysis 初值",让读者不误以为经过了验证。

**Blocked by:** 03(verification 每疑点一实例——未复核疑点正是它的产出)

**Status:** ready-for-agent

- [ ] 报告把 `verified=None` 的 finding 放独立区段(⚠ 未复核),不混入已验证区
- [ ] 未复核疑点 confidence 保留 analysis 初值,报告标注"未经复核"
- [ ] 已验证 finding 有完整 confidence + rationale,未复核的 rationale 为空、明确区分
