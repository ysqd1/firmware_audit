# 01: 工具接口契约声明与校验

**What to build:** 每个工具把 `params_doc` 从自由散文改为结构化参数声明(参数名→类型/必选/默认/枚举,用 dict 声明、零新依赖);`base.execute` 加统一参数校验钩子,按声明校验未知键/类型/缺失必选。read_file 收到 `recursive` 时返回"未知参数 recursive,已忽略;合法:path/offset/limit"的优雅错误,而非 Python 异常文案。涉及全部 15 个工具。这是后续 verification 重构与 token 续写的地基(契约稳定)。

**Blocked by:** None(可立即开始)

**Status:** ready-for-agent

- [ ] 每个工具声明结构化参数规格(dict:参数名→类型/必选/默认/枚举),零第三方依赖
- [ ] `base.execute` 按声明统一校验:未知键/类型错误/缺失必选,返回优雅错误而非异常
- [ ] read_file 收到 `recursive` 返回"未知参数已忽略;合法参数:path/offset/limit"
- [ ] params_doc 与校验共享同一份声明(单一来源),系统提示词里 LLM 看到清晰参数规格
- [ ] 工具级 `execute()` 测试:对每个工具构造非法参数调用,断言 `ok=False` + 优雅错误文本
