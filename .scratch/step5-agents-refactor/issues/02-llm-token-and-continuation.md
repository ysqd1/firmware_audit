# 02: LLM token 预算与截断续写

**What to build:** `DEFAULT_MAX_TOKENS` 从 16384 提到 32768(env `LLM_MAX_TOKENS` 仍可覆盖);`chat()` 内 content 空 + reasoning 非空时,不判空回复硬重试,而是截断续写——构造续写请求(assistant 消息带 reasoning_content + "直接给最终答复,别展开思考"的 user 提示),用原 max_tokens 再调一次。续写只回传 API 接续,不进 ReAct 上下文/长期记忆,`chat()` 对上层透明;续写请求失败(400 等)→ 降级为普通重试。

**Blocked by:** None(可立即开始)

**Status:** done

- [x] `DEFAULT_MAX_TOKENS` 16384→32768,env 可覆盖
- [x] content 空 + reasoning 非空 → 触发截断续写(assistant 消息回传 reasoning + 续写提示),用原 max_tokens 再调
- [x] 续写只回传 API,不进 ReAct 上下文/长期记忆,`chat()` 对上层透明(上层仍只拿 content)
- [x] 续写请求失败(400 等)→ 降级为普通重试,不阻塞流程
- [x] LLM 级 `chat()` 测试:打桩"content 空 + reasoning 非空"→ 断言续写请求发出 + 返回续写 content;续写失败 → 断言降级重试
