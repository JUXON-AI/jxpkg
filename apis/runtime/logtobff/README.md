# 全局管理端 Session

`New` 保留原员工组织模式。`NewGlobal(ctx, config, authority)` 为独立全局管理应用启用身份模式，不请求组织 scope、不读取组织成员身份、不暴露组织切换或账户中心路由。

`GlobalAuthority.Permissions(ctx, subject)` 每次授权在线核实用户、应用人员准入与当前角色，返回 `GlobalAccess`。`Allowed=false`（含零值）或 `ErrGlobalAccessDenied` 明确拒绝；`Allowed=true, Permissions=nil` 允许已准入但暂无业务权限的用户进入应用。其他错误按依赖故障处理，不当作放行或不存在。

资源 Token 必须属于配置的 issuer、client、audience 和用户，且不得携带组织身份；资源 Token 每次刷新，取其 scope 与在线权限的交集。共享库不规定业务 scope 名字，也不新增准入 scope。应用登记自己的具名动作与业务权限，人员白名单由 authority 决定。

Session Redis key 和加密 AAD 额外使用 `global:` 模式前缀，防止误用相同配置时跨模式读取。`GlobalFromContext` 仅发布管理员主体，不发布员工 Principal、组织身份或员工授权能力。

浏览器先 `GET /auth/session` 取得 `csrf_token`、`authority_epoch` 和 `expires_at`，仅存内存。业务 POST 与续期 POST 必须带同源 Origin、`X-CSRF-Token`、`X-Authority-Epoch`；权限交集变化返回 409 `authority_changed`，前端重新读取会话并隔离旧缓存。身份/权限读取失败返回 503；明确无准入返回 403。临时签名服务故障保留 Session。

`global_test.go` 使用本机 httptest 和纯加密测试，覆盖准入/权限分离、权限交集、Token scope 撤销、身份上下文隔离、CSRF/epoch/续期期限、跨模式 AEAD 和组织路由关闭。实际 Redis 会话租约集成测试需要单独提供隔离测试配置；默认跳过不代表已验证。

Authority 的 `GlobalAccess.Username` / `Name` 必须来自同一次在线核实的用户，仅用于显示，不参与身份或权限判断。全局模式不重复读取 UserInfo；异常、包含控制字符或超过 512 字节的名称会省略，不影响已确认准入。
