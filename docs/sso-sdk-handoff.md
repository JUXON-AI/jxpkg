# SSO SDK 最终架构与跨仓交接

核对日期：2026-09-11。关联：
[Issue #16](https://github.com/JUXON-AI/jxpkg/issues/16)、
[JXpKG PR #17](https://github.com/JUXON-AI/jxpkg/pull/17)、
[Account PR #3](https://github.com/JUXON-AI/jxaccount/pull/3)、
[JXOne PR #7](https://github.com/JUXON-AI/jxone/pull/7)。

## 冻结版本

| 仓库 | 当前实现提交 | 作用 |
| --- | --- | --- |
| JXpKG | `fbaafaea11397b928d0344b7e837478ec94dbcfc` | Consumer/Provider、路由边界、Browser 与 Bearer 隔离 |
| Account | `5ab5fa012f425152f44aa4a4c8fa34f6ed70597e` | 唯一 Authority、Provider 接入、legacy Bearer 弃用标记 |
| JXOne | `3c5b7c6538b12002152c49826de6aebf7b2f95a6` | 最小 Consumer 接入、业务 accessor 使用 |

Account 与 JXOne 固定官方 pseudo-version
`github.com/JUXON-AI/jxpkg v0.0.14-0.20260911085822-fbaafaea1139`。
源码、`go.mod`、`vendor` 和最终镜像均无 `replace`。

## 最终边界

应用只做三件事：启动时加载一次 runtime、给 router 安装一个 option、给业务
action 选择一个明确的认证 registrar。应用不创建 Cookie/CSRF/CORS middleware，
不创建 resolver transport，不读取 `LoginStatus`，不复制 principal 字段。

```go
ssoRuntime, err := sso.LoadEnv(os.Getenv, "JUXONONE")
if err != nil {
    return err
}
defer ssoRuntime.Close()

router := server.NewRouter(
    "/v1/",
    ssoRuntime.RouterOption(),
    server.WithGracefulShutdownTimeout(httpDrainTimeout),
)
router.PRequireBrowserSession("juxonone.ListProjects", ListProjects)
```

业务只从 JXpKG 读取已经验证的事实：

```go
runtime.UserID(ctx)
runtime.UIN(ctx)
runtime.CompanyID(ctx)
runtime.MembershipEpoch(ctx)
runtime.BrowserSessionExpiresAt(ctx)
runtime.LoginWay(ctx)
```

没有当前生产调用的 getter、facade、wrapper 或测试专用公开方法不保留。

### Browser 请求执行顺序

`PRequireBrowserSession` 固定执行：

1. 从当前 Host 的唯一 `__Host-` Cookie 读取不透明 Session ID；
2. 通过专用 mTLS client 调用 Account resolver；
3. Account Authority 校验 Client/Host、会话、撤销状态、期限、公司成员状态与 epoch；
4. JXpKG 校验返回 principal 完整性并发布 UserID/UIN/CompanyID/MembershipEpoch；
5. `RequireAuthenticated` 拒绝任何未完成认证的请求；
6. unsafe method 校验精确 Origin 和 Session 绑定 CSRF；
7. 进入业务 handler，由业务服务执行公司/项目 RBAC。

这一链不会执行 `AuthInject`。Browser Session 已经由 Account Authority 完成权威
重验证，再调用应用 Bearer injector 会造成重复查询和错误的双重认证结构。

### Bearer 兼容边界

`AuthInject` 现在只由 `PRequireBearer` 调用。Account 暂时保留并明确标记
`Deprecated:` / Swagger `@Deprecated` 的三个 action：

- `account.ListMyIdentities`
- `account.SwitchIdentity`
- `account.GetCurrentIdentity`

当前部署的新版 `jxone-web` 使用 `/auth/session`、`/auth/identities`、
`/auth/switch-identity`、`/auth/logout`；新版 `jxaccount-web` 使用 OIDC interaction
Cookie 和 `credentials: include`，两者都不发送用户 Bearer。旧 `jxone-web/main`
直接调用上述 Account action，因此当前不能让三条路由失效；仓库外客户端还需通过
调用观测排除。`jxx` 的自身生产路由仍大量使用 JXpKG `PRequireLogin`，它不是当前
Account 三个 endpoint 的调用证据，但会阻止直接删除 SDK legacy alias。后续禁止新增
用户-Bearer 调用：旧 Web/外部客户端归零后删除 Account 三套 contract；`jxx` 迁移后
再删除 JXpKG legacy alias。

JXWorker Bearer 是独立的 256-bit workload credential，不是用户令牌，不在弃用范围。

## JXpKG 公共接口

Consumer：

```go
sso.LoadEnv(getenv func(string) string, prefix string) (*sso.Runtime, error)
(*sso.Runtime).Origin() string
(*sso.Runtime).RouterOption() server.RouterOption
(*sso.Runtime).CompanyIdentityResolver() auth.CompanyIdentityResolver
(*sso.Runtime).Close() error
server.NewBrowserSessionOption(middleware.BrowserSessionOptions) (server.RouterOption, error)
(*server.Router).PRequireBrowserSession(action string, handlers ...interface{})
(*server.Router).PRequireBearer(action string, handlers ...interface{})
```

Multi-host T1 adds `middleware.BrowserSessionBinding{Host, Service, CookieName,
ExternalOrigin}` and replaces the old single-host fields with
`BrowserSessionOptions.Bindings`. `NewBrowserSessionHandlers` is the only low-level
browser constructor, returning Session/CSRF/Bearer handlers backed by one immutable
Host directory. The old `NewBrowserSessionMiddleware` and `NewCSRFMiddleware`
constructors are removed. Normal consumers still only install `Runtime.RouterOption`.

Every Host (including port) is exact. Bearer checks only its selected cookie;
an unbound Host still requires normal Bearer authentication without selecting a
browser cookie. Browser routes reject unbound Hosts. `LoadEnv` validates the configured origin belongs to the explicit
allowlist, then derives each allowlisted Host's own origin using that scheme, for
both CORS and CSRF. Low-level empty origins retain direct TLS/Host derivation.
Account 已从不可变 OIDC Client registry 构建所有 binding，并移除
`ACCOUNT_BUSINESS_HOST`。新增服务不应复制低层构造；完整 Client、caller、Ingress、
TLS 与 mTLS 配置见 [JX SSO 接入指南](sso-integration-guide.md)。

Provider：

```go
sso.LoadProviderEnv(getenv func(string) string, prefix string, authority sso.ProviderAuthority) (*sso.Provider, error)
(*sso.Provider).Serve() error
(*sso.Provider).Close() error
```

`ProviderAuthority` 只组合 `auth.SessionResolver`、
`auth.CompanyIdentityResolver` 与
`ServiceHostAllowed(service, host string) bool`。内部 wire DTO 在 Consumer 与 Provider
之间唯一共享；应用不定义第二份请求/响应模型。

已删除的冗余公共面包括 `BrowserSecurity`、`NewBrowserSecurity`、
`WithBrowserSecurity`、`WithBrowserSession`、复数 `RouterOptions`、无调用的
`GRequireBrowserSession` / `GRequireBearer` / `GRequireLogin` / `PRequireEmployee`、
公开 `SessionMetadata` 及其 getter、`ProviderOptions`、`Provider.Addr` 和公开
`Provider.ServeHTTP`。`PRequireLogin` 只作为 legacy Bearer 的 deprecated alias 保留。

## JXOne 修改清单

| 文件 | 已实施动作 | 结果 |
| --- | --- | --- |
| `apps/juxonone/cmd/sso.go` | 整删 | 删除 transport、TLS、CORS、Cookie、resolver options 的应用组装 |
| `apps/juxonone/cmd/sso_test.go` | 整删 | 迁走的协议行为由 SDK 测试覆盖 |
| `apps/juxonone/internal/mds/loginstatus.go` | 整删 | 删除应用 principal injector |
| `apps/juxonone/internal/mds/loginstatus_test.go` | 整删 | 不以重复测试倒逼重复生产 API |
| `apps/juxonone/internal/apis/api.go` | 删除 `AuthInject` | 业务 action 只保留 `PRequireBrowserSession` 声明 |
| `apps/juxonone/cmd/main.go` | 改用 `LoadEnv` + 一个 `RouterOption` | SSO 只存在于 composition root |
| `apps/juxonone/services/svrcollaboration/ticket.go` | 改用 `runtime.BrowserSessionExpiresAt` | 不再读取 `LoginStatus` / Session metadata |
| `apps/juxonone/session_resolve_integration_test.go` | 删除 app injector 接线 | 保留 Consumer→Provider→principal 的纵向验证 |
| `go.mod`、`go.sum`、`vendor` | 固定正式 pseudo-version | 无本地 SDK 替换、vendor 由 Go tooling 生成 |

`apps/juxonone` 非生成源码/测试合计新增 35 行、删除 467 行，净减少 432 行。
必须保留的代码是项目 RBAC、company identity directory 注入、collaboration ticket
与 Worker credential；它们是业务授权或 workload 边界，不是重复 Browser SSO。

## Account 修改清单

| 文件 | 已实施动作 | 结果 |
| --- | --- | --- |
| `cmd/session_resolver.go` | 整删 | Account 不再实现 listener/TLS/server 生命周期 |
| `services/svrsessionresolver/*` | 整包删除 | 删除重复 HTTP、wire DTO、SPIFFE、in-process resolver |
| `services/devssoauthority/authority.go` | 建立唯一领域 Authority | 本地 Browser 与网络 Provider 共用权威逻辑 |
| `cmd/main.go` | `LoadProviderEnv` + lifecycle closer | Provider 启停归 SDK，Account 只注入 Authority |
| `cmd/sso.go` | `NewBrowserSessionOption` | Account 不拼 middleware 顺序 |
| `services/svroauth/handler.go` | 只产出 Account-owned Browser options | Client/Cookie/Origin registry 仍归 Account |
| `internal/apis/api.go` | Browser action 使用 `PRequireBrowserSession` | legacy injector 紧邻 deprecated Bearer block，Browser 不调用 |
| `internal/apis/auth.go`、DTO、`services/svrauth/auth.go` | 三个 Bearer contract 标记 Deprecated | 保持兼容但阻止新代码采用 |
| `go.mod`、`go.sum` | 固定正式 pseudo-version | 无 `replace` |

Account PR 合计新增 858 行、删除 1631 行，净减少 773 行。新增主要是唯一 Authority、
SDK 纵向/生命周期测试和交接文档；生产重复 resolver 实现已删除。

必须保留 Account 的 OIDC/OAuth、Session 存储/撤销、Client registry、公司成员与 epoch、
RBAC、上游身份、验证码和动态 Host CORS。JXpKG 是协议边界 SDK，不是完整 IdP。

## K3s 设施结论

无需新增或修改基础设施。继续使用现有：

- `account-session-resolver` ClusterIP Service `:8443`，无公网 Ingress；
- `account-resolver-mtls` / `juxonone-resolver-mtls` Secret 与现有证书路径；
- `ACCOUNT_SESSION_RESOLVER_*` 与 `JUXONONE_*` 环境键；
- resolver caller/service/allowed-host 绑定；
- `account-api-ingress` 与 `account-session-resolver-ingress` NetworkPolicy；
- 现有 Redis、MySQL、PVC、Ingress 和 workload 权限；
- JXOne `terminationGracePeriodSeconds: 90`。

本次协议、Cookie、Secret、端口、存储格式和 DB schema 均未改变，不需要 migration、
密钥轮换、sidecar、Gateway 或数据回滚。最终 candidate digest 已写入 `k3syaml`
release set 并由正常 promote workflow 部署。旧 `ACCOUNT_BUSINESS_HOST` Secret key
只作为回滚兼容项保留，新镜像不再读取它。

## 最终部署证据

namespace `jxone` 当前 candidate：

| Workload | Source | Immutable image |
| --- | --- | --- |
| Account API | `5ab5fa012f42` | `account-api@sha256:fabe5118cc4b853dbb15d63a983f4979601811262bc8aece9dc3e65e61738d70` |
| JXOne API | `3c5b7c6538b1` | `juxonone-api@sha256:3eb95dc0bb70a49a056458233c208a8acd5b8848d6cf7b267e03bd7b84eac364` |
| JXWorker | `3c5b7c6538b1` | `jxworker-api@sha256:6961d617641c96073781f71c09bfb40f5604ae9d3588c9e2d522ff1185253d31` |

镜像 buildinfo 均包含 JXpKG pseudo-version `...-fbaafaea1139`。Account 还直接记录
`vcs.revision=5ab5fa0...` 和 `vcs.modified=false`；JXOne Docker build context 排除
`.git`，因此其 app binary 无 VCS setting，源码身份由 CI checkout SHA 与不可变 tag/digest
共同固定。

验证结果：

- release set：`k3syaml` `01afaf396974`，deploy run `34584065918` 成功；
- rollout：Account/JXOne/Worker Ready 为 1/1/2；4 个当前 Pod 均 0 restart；
- 日志：未发现 panic、fatal、x509、resolver 或 Redis 错误；
- `k3syaml` `module` smoke：`pass=22 fail=0 blocked=0 manual=0`；
- Worker 边界：旧 credential 404、匿名 401、有效 credential 进入 handler；
- graceful rollout：两名 Worker、八次 heartbeat 均完成；
- 合法 JXOne client certificate + 无效 Session：HTTP 401 `invalid_session`；
- 无 client certificate：TLS 1.3 `certificate required`，curl exit 56；
- `/auth/login?return_to=%2F`：HTTP 302 到 Account OIDC authorize；
- 缺少输入的 `/auth/callback`：HTTP 400。

以上不是使用真实用户凭据完成的浏览器验收，不能替代登录、身份切换、权限、CSRF、
跨源拒绝和退出失效的人工作业。

## 测试与已知限制

| 范围 | 结果 |
| --- | --- |
| JXpKG | `go test -count=1 ./...`、runtime race、vet、build、`make check` 通过 |
| Account | 全仓 test/race、vet、build、`go mod verify`、SIGTERM 与 SDK 纵向测试通过 |
| JXOne | build、module verify、SSO/router/startup/collaboration/project 相关 race 通过 |
| JXOne full test | 唯一失败为未修改的 `devcanvas/TestWorkshopNumbersRetainValidation` 浮点/整数边界 |

JXOne 的已知 full-test 失败不算 SSO 回归，但合并前应独立修复或由仓库维护者正式接受；
不能删除测试来取得绿色结果。

## 下一个 agent 的执行顺序

1. 从各仓 `origin/main` 更新代码，并确认应用 `go list -m` 指向
   `...-fbaafaea1139`、无 `replace`。
2. 全仓搜索 `AuthInject`、`PRequireLogin`、`PRequireBearer` 和 Browser Session getter；
   仅允许本文件描述的真实生产消费者，测试引用不能成为保留公共 API 的理由。
3. 复跑各仓 format/vet/test/race/build；将 devcanvas 基线失败与 SSO 结果分开记录。
4. 新服务按 [JX SSO 接入指南](sso-integration-guide.md) 完成 Account Client/caller、
   Ingress、公网 TLS、resolver mTLS 和八个 Consumer 环境变量，不复制 middleware。
5. 后续镜像仍需用受信 JX-LAN runner 构建，并核对 binary buildinfo、registry digest、
   release set 与 Deployment `imageID`，不要只核对 tag。
6. 使用真实账号验证 Browser login、identity switch、公司/项目 403、Origin/CSRF、
   logout 后旧 Session 失效；不要把 302 bootstrap 当成完整登录成功。
7. 为 deprecated user-Bearer 统计剩余调用。迁移旧 `jxone-web/main` 并确认无仓库外
   客户端后，删除 Account 三个 action、DTO、service wrapper 和 injector；迁移 `jxx`
   的 legacy registrar 后再删除 JXpKG alias。JXWorker credential 始终保留。

## 整洁度结论

当前 Browser SSO 路径满足单一接入点、固定 middleware 顺序、单一 Authority、单一
wire contract 和最小业务 accessor。新 public API 均有真实生产调用，没有测试专用
public symbol，也没有近义 wrapper 链。剩余用户 Bearer 是明确隔离并标记弃用的迁移债，
不是 Browser SSO 的一部分；在真实调用归零前直接删除会造成兼容性故障。

提交邮箱：`nokeruila@gmail.com`。
