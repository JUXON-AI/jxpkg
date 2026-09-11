# SSO SDK 最终架构与跨仓交接

核对日期：2026-09-11。关联：
[Issue #16](https://github.com/JUXON-AI/jxpkg/issues/16)、
[JXpKG PR #17](https://github.com/JUXON-AI/jxpkg/pull/17)、
[Account PR #3](https://github.com/JUXON-AI/jxaccount/pull/3)、
[JXOne PR #7](https://github.com/JUXON-AI/jxone/pull/7)。

## 冻结版本

| 仓库 | 当前实现提交 | 作用 |
| --- | --- | --- |
| JXpKG | `a6a5c01063b44486ebf53b6c697f4cc536e22f52` | Consumer/Provider、路由边界、Browser 与 Bearer 隔离 |
| Account | `0e7520f8ace0ca889cfceef9d092612254dfd28f` | 唯一 Authority、Provider 接入、legacy Bearer 弃用标记 |
| JXOne | `ee63b80a5213b3f3efcf626304e69d8dc791e143` | 最小 Consumer 接入、业务 accessor 使用 |

Account 与 JXOne 固定官方 pseudo-version
`github.com/JUXON-AI/jxpkg v0.0.14-0.20260911065453-a6a5c01063b4`。
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
Cookie 和 `credentials: include`，两者都不发送用户 Bearer。仍有生产源码调用的
兼容方是 `jxx` 与旧 `jxone-web/main`，并可能存在仓库外客户端，因此本 PR 不让
路由失效。后续禁止新增用户-Bearer 调用；上述消费者迁移并完成调用观测后，三个
action、DTO、service wrapper、Account `AuthInject` 和 JXpKG `PRequireLogin` 才能同批删除。

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
密钥轮换、sidecar、Gateway 或数据回滚。当前验证是直接设置 candidate digest；
合并发布时仍需把相同 digest 写入 `k3syaml` release set，不能从旧清单全量 apply。

## 最终部署证据

namespace `jxone` 当前 candidate：

| Workload | Source | Immutable image |
| --- | --- | --- |
| Account API | `0e7520f8ace0` | `account-api@sha256:9aa7e9cdf23dcac59ce6d248d76d9efe2e8d5d4cf051722ba950f96be0115126` |
| JXOne API | `ee63b80a5213` | `juxonone-api@sha256:6a98e56230ef9110cfa5718cfa223a414e3c869ee5cf9c3e7012b4605d29b787` |
| JXWorker | `ee63b80a5213` | `jxworker-api@sha256:64f5eb93e0725eb522999aa425b0d5ddff3f032312e0ea1ab6d8cc3e629a0dbb` |

镜像 buildinfo 均包含 JXpKG pseudo-version `...-a6a5c01063b4`。Account 还直接记录
`vcs.revision=0e7520f...` 和 `vcs.modified=false`；JXOne Docker build context 排除
`.git`，因此其 app binary 无 VCS setting，源码身份由 CI checkout SHA 与不可变 tag/digest
共同固定。

验证结果：

- rollout：Account/JXOne/Worker Ready 为 1/1/2；4 个当前 Pod 均 0 restart；
- 日志：未发现 panic、fatal、x509、resolver 或 Redis 错误；
- `k3syaml` `module` smoke：`pass=22 fail=0 blocked=0 manual=0`；
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

1. 读取三个 PR 当前 head，并确认应用 `go list -m` 指向 `...-a6a5c01063b4`、无 `replace`。
2. 全仓搜索 `AuthInject`、`PRequireLogin`、`PRequireBearer` 和 Browser Session getter；
   仅允许本文件描述的真实生产消费者，测试引用不能成为保留公共 API 的理由。
3. 复跑各仓 format/vet/test/race/build；将 devcanvas 基线失败与 SSO 结果分开记录。
4. 用受信 JX-LAN runner 按精确 SHA 构建，核对 binary buildinfo、registry digest 和
   Deployment `imageID`，不要只核对 tag。
5. 将三个验收 digest 写入 `k3syaml` release set，审阅仅有 image 变化且保留 90 秒
   grace period；按正常 promote workflow 做 migration 判定、rollout 和 smoke。
6. 使用真实账号验证 Browser login、identity switch、公司/项目 403、Origin/CSRF、
   logout 后旧 Session 失效；不要把 302 bootstrap 当成完整登录成功。
7. 为 deprecated user-Bearer 统计剩余调用。先迁移 `jxx` 和旧 `jxone-web/main`，确认
   无仓库外客户端后，一次性删除三个 action、DTO、service wrapper、Account injector
   与 JXpKG legacy alias；JXWorker credential 始终保留。

## 整洁度结论

当前 Browser SSO 路径满足单一接入点、固定 middleware 顺序、单一 Authority、单一
wire contract 和最小业务 accessor。新 public API 均有真实生产调用，没有测试专用
public symbol，也没有近义 wrapper 链。剩余用户 Bearer 是明确隔离并标记弃用的迁移债，
不是 Browser SSO 的一部分；在真实调用归零前直接删除会造成兼容性故障。

提交邮箱：`nokeruila@gmail.com`。
