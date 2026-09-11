# SSO SDK 清理与跨仓交接

核对日期：2026-09-11。本文按已落地的 Consumer + Provider 代码交接。
关联：[Issue #16](https://github.com/JUXON-AI/jxpkg/issues/16)、
[JXpKG PR #17](https://github.com/JUXON-AI/jxpkg/pull/17)、
[Account PR #3](https://github.com/JUXON-AI/jxaccount/pull/3)、
[JXOne PR #7](https://github.com/JUXON-AI/jxone/pull/7)。

| 仓库 | 当前代码证据 | 说明 |
|---|---|---|
| JXpKG | `c318a8267d4f74f6e29af49cc8cbacadd91d6312` | Provider、唯一 wire DTO、真实 TLS 与 shutdown 测试 |
| Account | `419726b7538d6c77b4fd2099d6ebf0a551d4d1e1` | Authority 接入、旧 resolver 包删除、SIGTERM 测试 |
| JXOne | `1d8212c03808c0e5506e958e2bee13e7df870ffe` | 依赖升级；Consumer API 不变 |

两应用固定官方版本 `v0.0.14-0.20260911043307-c318a8267d4f`。
接手时仍须读取 PR 当前 head；本表不是浮动分支的永久声明。

## 目标与已实现边界

业务应用只加载一次 SDK、挂载一个 RouterOption、声明受保护方法。
JXOne 不再实现证书加载、resolver transport、Session/CSRF/CORS 构造、
LoginStatus 字段校验或 MembershipEpoch 复制。项目权限仍归 JXOne。
Account 的同一个 Authority 被本地浏览器会话边界和网络 Provider 调用；
Provider 拥有内部 HTTP/mTLS 与 listener 生命周期，Account 继续拥有密码、
OIDC、Session 写入/撤销和公司身份权威数据。没有引入第三方 OIDC/IdP 替换、
新外部依赖、通用认证框架或新的部署拓扑。

本次对仓库认证关键词和调用点做全局检索，并沿启动、路由、injector、resolver、
公司/项目权限和部署路径审阅。不是对全部业务代码逐行做安全审计。

## 公共接口与执行顺序

已有公共接口，无需再增加近义 wrapper：

```go
sso.LoadEnv(getenv func(string) string, prefix string) (*sso.Runtime, error)
(*sso.Runtime).Origin() string
(*sso.Runtime).RouterOption() server.RouterOption
(*sso.Runtime).CompanyIdentityResolver() auth.CompanyIdentityResolver
(*sso.Runtime).Close() error
server.NewBrowserSessionOption(middleware.BrowserSessionOptions) (server.RouterOption, error)
sso.LoadProviderEnv(getenv func(string) string, prefix string, authority sso.ProviderAuthority) (*sso.Provider, error)
(*sso.Provider).Serve() error
(*sso.Provider).Close() error
```

`ProviderAuthority` 组合 `auth.SessionResolver`、
`auth.CompanyIdentityResolver` 和
`ServiceHostAllowed(service, host string) bool`，Account 只传入唯一 authority。
caller 配置仍从环境读取，并在启动时对 Account registry 逐项检查。
wire DTO 与严格 DecodeSessionResolveRequest/DecodeCompanyIdentityResolveRequest
归属 `apis/runtime/auth`，客户端与 Provider 使用同一份类型。
不新增 NewConsumer/NewProvider/Manager 等近义包装入口。

浏览器路由顺序是 Session resolver、默认身份发布或显式 AuthInject、登录要求、
CSRF、业务 handler。默认路径校验 BrowserSession 模式及非零
UserID/UIN/CompanyID/MembershipEpoch，然后发布上下文。显式 callback 仍执行，
拒绝结果仍生效。Bearer 没有 callback 时仍拒绝，不能借此次重构放宽。
Browser Session 的应用接入不再暴露 middleware pair、getter 或兼容入口。

## JXOne 文件与方法清单

分支 `cc/sso-sdk-cleanup`，工作目录 `jxone-sdk-cleanup`。

| 文件 | 实施动作 | 验收 |
|---|---|---|
| apps/juxonone/cmd/sso.go | 整删 127 行；删除 buildBrowserSessionOptions、newBrowserSessionCORS、newProductionResolverTransport 及三个 resolver timeout 常量 | 非测试应用源码不再直接创建 Session resolver transport/middleware |
| apps/juxonone/cmd/sso_test.go | 删除旧私有构造测试；协议行为由 SDK 与应用集成测试继续覆盖 | 不能只凭删除测试获得绿色结果 |
| apps/juxonone/internal/mds/loginstatus.go | 整删 InjectLoginStatus | SDK 自动发布 epoch，拒绝非法 principal |
| apps/juxonone/internal/mds/loginstatus_test.go | 删除迁走的重复测试 | SDK 增加默认 injector 正向、非法主体和 CSRF 回归 |
| apps/juxonone/internal/apis/api.go | 删除 mds import 和 AuthInject 注册 | 所有 PRequireBrowserSession 保留，Worker 路由保持独立 |
| apps/juxonone/cmd/main.go | LoadEnv 替代 transport/options/CORS 构造；defer Close；Origin 传给 initCollaboration；注入 CompanyIdentityResolver；挂载单个 RouterOption | 启动错误脱敏；migration-only 仍先退出；初始化及资源关闭顺序保持 |
| apps/juxonone/session_resolve_integration_test.go | 删除应用 injector import/注册；保留真实解析客户端与身份上下文断言 | 无 injector 时 user_id/uin/company_id/epoch 正确；失败不进 handler |
| go.mod、go.sum、vendor | 固定官方 SDK commit 的 pseudo-version；使用 go mod vendor 生成 | 禁止个人 fork、手改 vendor、提交本地 replace/go.work |
| README.md、docs/sso/README.md | 指向此次 SDK 接入说明，旧 AuthInject 图示标明历史基线 | 新服务按文档不需要应用 injector |

最终接入片段：

```go
runtime, err := sso.LoadEnv(os.Getenv, "JUXONONE")
// 启动边界处理 err，失败时终止；随后 defer runtime.Close()。
devproject.ConfigureCompanyIdentityResolver(runtime.CompanyIdentityResolver())
// initCollaboration(ctx, runtime.Origin()) 继续使用同一权威 Origin。
router := server.NewRouter("/v1/", runtime.RouterOption(),
    server.WithGracefulShutdownTimeout(httpDrainTimeout))
// 原有 workerAuth 参数及业务路由注册继续使用。
```

保留 internal/mds/worker.go 及其测试。devproject/access.go、membership.go 的
GetAuthoritativeProjectAccess、resolveCompanyIdentities、项目角色与 epoch 比较，
以及 devcollabtransport 的一次性票据/连接复核均具有业务职责，不能删除。
ConfigureCompanyIdentityResolver 是公司目录注入点，不是另一个浏览器认证层。

## Account 文件与方法清单

分支 `cc/sso-sdk-cleanup`，工作目录 `jxaccount-sdk-cleanup`。

| 文件 | 实施动作 | 验收 |
|---|---|---|
| cmd/main.go | newAccountRouter 组装公共路由；devssoauthority.New 创建唯一 authority；LoadProviderEnv 创建内部服务 | AddCloser(provider) 在启动时注册；Serve 错误触发 lifecycle.Exit；trusted proxies 与 upstream 生命周期保留 |
| cmd/sso.go | newAccountRouter 统一 NewBrowserSessionOption、CORS 和 OAuth/upstream 路由注册 | 生产与测试调用同一组装函数，构造失败在监听前返回 |
| cmd/sso.go | 删除无调用方的 buildProductionSSOHandlers、buildProductionSSOHandler | 全仓搜索无引用；不新增别名或转发 wrapper |
| cmd/sso.go、cmd/sso_test.go | assembleAccountRouter 移入 _test.go，只构造测试依赖并调用生产 newAccountRouter | 不把测试依赖工厂编进生产 |
| cmd/session_resolver.go | 整删 142 行及旧构造/timeout 测试 | Account 不再自行加载 resolver TLS、创建 server/listener 或实现关闭逻辑 |
| services/svrsessionresolver/handler.go、handler_test.go | 整删 HTTP/wire/SPIFFE 实现及纯协议重复测试 | 同类严格输入、caller、TLS 测试由 JXpKG Provider 承接 |
| services/svrsessionresolver/inprocess.go、inprocess_test.go | 整删，领域逻辑合入 Authority | 本地与网络不再各自实现一遍 ResolveApp/membership 检查 |
| services/svrsessionresolver/sdk_integration_test.go | 删除旧实现；新入口为 services/devssoauthority/sdk_integration_test.go | 新链是 SDK Consumer → SDK Provider → Account Authority → Redis |
| services/devssoauthority/authority.go | 唯一 Account 权威适配器，实现两个 auth resolver 接口与 ServiceHostAllowed | ClientID/Host 返回绑定、状态、epoch、领域错误转换；内部失败只记录一次脱敏日志 |
| services/devssoauthority/lifecycle_test.go | 真实子进程发送 SIGTERM，执行 AddCloser/WaitExit | 1.5 秒在途请求完成；验证 closer marker、进程正常退出和端口释放 |
| services/svroauth/handler.go | BrowserSessionOptions(host, authority) 接受同一个 auth.SessionResolver | 保留登记 Client/Cookie/Origin 装配，不在方法内部 new resolver |
| internal/apis/api.go | 保留显式认证边界与 Account AuthInject | 三个旧身份接口仍需 Bearer 数据库复核 |
| go.mod、go.sum | 与 JXOne 固定同一官方 SDK commit；Account 基线不跟踪 vendor，不引入整套 vendor | 发布后统一升级正式版本，不用浮动分支 |
| README.md | 说明公共 Browser Session 边界与 Account 专属能力边界 | 不声称 SDK 取代完整 IdP |

最终调用方式见 [runtime-sso.md](runtime-sso.md#account-issuer-integration)。核心接线如下，
各个构造返回的 error 都必须在启动边界处理后再继续：

```go
authority, err := devssoauthority.New(sessions, oauthHandler, devcompany.NewService(db))
if err != nil { return err }
provider, err := sso.LoadProviderEnv(os.Getenv, "ACCOUNT", authority)
if err != nil { return err }
lifecycle.Std().AddCloser(provider)
defer provider.Close()
browserSession, err := oauthHandler.BrowserSessionOptions(host, authority)
if err != nil { return err }
```

`LoadProviderEnv` 在构造时绑定 listener；后续启动失败必须释放资源。
`Serve()` 在 goroutine 运行，非空 error 触发 `lifecycle.Std().Exit()`。
不能只写 defer：`WaitExit` 最终调用 `os.Exit`，只有注册的 closer 会执行。
Provider 固定三秒 graceful drain，必要时强制关闭，Serve/Close 并发幂等。

Account 提交 `419726b` 共新增 703 行、删除 2090 行，净减少 1387 行；
其中生产 Go 新增 137 行、删除 792 行，净减少 655 行。数字含 Provider 接入及
日志修复；测试转移不被算作安全覆盖增加。JXOne 首次清理提交 `fc40a59`
新增 313 行、删除 410 行，净减少 97 行，数字含 SDK vendor 快照；
不能把 vendor 新增行误认为应用手写 glue。

必须保留的 Account 代码：

- services/svroauth/handler.go 的 BrowserSessionOptions：把选定的 ACCOUNT_BUSINESS_HOST、Client 注册表、Cookie 与同一个 authority 适配为公共配置。
- cmd/sso.go 的 newAccountCORSMiddleware、canonicalRequestHost：Account auth Host 与登记 business Host 的策略。当前构造仍按请求选 CORS，保留现有语义；不能把 Origin header 反射为允许源。
- cmd/sso.go 的 buildProductionSSORuntime、productionAccountDomain、独立密钥校验与 Redis event sink：拥有身份协议与权威数据职责。
- services/devssoauthority：根据 Host/Service 取登记 ClientID，调用 ResolveApp 后检查 snapshot 的 Host/ClientID 和完整性，再查当前 membership。无效/过期/撤销转 ErrInvalidCredential；依赖异常转 ErrAuthBackendUnavailable；目录公司缺失/不可用转 ErrCompanyIdentityNotFound。Provider 保持现有 401/503/404 状态，不把数据库类型泄露到公共包。
- internal/mds/loginstatus.go：仍服务于 account.ListMyIdentities、account.SwitchIdentity、account.GetCurrentIdentity 三个 PRequireLogin/Bearer action，以及现有显式 callback。删除这些旧 API 是协议退役，需先查客户端调用和另列迁移，不属于此次等价 SDK 整理。
- devoauth、devwebsession、devauth、devcompany、devverification、devupstreamidentity、svrupstreamidentity：不因包含 auth/session 关键字就移进 jxpkg。

Account 当前只有 ACCOUNT_BUSINESS_HOST 选定的一个业务 API Host。注册多个
OIDC Client 不等于支持多个业务 API Host；本 PR 不宣称完成该能力。

## K3s 实查与变更要求

以下为 2026-09-11 10:54–10:58 CST 的历史只读 JX-LAN 快照，
用于说明既有设施匹配；不是本轮候选镜像的运行验收。发布前需重新核对：

- namespace jxone 中 account-api 和 juxonone-api 均 1/1 Ready。
- 正在运行的提交分别为 2fb5beb2735d、3a1d89ca672d，镜像带 digest。
- account-session-resolver 是 ClusterIP，8443 映射 Account resolver listener，有可用 EndpointSlice。
- 两个 API 分别通过 account-sso-runtime / juxonone-sso-runtime envFrom，挂载 account-resolver-mtls / juxonone-resolver-mtls。
- Ingress 保持业务 Host 的 /auth、/v1/account 到 Account，/v1/juxonone 到 Juxonone；resolver 无公网 Ingress。
- account-api-ingress 与 account-session-resolver-ingress 两条 NetworkPolicy 同时存在；实查后者允许 Traefik 到 8080、同 namespace 的 Juxonone 到 8443。不得凭名称直接删策略。
- Juxonone terminationGracePeriodSeconds 为 90，Account 为 30。
- 两个 Deployment 存在额外未挂载的 resolver Secret volume 条目；这次不依赖它们。若后续清理，先核对所有容器挂载引用。

SDK 保留全部八个 JUXONONE 环境键：BROWSER_ALLOWED_HOSTS_JSON、
BROWSER_SESSION_COOKIE、EXTERNAL_ORIGIN、SESSION_RESOLVER_ENDPOINT、
SESSION_RESOLVER_SERVICE、SESSION_RESOLVER_CA_FILE、SESSION_RESOLVER_TLS_CERT_FILE、
SESSION_RESOLVER_TLS_KEY_FILE。Provider 保留 ACCOUNT_SESSION_RESOLVER_ADDR、
CALLERS_JSON、TLS_CERT_FILE、TLS_KEY_FILE、CLIENT_CA_FILE。
没有新的 Secret、端口、Redis、数据库表、PVC、
Gateway、sidecar 或证书体系要求；现有证书和 caller 绑定继续使用。

发布清单必须更新：

1. test-api/account-api.yaml 与 test-api/juxonone-api.yaml 的 image 固定为验收过的各自提交及 digest。本地基线 e13ec3f 的清单仍引用旧 4b49efd / b857c6b，不能原样 apply。
2. test-api/juxonone-api.yaml 的 Deployment.spec.template.spec 显式保留 terminationGracePeriodSeconds: 90。省略会恢复默认 30 秒，短于程序的 60 秒 HTTP drain 和 75 秒退出预算。
3. 保留现有 envFrom、Secret 文件路径、8443 Service、Host 路由和网络策略；不需要改变工作负载权限。
4. 在 JX-LAN 当前清单仓库先核对 git status 和分支，再执行 make check、make diff；仅审核相应 Deployment diff，不能覆盖共享资源。按原发布 workflow 更新镜像，勿直接从本地旧清单全量部署。

上述 10:54 快照只证明既有设施存在；本轮后续部署证据如下，不再沿用旧镜像作为当前状态。

### 本轮 JX-LAN 部署与协议验证

构建源码固定为 JXpKG `c318a8267d4f`、Account `419726b7538d`、
JXOne `1d8212c03808c0e5506e958e2bee13e7df870ffe`。隔离临时构建使用 `replace => ./.local-jxpkg`，
指向上述精确 SDK 源码；Account、JXOne、Worker 三个镜像的 buildinfo 均核对通过。
这项 replace 只存在于临时构建目录，不提交到应用仓库，也不能描述为仅从
go.mod 版本下载得到的构建。下次重建必须再次核对本地替换目录的 SHA 与 buildinfo。

| 检查 | 本轮结果 |
|---|---|
| Redis + mTLS 服务链 | 全部场景 PASS，使用新 Consumer/Provider 与 Account Authority |
| 镜像 digest 前缀 | Account `9a48db624ee6…`；JXOne `ae3cb4a300cd…`；Worker `7583f663e557…` |
| namespace `jxone` rollout | 成功；Account/JXOne/Worker Ready 副本分别为 1/1/2 |
| Pods | 共 4 个，检查时均为 0 restart |
| K3s module smoke | 20/20 通过 |
| live resolver，合法客户端证书 + 无效 Session | HTTP 401 |
| live resolver，无客户端证书 | TLS 拒绝 |
| login bootstrap | HTTP 302 |
| 缺少必要输入的 callback | HTTP 400 |
| 使用用户凭据的真实浏览器登录/业务交互 | 未执行，不能用上述 302/400 代替 |

首次从宿主直连 ClusterIP 失败，原因是宿主不路由 Service CIDR；随后通过
port-forward 完成 live resolver 验证。这次失败不归类为应用故障，
port-forward 成功也不单独证明业务 Pod 到 Service 的网络策略路径。

回滚镜像记录位于 JX-LAN `/tmp/jx-sso-provider.NRhvCO/rollback-images.tsv`。
上表只保留 digest 前缀用于阅读，部署或回滚必须使用实际清单/记录中的完整镜像引用，
不能将省略的 digest 拼成部署值。回滚文件属于远端临时证据，应在清理临时目录前
归档到发布记录；本轮没有执行回滚。

## 测试与接手门禁

| 层次 | 本轮状态 | 证据范围 |
|---|---|---|
| SDK c318a826 | 本轮已通过 | 非缓存全仓 test、vet 和 `go test -race -count=1 ./...`；严格 JSON、authority 输出、真实 TLS1.3/caller、并发 Serve/Close、drain/强制关闭 |
| Account 419726b | 本地已通过 | 非缓存全仓 test/race、vet、go mod verify、构建；日志修复后 authority race/vet 再通过 |
| Account SIGTERM | 本地已通过 | 实际子进程信号触发 lifecycle.AddCloser/WaitExit；在途请求完成后退出；不是启动带真实 DB 的 Account 主程序 |
| Account Redis 服务链 | 本轮 JX-LAN 已通过 | 新 Consumer/Provider 与 Authority 全部场景 PASS，不引用旧 26 场景结果 |
| JXOne `1d8212c03808c0e5506e958e2bee13e7df870ffe` 镜像 | 本轮构建与 rollout 已通过 | 临时本地 SDK 替换构建；buildinfo 对齐，module smoke 通过；不据此新增全仓单测通过声明 |
| K3s 镜像与协议 | 本轮已通过 | 1/1/2 Ready、4 Pods 零重启、smoke 20/20、live mTLS 与 login/callback 状态检查 |
| 真实浏览器/OIDC/DB 产品交互 | 仍未完成 | 未使用用户凭据完成浏览器交互；协议探测不能证明完整用户流程 |

旧 JXOne 本机 Go 1.26.4 曾在 devcanvas/TestWorkshopNumbersRetainValidation
复现浮点边界失败，主干 3a1d89c 也有同样结果；须结合当前 runner 的 Go/CPU 和
精确 ref 重新判断，不得将历史失败或历史通过自动套用到本轮。

Account 端到端入口：

```bash
GOWORK=off go test -race -count=1 ./services/devssoauthority -run TestProviderSIGTERMLifecycle -v
# 先用 docker image inspect 核实并导出 SSO_SDK_TEST_REDIS_IMAGE。
GOWORK=off bash scripts/test-sso-sdk.sh
```

第二条命令从 Account 仓库执行，创建独立 loopback Redis 容器并在退出时清理。
目录/IdentityValidator 为隔离 fixture，Session 由 Account writer 种入。
此测试不验证真实 browser/OIDC/DB、不读取共享 Secret、不代替 K3s 产品验收。

接手 agent 执行顺序：

1. 读取三个 PR 当前 head，确认两应用 SDK 包含 c318a826；在独立 checkout 设置 GOWORK=off，保存完整 SHA、Go/CPU、模块版本、命令、退出码和日志路径。若复用本轮临时构建流程，单独记录 replace 目录的精确 SHA，不把其构建证据表述为无覆盖的依赖下载。
2. 合并发布 SDK 后将两应用依赖统一升级正式版本，执行 go mod tidy、go mod verify；仅 JXOne 执行 go mod vendor，Account 保持原模块布局。当前草稿允许固定官方 pseudo-version，不能依赖本地 workspace 才编译。
3. 各仓执行 AGENTS.md 要求的 gofmt、vet、全量测试、race、构建；保留已知失败与跳过记录。重点检查没有应用 AuthInject 的 Cookie 正向链路、重复/缺失 Cookie、Bearer 混用、Host/Origin/CSRF 拒绝、epoch/version/过期/撤销、resolver 超时 503。
4. 执行上面的 Account SIGTERM 与 Redis 服务链入口；复核 selected business Host、auth Host CORS、logout CORS、上游禁用/错误配置及 legacy Bearer 断言。纯协议/mTLS 恶意输入测试在 SDK 执行，不恢复已删除的 Account HTTP handler 测试副本。
5. 对比两仓变更前后路由 action 清单；只允许实现归属变化，不删除业务或 Worker action。
6. 受信 runner 构建不可变镜像；核对上述两处清单与 90 秒宽限期。无需 DB migration、Redis 数据迁移或密钥轮换。
7. 本轮 rollout、module smoke 与协议探测已完成；下一步补齐使用用户凭据的真实浏览器登录、项目权限 403、Account 公司操作、跨源拒绝、退出后失效及 Worker Bearer 隔离。核对 Cookie 和内存 CSRF，不将 302 bootstrap 等同登录成功；复查当时的 Ready 与完整 imageID digest。
8. 回滚只回滚到此次记录的已知旧镜像；因协议/配置/存储格式不变，不进行数据回滚。

## 整洁度审阅

Ponytail P-2：JXOne 私有 transport/options/CORS 与 SDK 重复，已删除。
Ponytail P-2：JXOne epoch 复制及 principal 校验已由 SDK 接管，删除应用 injector。
Ponytail P-1：Account 两个无调用方 helper 已删除。
Ponytail P-4：Account 测试工厂已移至 _test.go。
G-09b：newAccountRouter 同时用于生产和测试，负责安全校验与路由装配，不是逐字段转发。
G-09b：Authority 保留 Account 模型和领域错误，Provider 复用 auth 两个 resolver 接口，
不再定义另一套 SessionStore、HTTP DTO 或回调工厂。
G-21/G-23a：Account 内部失败记录安全阶段/错误类型；原始底层 error 不写入日志，
Resolve 转发目录已记录的错误时不重复日志。
不把项目 RBAC、Account 数据库复核或身份协议搬进公共库来追求表面行数。

提交邮箱：nokeruila@gmail.com。
