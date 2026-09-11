# SSO SDK 清理与跨仓交接

核对日期：2026-09-11。基线：JXOne `3a1d89c`、Account `2fb5beb`、SDK
PR #17 原 head `908a323`。默认浏览器身份注入在 SDK `84c7722` 补齐。
关联：https://github.com/JUXON-AI/jxpkg/issues/16 、https://github.com/JUXON-AI/jxpkg/pull/17 。

## 目标与已实现边界

业务应用只加载一次 SDK、挂载 RouterOptions、声明受保护方法。
JXOne 不再实现证书加载、resolver transport、Session/CSRF/CORS 构造、
LoginStatus 字段校验或 MembershipEpoch 复制。项目权限仍归 JXOne。
Account 通过同一个 BrowserSecurity 组件消费进程内 resolver，继续拥有密码、
OIDC、Session 写入/撤销和公司身份权威数据。

本次对仓库认证关键词和调用点做全局检索，并沿启动、路由、injector、resolver、
公司/项目权限和部署路径审阅。不是对全部业务代码逐行做安全审计。

## 公共接口与执行顺序

已有公共接口，无需再增加近义 wrapper：

```go
sso.LoadEnv(getenv func(string) string, prefix string) (*sso.Runtime, error)
(*sso.Runtime).Origin() string
(*sso.Runtime).RouterOptions() []server.RouterOption
(*sso.Runtime).CompanyIdentityResolver() auth.CompanyIdentityResolver
(*sso.Runtime).Close()
middleware.NewBrowserSecurity(middleware.BrowserSessionOptions) (*middleware.BrowserSecurity, error)
server.WithBrowserSecurity(*middleware.BrowserSecurity) server.RouterOption
```

浏览器路由顺序是 Session resolver、默认身份发布或显式 AuthInject、登录要求、
CSRF、业务 handler。默认路径校验 BrowserSession 模式及非零
UserID/UIN/CompanyID/MembershipEpoch，然后发布上下文。显式 callback 仍执行，
拒绝结果仍生效。Bearer 没有 callback 时仍拒绝，不能借此次重构放宽。
兼容入口 WithBrowserSession 保留，内部复用 BrowserSecurity。

## JXOne 文件与方法清单

分支 `cc/sso-sdk-cleanup`，工作目录 `jxone-sdk-cleanup`。

| 文件 | 实施动作 | 验收 |
|---|---|---|
| apps/juxonone/cmd/sso.go | 整删 127 行；删除 buildBrowserSessionOptions、newBrowserSessionCORS、newProductionResolverTransport 及三个 resolver timeout 常量 | 非测试应用源码不再直接创建 Session resolver transport/middleware |
| apps/juxonone/cmd/sso_test.go | 删除旧私有构造测试；协议行为由 SDK 与应用集成测试继续覆盖 | 不能只凭删除测试获得绿色结果 |
| apps/juxonone/internal/mds/loginstatus.go | 整删 InjectLoginStatus | SDK 自动发布 epoch，拒绝非法 principal |
| apps/juxonone/internal/mds/loginstatus_test.go | 删除迁走的重复测试 | SDK 增加默认 injector 正向、非法主体和 CSRF 回归 |
| apps/juxonone/internal/apis/api.go | 删除 mds import 和 AuthInject 注册 | 所有 PRequireBrowserSession 保留，Worker 路由保持独立 |
| apps/juxonone/cmd/main.go | LoadEnv 替代 transport/options/CORS 构造；defer Close；Origin 传给 initCollaboration；注入 CompanyIdentityResolver；展开 RouterOptions 并追加 graceful timeout | 启动错误脱敏；migration-only 仍先退出；初始化及资源关闭顺序保持 |
| apps/juxonone/session_resolve_integration_test.go | 删除应用 injector import/注册；保留真实解析客户端与身份上下文断言 | 无 injector 时 user_id/uin/company_id/epoch 正确；失败不进 handler |
| go.mod、go.sum、vendor | 固定官方 SDK commit 的 pseudo-version；使用 go mod vendor 生成 | 禁止个人 fork、手改 vendor、提交本地 replace/go.work |
| README.md、docs/sso/README.md | 指向此次 SDK 接入说明，旧 AuthInject 图示标明历史基线 | 新服务按文档不需要应用 injector |

最终接入片段：

```go
runtime, err := sso.LoadEnv(os.Getenv, "JUXONONE")
// 启动边界处理 err，失败时终止；随后 defer runtime.Close()。
devproject.ConfigureCompanyIdentityResolver(runtime.CompanyIdentityResolver())
// initCollaboration(ctx, runtime.Origin()) 继续使用同一权威 Origin。
router := server.NewRouter("/v1/",
    append(runtime.RouterOptions(), server.WithGracefulShutdownTimeout(httpDrainTimeout))...)
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
| cmd/main.go | 删除独立 CORS/router/可选 upstream 路由装配，调用 newAccountRouter | resolver listener、trusted proxies、defer upstream.Close 继续由启动层管理 |
| cmd/sso.go | newAccountRouter 统一 NewBrowserSecurity、CORS、WithBrowserSecurity 和 OAuth/upstream 路由注册 | 生产与测试调用同一组装函数，构造失败在监听前返回 |
| cmd/sso.go | 删除无调用方的 buildProductionSSOHandlers、buildProductionSSOHandler | 全仓搜索无引用；不新增别名或转发 wrapper |
| cmd/sso.go、cmd/sso_test.go | assembleAccountRouter 移入 _test.go，只构造测试依赖并调用生产 newAccountRouter | 不把测试依赖工厂编进生产 |
| internal/apis/api.go | 保留显式认证边界与 Account AuthInject | 三个旧身份接口仍需 Bearer 数据库复核 |
| go.mod、go.sum、vendor | 与 JXOne 固定同一官方 SDK commit | 发布后统一升级正式版本，不用浮动分支 |
| README.md | 说明公共 BrowserSecurity 与 Account 专属能力边界 | 不声称 SDK 取代完整 IdP |

必须保留的 Account 代码：

- services/svroauth/handler.go 的 BrowserSessionOptions：把选定的 ACCOUNT_BUSINESS_HOST、Client 注册表、SessionStore、公司目录适配为公共配置。
- cmd/sso.go 的 newAccountCORSMiddleware、canonicalRequestHost：Account auth Host 与登记 business Host 的策略。当前构造仍按请求选 CORS，保留现有语义；不能把 Origin header 反射为允许源。
- cmd/sso.go 的 buildProductionSSORuntime、productionAccountDomain、独立密钥校验与 Redis event sink：拥有身份协议与权威数据职责。
- cmd/session_resolver.go 的 handler/server/listener 构造：Account 是 mTLS 服务端，不能改成调用自身网络 SDK。
- services/svrsessionresolver 的 InProcessSessionResolver、membership 校验和 caller registry：业务请求得到经权威核验的 principal。
- internal/mds/loginstatus.go：仍服务于 account.ListMyIdentities、account.SwitchIdentity、account.GetCurrentIdentity 三个 PRequireLogin/Bearer action，以及现有显式 callback。删除这些旧 API 是协议退役，需先查客户端调用和另列迁移，不属于此次等价 SDK 整理。
- devoauth、devwebsession、devauth、devcompany、devverification、devupstreamidentity、svrupstreamidentity：不因包含 auth/session 关键字就移进 jxpkg。

Account 当前只有 ACCOUNT_BUSINESS_HOST 选定的一个业务 API Host。注册多个
OIDC Client 不等于支持多个业务 API Host；本 PR 不宣称完成该能力。

## K3s 实查与变更要求

2026-09-11 10:54–10:58 CST 只读查询 JX-LAN：

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
SESSION_RESOLVER_TLS_KEY_FILE。没有新的 Secret、端口、Redis、数据库表、PVC、
Gateway、sidecar 或证书体系要求；现有证书和 caller 绑定继续使用。

发布清单必须更新：

1. test-api/account-api.yaml 与 test-api/juxonone-api.yaml 的 image 固定为验收过的各自提交及 digest。本地基线 e13ec3f 的清单仍引用旧 4b49efd / b857c6b，不能原样 apply。
2. test-api/juxonone-api.yaml 的 Deployment.spec.template.spec 显式保留 terminationGracePeriodSeconds: 90。省略会恢复默认 30 秒，短于程序的 60 秒 HTTP drain 和 75 秒退出预算。
3. 保留现有 envFrom、Secret 文件路径、8443 Service、Host 路由和网络策略；不需要改变工作负载权限。
4. 在 JX-LAN 当前清单仓库先核对 git status 和分支，再执行 make check、make diff；仅审核相应 Deployment diff，不能覆盖共享资源。按原发布 workflow 更新镜像，勿直接从本地旧清单全量部署。

此处验证的是资源存在和配置对齐；没有用新镜像部署，也没有执行真实浏览器登录或故障注入。

## 测试与接手门禁

已执行：SDK 全量单测、vet、模块校验、vendor 包列表、构建；SDK auth/middleware/server/sso race。
JXOne 删除 injector 后垂直 Session flow、API、Worker middleware、devproject 的单测与 race 通过；
JXOne vet 和 Juxonone 构建通过。Account cmd/internal/resolver 测试通过，cmd/resolver race、vet、构建通过。

已知失败：JXOne devcanvas/TestWorkshopNumbersRetainValidation 在本机 Go 1.26.4
接受浮点值 9.223372036854776e+18；未改主干 3a1d89c、GOWORK=off 也能复现。
不能据此声称 JXOne 全量测试通过。需在 JX-LAN 受信 CI 复核目标 Go/CPU 环境并单独跟踪。

接手 agent 执行顺序：

1. 读取三个 PR 当前 head，确认 JXOne/Account 固定的 SDK 版本包含 84c7722。
2. 合并发布 SDK 后将两应用依赖统一升级正式版本，go mod tidy、go mod vendor、go mod verify。当前草稿允许固定官方 pseudo-version，不能依赖本地 workspace 才编译。
3. 各仓执行 AGENTS.md 要求的 gofmt、vet、全量测试、race、构建；保留已知失败与跳过记录。重点检查没有应用 AuthInject 的 Cookie 正向链路、重复/缺失 Cookie、Bearer 混用、Host/Origin/CSRF 拒绝、epoch/version/过期/撤销、resolver 超时 503。
4. Account 额外执行 selected business Host、auth Host CORS、logout CORS、上游禁用/错误配置、mTLS caller 身份和 CompanyIdentityDirectory 故障测试；保留旧 Bearer 身份协议断言。
5. 对比两仓变更前后路由 action 清单；只允许实现归属变化，不删除业务或 Worker action。
6. 受信 runner 构建不可变镜像；核对上述两处清单与 90 秒宽限期。无需 DB migration、Redis 数据迁移或密钥轮换。
7. 部署后逐项验证无登录请求、登录成功、项目权限 403、Account 公司操作、跨源拒绝、退出后失效及 Worker Bearer 隔离；真实浏览器验证 Cookie 和内存 CSRF，再确认 Ready 与 imageID digest。
8. 回滚只回滚到此次记录的已知旧镜像；因协议/配置/存储格式不变，不进行数据回滚。

## 整洁度审阅

Ponytail P-2：JXOne 私有 transport/options/CORS 与 SDK 重复，已删除。
Ponytail P-2：JXOne epoch 复制及 principal 校验已由 SDK 接管，删除应用 injector。
Ponytail P-1：Account 两个无调用方 helper 已删除。
Ponytail P-4：Account 测试工厂已移至 _test.go。
G-09b：newAccountRouter 同时用于生产和测试，负责安全校验与路由装配，不是逐字段转发。
不把项目 RBAC、Account 数据库复核或身份协议搬进公共库来追求表面行数。

提交邮箱：nokeruila@gmail.com。
