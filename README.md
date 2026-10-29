# jxpkg

新增 `credits` 服务端协议客户端：业务读取自己的配置并显式传给 `NewClient(Config)`，SDK 不读取 coresetting 或应用环境。`Client.AcquireDefault(ctx, Subject)` 获取员工 default Key 和 New API 地址；需要在一次执行内复用时创建 `NewExecution(subject, client.AcquireDefault)`，再调用 `execution.AcquireDefault(ctx)`，或通过 `WithExecution` / `ConnectionFromContext` 传递给下游。SDK 自建 mTLS 连接池；Client 没有全局员工 Key 缓存，Execution 只保留本次执行的结果（包括失败），不隐式重试、不跟随重定向。Subject 必须来自已验证登录或权威任务归属。HTTP 应用可在 Browser Session 校验后使用 `middleware.BindCreditsExecution(client)`，SDK 不决定业务资源权限。下游接入时需升级包含这些能力的发布版本并重新生成 vendor。

`jxpkg` 是 JUXON Go 服务共用的基础库，覆盖 HTTP API、认证、配置、数据库、Redis、日志、对象存储、任务、邮件、验证码和模型客户端。它只提供可复用能力，不承载 Account、JXONE 等具体业务的数据模型或业务流程。

## 快速开始

```bash
go get github.com/JUXON-AI/jxpkg@latest
```

要求 Go 1.25 或更高版本。`@latest` 会解析为最新正式 tag；生产仓库应将解析后的明确版本提交到 `go.mod`。跨仓库联调可以临时使用 commit，但不得把个人 fork 的 `replace` 提交到仓库。

```go
import "github.com/JUXON-AI/jxpkg/logs"

func main() {
    logs.Infow("service started", "component", "example")
}
```

## 开发检查

`jxpkg` 是库而不是可启动服务，因此不提供虚假的 `dev` 或容器镜像 target。Makefile
只暴露可重复执行且与 CI 相同的检查：

```bash
make check       # gofmt、vet、module/vendor 完整性
make test        # 单元与集成测试
make test-race   # race detector
make build       # 编译全部 package 与 test binary，不执行测试
make clean       # 清理 Go test cache
```

需要 Redis 的测试通过 `JXPKG_TEST_REDIS_ADDR` 指向专用测试实例；不得连接生产或共享
业务 Redis。GitHub Actions 会为两条 CI 路径提供隔离的 Redis service。

## 包索引

| 包 | 用途 | 主要入口 |
| --- | --- | --- |
| [`apis/apiobj`](#apisapiobj) | 通用分页、筛选和详情请求/响应 DTO | `PageQuery`、`QueryRequest`、`QueryResponse` |
| [`apis/constants`](#apisconstants) | Gin Context 的稳定请求键名 | `CtxKeyRequestID`、`CtxKeyCode` |
| [`apis/errcode`](#apiserrcode) | 业务错误码注册和消息查询 | `Register`、`GetMessage` |
| [`apis/runtime`](#apisruntime) | HTTP 响应和请求元数据 helper | `Success`、`BadRequest`、`RequestID` |
| [`apis/runtime/logtobff`](#apisruntimelogtobff) | Logto Browser BFF、主体发布和 CSRF 边界 | `New`、`Runtime.Require`、`FromContext` |
| [`apis/runtime/logtodirectory`](#apisruntimelogtodirectory) | 固定用途 Logto workload-directory M2M 客户端 | `NewClient`、`Snapshot`、`ListPage`、`SearchOrganizations` |
| [`apis/runtime/auth`](#apisruntimeauth) | 通用权限错误、权限编码和严格 EdDSA 验签 | `PermissionCode`、`NewTokenVerifier` |
| [`apis/runtime/middleware`](#apisruntimemiddleware) | Gin 日志、恢复、CORS 与 Credits 执行绑定 | `NewCORS`、`BindCreditsExecution` |
| [`apis/runtime/server`](#apisruntimeserver) | Gin Router、DTO 适配和显式 handler 组合 | `NewRouter`、`Post`、`API` |
| [`identity`](#identity) | 原生组织和用户身份及授权上下文 | `Member`、`Authorization`、`WithAuthorization` |
| [`config`](#config) | YAML 和环境变量配置加载 | `LoadCoreConfigFromEnv` |
| [`dbtools`](#dbtools) | GORM 多数据库连接和显式迁移 | `InitDBConn`、`DoInitModels` |
| [`dbtools/redispool`](#dbtoolsredispool) | Redis 连接及常用数据结构操作 | `InitRedisWithConfig`、`Redis` |
| [`lifecycle`](#lifecycle) | 服务启动、停止及清理回调协调 | `New`、`Std` |
| [`llm`](#llm) | OpenAI-compatible 客户端构造 | `NewOpenAIClient` |
| [`logs`](#logs) | Zap 结构化日志和 GORM logger | `ReloadConfig`、`Get`、`GetGorm` |
| [`mail`](#mail) | SMTP 邮件发送 | `NewSMTPSender`、`Sender` |
| [`mutex`](#mutex) | Redis 分布式锁和主节点选举 | `NewRedisLocker`、`NewClusterMutex` |
| [`random`](#random) | 非安全用途随机字符串和数字 | `String`、`Alphanum`、`Int` |
| [`settings`](#settings) | 数据库存储的分组配置项 | `GetValue`、`Set`、`InitDB` |
| [`storage`](#storage) | S3-compatible 对象存储和文件元数据 | `NewS3Fs`、`LoadStorager` |
| [`task`](#task) | 数据库/Redis 支撑的异步任务与 worker API | `CreateTask`、`RegisterCallBack` |
| [`verification`](#verification) | 一次性验证码的发送、即时消费和可回滚事务领取 | `NewService`、`NewRedisStore`、`VerifyAndClaim` |

## 包使用说明

### `apis/apiobj`

统一列表接口的分页、排序和筛选结构。`PageQuery` 表示分页条件，`Filter` 表示字段过滤，`QueryRequest`/`QueryResponse` 用于标准列表请求和响应。业务 DTO 可以嵌入这些结构，但不要在这里增加业务字段。

```go
type ListUsersRequest struct {
    apiobj.QueryRequest
}
```

调用方仍需自行设置最大分页大小、可排序字段白名单和过滤权限；该包不会生成 SQL。

### `apis/constants`

集中声明 middleware 与 handler 之间传递请求 ID、日志器和响应码时使用的 Gin Context key。身份与授权数据由 `logtobff` 或 `identity` 的显式 context API 承载。

### `apis/errcode`

维护进程内的业务错误码到用户消息映射。使用 `Register` 注册服务自己的错误码，`GetMessage` 获取文案。错误码是业务协议的一部分，注册应集中、确定且有测试，不要用它替代 Go `error` 的因果链。

### `apis/runtime`

提供标准 JSON 响应、请求 ID、环境和客户端地址 helper。

```go
func GetProfile(ctx *gin.Context) {
    requestID := runtime.RequestID(ctx)
    if requestID == "" {
        runtime.BadRequest(ctx, "missing request id")
        return
    }
    runtime.Success(ctx, gin.H{"request_id": requestID})
}
```

这些 helper 不解析身份；认证必须由路由上显式安装的 handler 完成。

### `apis/runtime/logtodirectory`

提供 JXX 原生目录适配和 JXONE 有界成员列举共用的固定 Logto workload-directory M2M 客户端。应用必须显式读取自己的启动配置并传给 `NewClient(Config)`；SDK 不读取环境、数据库或 coresetting，导入和构造不执行网络、迁移或其他初始化副作用。`Endpoint` 只接受精确 HTTPS origin，客户端只派生 `/oidc/token`、`/api/workload-directory/snapshot` 和 `/api/workload-directory/organizations`，不接受任意 URL、scope、token 转发或 Management API 请求。`NewClientWithTransport` 只用于启动期注入可信 transport；默认 `NewClient` 不继承系统 proxy。

```go
client, err := logtodirectory.NewClient(logtodirectory.Config{
    Endpoint:     logtoEndpoint,
    ClientID:     workloadClientID,
    ClientSecret: workloadClientSecret,
    Resource:     directoryResource,
})
if err != nil {
    return err
}
snapshot, err := client.Snapshot(ctx, organizationID, userIDs, logtodirectory.Options{
    IncludeDepartments: true,
})
```

`Snapshot` 不缓存成员、角色、资料或部门，只缓存有界 M2M access token；默认超时 10 秒，显式范围 1..30 秒。同一 client 的冷 token 刷新会合并等待者，目录数据请求仍可并行；现有 request ID 会透传到 token 和每个目录请求。`Options.IncludeMembershipEpoch` 要求每个成员返回 canonical 正整数 decimal string，SDK 不把 epoch 解码为浮点数。错误通过 `ErrDenied`、`ErrUnavailable`、`ErrProtocol` 分类；固定目录 403 仅在严格精确的 `organization_access_denied` JSON 下返回包装 `ErrDenied` 的 `ErrOrganizationDenied`。调用方仍可用 `errors.Is` 检查 context cancellation。响应正文、token、Client Secret 和配置不会被写入错误。

`ListPage` 使用同一 snapshot path 的单页列出契约；SDK 与配套 Logto handler 已通过本地 HTTPS、数据库联合测试及独立复审。使用前仍须部署配套 provider，并在 provider registry 为该 workload 显式启用 `allowMemberListing`；省略时禁止列出。SDK 不提供 capability 覆盖或跨页聚合，调用方须自行设置完整性、人数、页数和总时限。

`SearchOrganizations` 使用固定的 organizations path，查询上限 128 runes、页大小 1..100、组织 ID/cursor 上限 21 runes；结果保持 provider 的 ID 顺序并要求唯一。该页的结束游标按 provider 契约可省略并返回 `nil`，不能复用 `ListPage` 的必需 JSON `null` 规则。`Close` 只转发 idle connection 回收，不取消 in-flight 请求。

### `identity`

`identity.Member` 仅使用原生 `organization_id` 与 `user_id` 字符串。`identity.Authorization` 在同一权威目录快照内绑定成员、组织 Owner 标记、原生部门祖先链和显式权限；`Allows` 不根据 Owner、部门或客户端输入推断权限。

`WithAuthorization` 与 `AuthorizationFromContext` 深复制切片并拒绝无效授权。业务服务只读取这个 context，不把请求体或旧数值身份投影升级为授权事实。

### `apis/runtime/logtobff`

`logtobff.Runtime` 拥有 Logto Browser BFF、Host-only Session Cookie、Origin/CSRF 校验、主体重验证和登出。应用把 `Handler()` 挂到 `/auth/*path`，并在每条受保护业务路由上显式安装 `Require()`：

```go
bff, err := logtobff.New(ctx, config)
if err != nil {
    return err
}
router := server.NewRouter("/v1/")
router.GinEngine().Any("/auth/*path", gin.WrapH(bff.Handler()))
router.Post("profile.Get", bff.Require(), server.API(handler.GetProfile))
```

`Require` 成功后，`FromContext` 返回已认证成员的原生 `Principal` 和有效标志。应用须通过在线权威目录校验该成员，自行组合 `identity.Authorization` 并通过 `identity.WithAuthorization` 写入请求上下文。副作用请求必须由 BFF 完成 CSRF 校验；调用方不得恢复 Cookie 与 Bearer 间的静默回退。

纯身份模式（`APIResource` 为空）把资料展示绑定到每次必做的在线组织身份检查：BFF 仅在该检查中请求受限的 `user` 投影，并在发布前校验其 subject 与已验证 Token 一致且资料字段有界。该模式不读取分钟级 UserInfo 资料缓存，也不会在投影缺失或畸形时回退到 UserInfo；资源 Token 模式继续使用既有 UserInfo 与组织权限流程。

退出时，中央端点明确返回 401 会按本地会话失效处理，BFF 返回 `401 session_invalid`，清理被拒绝的旧本地会话；这不表示新 SSO 会话已被退出，也不会重试中央退出动作。超时、5xx、未知状态或响应关闭异常仍返回 503 并保留恢复状态；旧请求不能清除已更新的会话状态。

### `apis/runtime/auth`

认证包提供业务服务共享的 `PermissionCode`、稳定认证错误和严格 EdDSA/JWK 验签原语。它不再提供 Account numeric Session Resolver、UIN/CompanyID 授权上下文或旧 HS256 Bearer API。

```go
signer, publicKey, err := auth.GenerateTokenSigner("2026-09")
if err != nil {
    return err
}
verifier, err := auth.NewTokenVerifier([]auth.VerificationKey{publicKey})
if err != nil {
    return err
}

claims := &auth.UserClaims{
    RegisteredClaims: jwt.RegisteredClaims{
        Issuer:    "https://issuer.example.com",
        Subject:   "user-42",
        Audience:  jwt.ClaimStrings{"orders-api"},
        IssuedAt:  jwt.NewNumericDate(now),
        ExpiresAt: jwt.NewNumericDate(now.Add(15 * time.Minute)),
        ID:        "unique-token-id",
    },
}
raw, keyID, err := signer.Sign(ctx, claims)
verified, err := verifier.Verify(ctx, raw, "https://issuer.example.com", "orders-api")
```

验证器固定要求 `typ=JWT`、已知且非空的 `kid`、`alg=EdDSA`，并校验 `iss`、`aud`、`sub`、`iat`、可选 `nbf`、`exp` 和 `jti`。多受众 token 还必须提供与预期受众相等的 `azp`。JOSE header 和 claims 使用有大小/深度限制且拒绝重复字段的严格 JSON 解析。

`Ed25519TokenVerifier.JWKS`/`PublicJWKS` 只输出公开密钥材料，claims 不携带旧 numeric UIN/CompanyID 或短字段兼容投影。

### `apis/runtime/middleware`

提供请求日志、panic 恢复、自定义 header、严格 CORS 和 Credits 执行绑定。Browser Cookie、注册、登录、登出和 CSRF 边界属于 `logtobff`；共享 middleware 不解析旧 Bearer 或 Account Session。

`NewCORS` 只接受精确 HTTP(S) origin，不接受通配符、域名后缀、路径或动态反射。CORS 决定浏览器能否读取响应，不是 CSRF 防护。位于可信反向代理之后时，CORS 与 Browser Session 必须配置同一个 `ExternalOrigin`；两者都不会信任客户端提供的 `X-Forwarded-Host`/`X-Forwarded-Proto`。

```go
externalOrigin := "https://api.example.com"
corsMiddleware, err := middleware.NewCORS(middleware.CORSOptions{
    AllowedOrigins: []string{"https://app.example.com"},
    ExternalOrigin: externalOrigin,
})
```

`CORS()` 是 Router 使用的安全默认入口；需要额外 Origin allowlist 时应优先使用显式构造器并处理配置错误。

### `apis/runtime/server`

`Router` 在 Gin 之上统一 API prefix、DTO 适配和 handler 组合。`Post`、`G` 本身不解析认证凭据；受保护业务必须像上面的 `bff.Require()` 示例一样显式安装当前产品自己的登录与 CSRF handler。Router 不提供隐式 Account 认证，也不会在 handler 失败后回退到其他身份模式。`API` 支持请求体大小限制。

应用创建 listener 后调用 `Run`，再交给同一个进程级 lifecycle 等待退出信号：

```go
listener, err := net.Listen("tcp", cfg.HTTPAddr)
if err != nil {
    return err
}
if err := router.Run(listener); err != nil {
    return err
}
lifecycle.Std().WaitExit()
```

`Run` 会把 Router 注册为 lifecycle closer。收到 SIGTERM 或中断信号时，HTTP server
立即停止接收新连接，并默认最多等待 10 秒让进行中的 handler 完成；这用于避免滚动发布
把请求截断成 `EOF`。如果 handler（例如 Worker 长轮询）的最长执行时间可能超过 10 秒，
创建 Router 时必须传入 `WithGracefulShutdownTimeout`，同时让 lifecycle hard timeout 和
容器编排器 termination grace 依次更长，并在入口摘流后再发送 SIGTERM：

```go
lifecycle.Std().SetTimeout(75 * time.Second)
router := server.NewRouter("/v1/",
    server.WithGracefulShutdownTimeout(60*time.Second),
)
```

应用不要再独立关闭同一个 listener；需要在测试或自定义生命周期中主动停止时可调用
`router.Close()`，重复调用 `Run` 会返回错误。非正数 timeout 保留 10 秒默认值。

### `config`

加载核心 YAML 配置。通常使用 `LoadCoreConfigFromEnv` 读取环境指定配置，或在工具/测试中显式使用 `LoadCoreConfigFromFile`。`Conf` 返回当前已加载核心配置。不要把 secret 写入仓库 YAML；由部署环境注入。

### `dbtools`

管理命名 GORM 连接。`InitDBConn` 初始化单个连接，`InitMutilDBConn` 初始化多个连接，`DB(name)` 读取命名连接，`Core`/`Account`/`Jxone` 是约定名称的快捷入口。

连接池可按数据库名通过环境变量配置。例如 `account` 使用
`JX_DB_ACCOUNT_MAX_OPEN_CONNS=16`、`JX_DB_ACCOUNT_MAX_IDLE_CONNS=8`、
`JX_DB_ACCOUNT_CONN_MAX_IDLE_TIME=10m`、`JX_DB_ACCOUNT_CONN_MAX_LIFETIME=30m`。
数据库名转换为大写，连字符转换为下划线；空名称使用 `DEFAULT`。
未配置时保持标准库默认值：打开连接不限、最多保留两个空闲连接、无空闲和寿命期限。
显式 `0` 分别表示不限打开连接、不保留空闲连接或关闭相应期限。
配置错误或空闲上限超过非零打开上限时，初始化失败。启动日志仅记录数据库名和池参数。
按实例核算所有服务和副本的连接总额；不要对每个低频数据库套用繁忙数据库的参数。

迁移必须由应用显式调用 `InitModel`/`DoInitModels`；导入包不会自动迁移。应用应在启动时校验连接和 migration 版本，并在部署流程中记录执行结果。

### `dbtools/redispool`

包装 go-redis 客户端和常见 String、JSON、List、Sorted Set、锁操作。优先通过 `InitRedisWithConfig` 注入显式配置，随后使用 `Redis()`/`Std()` 取得客户端。涉及多个 key 的一致性或复杂原子操作时，应使用 Redis transaction/Lua，而不是组合这些便捷函数假设原子性。

### `lifecycle`

协调服务生命周期和清理回调。独立服务建议持有自己的 `LifeCycle`；`Std` 是进程级兼容单例。资源应在启动成功后注册对应关闭动作，并让主进程等待统一退出信号。

### `llm`

根据 `LLMConfig` 创建 OpenAI-compatible 客户端。调用方负责提供超时、代理和 TLS 策略明确的 `http.Client`；不要依赖无界默认超时。模型名、base URL 和 API key 由应用配置。

### `logs`

提供 Zap 结构化日志、命名 logger、context 字段和 GORM logger。应用启动时调用 `ReloadConfig`，退出时调用 `Close`；需要落盘或测试读取时可调用 `Sync`。

```go
if err := logs.ReloadConfig("jxone", cfg.Logs); err != nil {
    return err
}
defer logs.Close()
logs.Infow("request complete", "request_id", requestID)
```

敏感 cookie、token、验证码和密码不得作为结构化字段记录。

### `mail`

`NewSMTPSender` 校验 SMTP host、端口、认证与加密方式并返回 `Sender`。支持明文（仅可信测试网络）、STARTTLS 和 TLS；生产环境应要求加密连接。`Message` 描述收件人、主题和正文。调用方负责限流、重试策略及避免在日志中泄露正文/验证码。

### `mutex`

`RedisLocker` 提供单锁，`ClusterMutex` 用于带节点身份的集群协调，`IsMaster` 是主节点选举兼容入口。锁必须设置有限 TTL；业务操作需要设计为幂等，因为网络分区或超时后不能仅凭客户端状态证明仍持有锁。

### `random`

生成一般测试数据、标识片段和非安全随机值。该包不是密码学随机源，不能生成 session、token、验证码、重置链接或密钥；安全值应使用 `crypto/rand`。

### `settings`

在 `core_settings` 表中读写按 group/key 分组的文本、JSON 和 YAML 配置。使用前由应用显式调用 `InitDB`。secret 不应存入普通 settings；配置变更需要业务层权限与审计。

### `storage`

提供 S3-compatible `Storager`、`S3Fs` 和 `core_upload_files` 元数据。`NewS3Fs` 构造明确配置的实例；`LoadStorager`/`NewStorage` 使用 settings 中的 purpose 配置。使用文件模型前显式调用 `InitDB`。`S3Fs` 同时实现可选的 `MultipartStorager`，提供创建会话、签发分片 PUT URL、列出分片、完成合并和中止上传；业务可通过类型断言启用大文件直传，而无需改变已有 `Storager` 实现。

浏览器分片直传时，对象存储 CORS 必须允许前端 Origin 的 `PUT`，并在 `ExposeHeaders` 中暴露 `ETag`；否则浏览器即使上传成功，也无法取得完成合并所需的分片标签。

`S3Fs` 还实现可选的 `OriginalFileStorager`。`S3StorageConfig.OriginalImageCI` 默认 false；只有显式开启后，原图签名和读取才使用 COS 的 `ci-process=originImage`。该操作可能计费，且不适用于 MinIO/普通 S3；业务需要原字节契约时应先检查 `OriginalFileSupported`，开启后读取失败不得回退普通对象。原图 URL 由 `s3.NewPresignClient.PresignGetObject` 生成，查询通过 SDK build middleware 在签名前加入，以保留 SDK 的对象 key 编码、UNSIGNED-PAYLOAD 和过期语义。

对象 key 生成、内容 hash 与数据库元数据不能代替上传权限、内容类型校验、病毒扫描或下载授权，这些由业务服务负责。

### `task`

提供数据库任务记录、Redis Stream/队列、worker 健康检查和 callback 注册。典型流程是应用显式 `InitDB`、注册每种 task type 的 callback，再启动任务协调逻辑。

从 v0.0.24 开始，`RegisterWorkerRoutes` 必须显式传入 `WorkerCaller`：受信客户端证书唯一 URI SAN 与固定 taskType 一一绑定，Token 是第二层校验，拒绝 Cookie。应用使用 `NewWorkerServer(WorkerServerConfig, service, taskType, WorkerConfig, credits.AcquireFunc)` 启动独立 TLS 1.3 双向认证入口，显式调用 `Serve`，退出时 `Close`。Worker 使用 `NewWorkerHTTPClient(credits.TLSConfig, timeout)`；该客户端拒绝明文 HTTP 和重定向，调用方关闭空闲连接。SDK 不读取 settings、环境或 Account。旧的 v0.0.23 调用须补齐证书与 caller 配置后升级，否则注册失败关闭访问；原有其他手工注册路由不受影响。

模型主体来自权威任务行，领取前后校验当前 worker/attempt/running/截止时间；应用在领取回调中决定员工是否仍有效。没有模型调用的回调不触发凭证领取。Token 在注册时固定，更新后需重启应用。JXX 的 jxagent 和 jxmemory 是两个实际接入方，下游需升级发布版本并重新生成 vendor。`requestid` 为标准 Context 与 Gin 传播同一个安全请求 ID，额度客户端携带 `X-Request-Id`，不为每一跳重新生成。

历史 API 中保留了若干拼写兼容入口（例如 `ChackWockerHealth`）；新代码不要复制这些命名。任务 callback 必须幂等，并明确处理超时、重试和重复投递。

领取响应的 `attempt` 是本次执行的正数序号（`Redo + 1`）。Worker 必须在 callback 中原样回传，且只能回传 `success`/`fail`；缺少序号的旧请求被拒绝，不保留旧协议回退。同一 Worker 重领后的旧序号不会进入业务 callback，抢占与结果写入都核验领取时的 Redo。此协议要求 API 和 Worker 同时更新，无数据库结构迁移。

服务端会在执行应用 callback 前，将当前 worker 的 `running` 领取原子改为 `completing`，同一领取的重复回调不会再次进入应用 callback。若服务在 callback 中途退出，结果可能无法确认；超过一小时的 `completing` 任务会标记为 `fail`、耗尽自动重试，并记录 `task_callback_outcome_unknown`，需要按业务侧记录人工核对。这个状态不能用自动重试代替幂等处理。

### `verification`

一次性验证码的通用领域服务。`Store` 管理验证码状态，`Deliverer` 负责邮件等通道，`Policy` 定义长度、有效期、发送冷却和尝试次数；`RedisStore` 是共享环境实现。

没有后续事务的操作可以使用 `VerifyAndConsume` 立即消费。注册等还需要提交数据库事务的流程应使用两阶段领取，避免验证码正确但业务事务失败后无法重试：

```go
claim, err := service.VerifyAndClaim(ctx, verification.VerifyInput{
    Purpose:     "account.registration",
    Channel:     verification.ChannelEmail,
    Destination: email,
    Code:        code,
})
if err != nil {
    return err
}

if err := createAccountTransaction(ctx); err != nil {
    _ = service.ReleaseClaim(ctx, claim)
    return err
}
// 数据库已经提交，因此验证码清理失败不得把已创建账号伪装成注册失败；
// 调用方应记录不含目标地址、验证码和领取凭据的运维告警。
_ = service.ConsumeClaim(ctx, claim)
```

`VerifyAndClaim` 会原子校验并独占挑战，同时保留原来的 TTL、错误次数和验证码；其他即时消费或领取请求会被拒绝。`ConsumeClaim` 只允许匹配的不透明领取凭据删除挑战，`ReleaseClaim` 只移除领取状态并保留剩余 TTL。`Claim` 不公开内部凭据或验证码，不能由业务代码构造。

业务方必须为 `Purpose`、目标地址和验证上下文建立绑定，不能把“验证码数字相同”当作跨邮箱、跨用途或跨流程有效。验证码、存储 key 和完整目标地址不得写日志。

## 本地开发

`jxpkg` 是库，不启动常驻服务，也不构建容器镜像。

```bash
make build
go test ./...
go test -race ./...
go vet ./...
```

`make build` 仅做全包编译验证。格式、测试、race、vet 和依赖校验由 GitHub Actions 执行，避免 Makefile 中存在本地开发不会使用的伪 target。

默认单元测试不连接外部资源。集成测试按需设置：

```text
JXPKG_TEST_DB_CORE
JXPKG_TEST_DB_ACCOUNT
JXPKG_TEST_DB_JXONE
JXPKG_TEST_S3_ENDPOINT
JXPKG_TEST_S3_ACCESS_KEY
JXPKG_TEST_S3_SECRET_KEY
JXPKG_TEST_S3_BUCKET
JXPKG_TEST_S3_REGION
```

测试数据库和 bucket 必须是隔离资源，不得指向生产环境。

## CI 与发布

- feature branch push 与 pull request：无论来自同仓库还是 fork，都在 GitHub-hosted
  runner 执行编译、格式、vet、单元测试、race 和 vendor 一致性检查；PR 控制的代码不会
  进入 JXlan。同仓库同一分支的 push/PR 事件共用并发键，只保留一个全量 run；fork 的
  仓库名参与并发键，不会与同名内部 branch 相互取消。
- `main`：合并或直接 push 后重新执行完整检查。是否强制 `Required` check 由
  GitHub branch rules 管理，workflow 本身不能替代该仓库设置；受信执行使用
  `JXlan Trusted` self-hosted runner。
- `v*` tag：在 JXlan 重新执行与 `main` 相同的完整检查，发布 tag 未通过不能作为
  下游升级证据。
- manual：`workflow_dispatch` 可在 GitHub UI 选择或输入指定 ref 验证。

正式发布必须在 `main` 绿灯后创建语义化 tag。下游升级到新 tag 并完成兼容性测试后，才能删除临时 commit pin。

## 开发约束

- 公共包只保留至少两个实际消费者需要的稳定能力；Account/JXONE 业务模型归属业务仓库。
- 不提交个人 fork `replace`、本地凭证、生成日志、IDE 缓存或临时修复脚本。
- 导出 API 需要完整注释、测试和兼容性说明；破坏性变更必须通过新主版本发布。
- 数据库迁移和外部资源初始化均由应用显式触发，禁止 import side effect。

`safeerror.Wrap(message, cause)` 给内部 I/O 错误保留 errors.Is/As 分类，外层 Error() 只返回调用方提供的固定安全文本，原因为 nil 时返回 nil。credits 与 dbtools 是两个实际消费者；业务身份/启动边界也可直接复用。message 不得来自配置、凭证或上游响应，日志只输出外层错误。需要同时保留业务 sentinel 时把 errors.Join(sentinel,cause) 放在 Wrap 内，不直接返回 Join。

## 员工余额查询

`credits.Client.GetBalance(ctx, credits.Subject{OrganizationID: organizationID, UserID: userID})` 复用当前 mTLS 客户端，通过 `/internal/credits/balance` 查询原始 wallet。`credits.Subject` 不接受旧数字公司/UIN 回退，必须同时提供已验证的 Logto 组织与用户主体。`credits.Balance` 包含 state、quota、used_quota，不领取 default Key、不保存额度或扣费；缺失、重复或畸形响应失败关闭，pending 不代表零余额。本分支已定义新的字符串主体协议；额度服务的工作负载入口和 JXX 调用方仍须随迁移升级，旧数字接口不能直接互通。

业务浏览器接口使用 `apis/credits.RegisterBrowserBalance(router, "jxagent", client, bff)` 注册 `jxagent.GetMyModelBalance`。它复用已校验的 Logto Browser Session、当前组织与 CSRF，员工身份只来自当前验证结果；DTO/handler/安全错误映射由 SDK 提供，业务无需转发包装。响应保留原始单位并回传 `organization_id/user_id`，浏览器须核对主体，避免其他标签页切换身份后的迟到响应污染旧缓存。调用方后端显式传 Client 与 BFF，SDK 不读取环境或 coresetting，也不增加 Bearer fallback。
