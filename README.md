# jxpkg

`jxpkg` 是 JUXON Go 服务共用的基础库，覆盖 HTTP API、认证、配置、数据库、Redis、日志、对象存储、任务、邮件、验证码和模型客户端。它只提供可复用能力，不承载 Account、JXONE 等具体业务的数据模型或业务流程。

## 快速开始

```bash
go get github.com/JUXON-AI/jxpkg@v0.0.7
```

要求 Go 1.25 或更高版本。生产代码应依赖正式 tag；跨仓库联调可以临时使用 commit，但不得把个人 fork 的 `replace` 提交到仓库。

```go
import "github.com/JUXON-AI/jxpkg/logs"

func main() {
    logs.Infow("service started", "component", "example")
}
```

## 包索引

| 包 | 用途 | 主要入口 |
| --- | --- | --- |
| [`apis/apiobj`](#apisapiobj) | 通用分页、筛选和详情请求/响应 DTO | `PageQuery`、`QueryRequest`、`QueryResponse` |
| [`apis/constants`](#apisconstants) | Gin Context 的稳定键名 | `CtxKeyRequestID`、`CtxKeyUserID` |
| [`apis/errcode`](#apiserrcode) | 业务错误码注册和消息查询 | `Register`、`GetMessage` |
| [`apis/runtime`](#apisruntime) | HTTP 响应与已验证身份读取 | `Success`、`BadRequest`、`UserID` |
| [`apis/runtime/auth`](#apisruntimeauth) | Bearer/JWT、Browser Session 的共享认证契约 | `TokenSigner`、`TokenVerifier`、`SessionResolver` |
| [`apis/runtime/middleware`](#apisruntimemiddleware) | Gin 日志、恢复、CORS、认证与 CSRF 中间件 | `NewCORS`、`NewBrowserSessionMiddleware` |
| [`apis/runtime/server`](#apisruntimeserver) | Gin Router、路由认证模式和 API 适配 | `NewRouter`、`API` |
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
| [`verification`](#verification) | 一次性验证码的发送、存储和校验 | `NewService`、`NewRedisStore` |

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

集中声明 middleware 与 handler 之间传递请求 ID、用户、UIN、公司、成员代次和响应码时使用的 Gin Context key。业务代码应通过 `apis/runtime` 的读取函数访问常用身份字段，避免直接散落字符串 key。

### `apis/errcode`

维护进程内的业务错误码到用户消息映射。使用 `Register` 注册服务自己的错误码，`GetMessage` 获取文案。错误码是业务协议的一部分，注册应集中、确定且有测试，不要用它替代 Go `error` 的因果链。

### `apis/runtime`

提供标准 JSON 响应 helper，以及从已经通过认证和业务注入的 Gin Context 中读取 `UserID`、`UIN`、`CompanyID`、`MembershipEpoch`、`RequestID` 和 `LoginStatus`。

```go
func GetProfile(ctx *gin.Context) {
    userID := runtime.UserID(ctx)
    if userID == 0 {
        runtime.BadRequest(ctx, "missing user")
        return
    }
    runtime.Success(ctx, gin.H{"user_id": userID})
}
```

这些读取函数不执行认证；认证必须由对应路由 middleware 完成。

### `apis/runtime/auth`

认证包包含两条明确分离的链路：

- 新的 Browser Session：浏览器只持有 Host-only 不透明 Cookie，业务服务通过 `SessionResolver` 获取最小主体快照。
- 兼容 Bearer：旧服务可继续使用 HS256 迁移 API；新服务间 token 使用 Ed25519/EdDSA 签发和验证。

#### Browser Session

`NewInternalSessionResolverClient` 实现 `SessionResolver`，调用 Account 固定内部接口：

```go
resolver, err := auth.NewInternalSessionResolverClient(auth.SessionResolverClientOptions{
    Endpoint:  "https://account.internal/internal/session/resolve",
    Service:   "juxonone",
    Transport: workloadAuthenticatedTransport,
    Timeout:   750 * time.Millisecond,
})
```

`Transport` 必须已经配置 mTLS 或等价的工作负载认证。客户端不使用匿名默认 Transport、不跟随重定向、不缓存、不重试，并严格校验 HTTPS 地址、JSON 类型、响应大小和主体字段。Account 的 401/404 映射为 `ErrInvalidCredential`；Transport、超时、限流、调用方认证失败和畸形响应均 fail closed 为 `ErrAuthBackendUnavailable`。

有效主体必须同时包含非零 `UserID`、`UIN`、`CompanyID`、`MembershipEpoch` 和 `SessionVersion`。`membership_epoch=0` 不代表有效旧成员关系。

#### EdDSA JWT

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

`Ed25519TokenVerifier.JWKS`/`PublicJWKS` 只输出公开密钥材料。`JWTConfig`、`LoadJWTConfig`、`IssueIdentityToken` 和 `ParseLegacyToken` 仅用于旧 HS256 Bearer 迁移；Browser Session 不得调用这些旧 API。

### `apis/runtime/middleware`

提供请求日志、panic 恢复、自定义 header、显式 Bearer、Browser Session、CORS 和 CSRF 中间件。

Browser Session 通过 `NewBrowserSessionMiddleware` 构造，并与 `NewCSRFMiddleware` 共用 `BrowserSessionOptions`。Cookie 和 Bearer 互斥，不会在失败时互相回退。副作用请求必须通过 CSRF token 校验。

`NewCORS` 只接受精确 HTTP(S) origin，不接受通配符、域名后缀、路径或动态反射。CORS 决定浏览器能否读取响应，不是 CSRF 防护。位于可信反向代理之后时，CORS 与 Browser Session 必须配置同一个 `ExternalOrigin`；两者都不会信任客户端提供的 `X-Forwarded-Host`/`X-Forwarded-Proto`。

```go
externalOrigin := "https://api.example.com"
corsMiddleware, err := middleware.NewCORS(middleware.CORSOptions{
    AllowedOrigins: []string{"https://app.example.com"},
    ExternalOrigin: externalOrigin,
})
```

`LoginStatus` 和 `CORS()` 是兼容旧代码的入口。新代码应优先使用显式构造器并处理配置错误。

### `apis/runtime/server`

`Router` 在 Gin 之上统一 API prefix、DTO 适配和逐路由认证模式：

- `Post`、`G`：匿名路由，不解析认证凭据。
- `PRequireBrowserSession`、`GRequireBrowserSession`：只接受配置的 Browser Session。
- `PRequireBearer`、`GRequireBearer`：只接受 Bearer，并拒绝浏览器 Session Cookie。
- `PRequireLogin`、`GRequireLogin`：兼容旧代码的 Bearer 别名。

```go
router := server.NewRouter("/v1/",
    server.WithCORS(corsMiddleware),
    server.WithBrowserSession(middleware.BrowserSessionOptions{
        Service:        "api",
        CookieName:     "__Host-api_session",
        AllowedHosts:   map[string]struct{}{"api.example.com": {}},
        ExternalOrigin: externalOrigin,
        Resolver:       resolver,
    }),
)
router.PRequireBrowserSession("profile.Get", server.API(handler.GetProfile))
```

Browser Session 路由顺序固定为 Session Resolve、业务身份注入、登录要求、unsafe-method CSRF、业务 handler。`API` 支持请求体大小限制；不要在 handler 中重新实现认证分支。

### `config`

加载核心 YAML 配置。通常使用 `LoadCoreConfigFromEnv` 读取环境指定配置，或在工具/测试中显式使用 `LoadCoreConfigFromFile`。`Conf` 返回当前已加载核心配置。不要把 secret 写入仓库 YAML；由部署环境注入。

### `dbtools`

管理命名 GORM 连接。`InitDBConn` 初始化单个连接，`InitMutilDBConn` 初始化多个连接，`DB(name)` 读取命名连接，`Core`/`Account`/`Jxone` 是约定名称的快捷入口。

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

提供 S3-compatible `Storager`、`S3Fs` 和 `core_upload_files` 元数据。`NewS3Fs` 构造明确配置的实例；`LoadStorager`/`NewStorage` 使用 settings 中的 purpose 配置。使用文件模型前显式调用 `InitDB`。

对象 key 生成、内容 hash 与数据库元数据不能代替上传权限、内容类型校验、病毒扫描或下载授权，这些由业务服务负责。

### `task`

提供数据库任务记录、Redis Stream/队列、worker 健康检查和 callback 注册。典型流程是应用显式 `InitDB`、注册每种 task type 的 callback，再启动任务协调逻辑。

历史 API 中保留了若干拼写兼容入口（例如 `ChackWockerHealth`）；新代码不要复制这些命名。任务 callback 必须幂等，并明确处理超时、重试和重复投递。

### `verification`

一次性验证码的通用领域服务。`Store` 管理验证码状态，`Deliverer` 负责邮件等通道，`Policy` 定义长度、有效期、发送冷却和尝试次数；`RedisStore` 是共享环境实现。

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

- feature branch push：执行编译、格式、vet、单元测试、race 和 vendor 一致性检查。
- pull request：执行相同的完整检查；受信内部贡献在 JXlan self-hosted runner 上运行，未知 fork 在 GitHub-hosted runner 上运行。
- `main`：required check 通过后才允许合并；合并后再次验证。
- manual：`workflow_dispatch` 可在 GitHub UI 选择或输入指定 ref 验证。

正式发布必须在 `main` 绿灯后创建语义化 tag。下游升级到新 tag 并完成兼容性测试后，才能删除临时 commit pin。

## 开发约束

- 公共包只保留至少两个实际消费者需要的稳定能力；Account/JXONE 业务模型归属业务仓库。
- 不提交个人 fork `replace`、本地凭证、生成日志、IDE 缓存或临时修复脚本。
- 导出 API 需要完整注释、测试和兼容性说明；破坏性变更必须通过新主版本发布。
- 数据库迁移和外部资源初始化均由应用显式触发，禁止 import side effect。
