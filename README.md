# jxpkg

Juxonone 后端服务基础包，提供 HTTP API、配置、数据库、Redis、日志、对象存储、任务、认证、邮件和模型客户端等能力。

## 安装

```bash
go get github.com/JUXON-AI/jxpkg@v0.0.5
```

要求 Go 1.25 或更高版本。

## 目录

```text
apis/          HTTP API、JWT、Gin middleware 和 server
config/        YAML 配置加载
dbtools/       GORM 数据库和 Redis 连接
lifecycle/     应用生命周期
llm/           OpenAI-compatible 客户端
logs/          Zap 和 GORM 日志
mail/          SMTP 邮件
mutex/         Redis 锁和集群选主
random/        随机数据生成
settings/      数据库配置项
storage/       S3-compatible 对象存储和文件模型
task/          异步任务、队列和 worker API
verification/  一次性验证码
```

数据库迁移由应用显式调用，不会因为导入本包自动执行。数据库连接、Redis、S3 和 SMTP 等配置由应用提供。

## HTTP 认证模式

`apis/runtime/server.Router` 按路由显式选择唯一认证模式：

- `Post`、`G`：匿名路由，不解析或校验请求中的认证凭据；
- `PRequireBrowserSession`、`GRequireBrowserSession`：仅接受通过 `WithBrowserSession` 配置的 Host-only Cookie Session；
- `PRequireBearer`、`GRequireBearer`：仅接受 Bearer Token，并拒绝已配置的浏览器 Session Cookie；
- `PRequireLogin`、`GRequireLogin`：兼容旧代码的 Bearer 别名，新代码应使用显式方法。

浏览器会话路由固定按 Session Resolve、业务身份注入、登录要求、unsafe method CSRF、业务 Handler 的顺序执行。Cookie 和 Bearer 不会互相回退。

## CORS 配置

`server.NewRouter` 的默认 CORS 策略只放行无 `Origin` 请求和由请求 TLS 状态及 `Host` 确定的精确同源请求，不再组合 `AllowAllOrigins` 与凭据。跨源浏览器客户端必须配置完整且精确的 HTTP(S) Origin：

```go
corsMiddleware, err := middleware.NewCORS(middleware.CORSOptions{
    AllowedOrigins: []string{"https://app.example.com"},
    ExternalOrigin: "https://api.example.com",
})
if err != nil {
    return err
}
router := server.NewRouter("/v1/", server.WithCORS(corsMiddleware))
```

`AllowedOrigins` 不接受通配符、域名后缀、路径或请求值反射。服务位于可信反向代理之后时，可用 `ExternalOrigin` 声明应用确认的外部同源 Origin；中间件不会信任 `X-Forwarded-Host` 或 `X-Forwarded-Proto`。预检只返回本次请求且配置允许的方法与请求头。

CORS 只控制浏览器能否读取跨源响应，不是 CSRF 防护。使用 Cookie Session 的副作用请求仍必须配置浏览器 Session 路由并通过 Origin 和 CSRF Token 校验。

## 非对称 JWT API

`apis/runtime/auth` 的新 JWT API 只接受 Ed25519/EdDSA。签发器持有一个活动私钥，验证器可同时持有当前和旧公钥，以便在密钥轮换期间保留验证重叠窗口。密钥集合由调用方在本地提供；该包不会通过 `jku`、`x5u` 或远程 JWKS 自动刷新密钥。

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

`TokenVerifier` 是仅包含 `Verify` 的依赖接口，`NewTokenVerifier` 返回支持密钥轮换和 `JWKS` 的 `*Ed25519TokenVerifier`。验证固定要求 `typ=JWT`、非空且已知的 `kid`、`alg=EdDSA`，并校验 `iss`、`aud`、`sub`、`iat`、可选 `nbf`、`exp` 和 `jti`。多受众令牌还必须提供与预期受众相等的 `azp`。受保护 JOSE 头和声明必须是大小与深度受限、且任何层级都无重复成员的 JSON 对象。`VerificationKey.Algorithm` 应设置为 `auth.JWTAlgorithmEdDSA`。

`Ed25519TokenVerifier.JWKS`（或 `auth.PublicJWKS`）按 `kid` 确定性输出仅含 `kty=OKP`、`crv=Ed25519`、`x`、`kid`、`alg=EdDSA`、`use=sig` 的公开 JWKS，不包含私钥材料。`TokenSigner` 同样是可替换接口，构造器返回保留 `VerificationKey` 能力的 `*Ed25519TokenSigner`。

`JWTConfig`、`LoadJWTConfig`、`IssueIdentityToken` 和明确命名的 `ParseLegacyToken` 是迁移期旧版 HS256 API，仅用于兼容现有 Bearer 调用。`ParseToken` 已弃用并仅委托给 `ParseLegacyToken` 保持源码兼容。浏览器 Session 流程只接受不透明 Cookie Session，且不得调用这些旧 API；新代码必须使用 `TokenSigner` 和 `TokenVerifier`。

## 集成测试

默认测试不会连接外部资源。需要执行集成测试时设置对应环境变量：

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
