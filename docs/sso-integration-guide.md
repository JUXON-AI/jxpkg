# JX SSO 接入指南

适用对象：JXOne、Account、JXX 及其他需要接入统一登录的 Go 服务开发者。

当前 Browser SSO 的原则是：业务项目只在启动时安装一次 JXpKG runtime，在需要登录的路由上声明一次 middleware；Cookie、CORS、CSRF、Account Session 解析和 mTLS 由 JXpKG 管理。业务仓库不得再复制一套 SSO transport、middleware 或 principal wrapper。

## 先确认你的代码不是旧版本

现有本地 checkout、长期开发分支和 vendor 目录可能仍停留在旧 SSO。先在每个仓库检查，不要用 `reset --hard` 覆盖未提交工作：

```bash
git status --short
git fetch origin
git log --oneline HEAD..origin/main
```

当前 SSO 最低代码基线：

| 仓库 | `origin/main` 至少应包含 | 作用 |
| --- | --- | --- |
| `jxpkg` | `53a9318278c6ea10405cc1b0bd8a78dd93f2d80a` | PR #17：多 Host Browser binding 与开箱即用 runtime |
| `jxaccount` | `898c3afaace25d716ab5510017ee1d0d954fcea9` | PR #3：Account Provider、Client registry 多 Host 接线 |
| `jxone` | `bc11c5503976c10ea88aa73d071cfd863e5e9b6d` | PR #7：最小 Consumer 接入与新版 runtime pin |
| `k3syaml` | `4f26809b63dbf317f01d6d1720faf9990000b188` | PR #7：最终 main release set 与部署入口 |

下面的退出码为 0 才表示当前分支包含基线：

```bash
git merge-base --is-ancestor <baseline-commit> HEAD
```

工作树干净时再更新主线：

```bash
git switch main
git pull --ff-only
```

正在开发的 feature branch 应按团队流程 merge/rebase 最新 `origin/main` 并解决冲突，不要复制旧 SSO 文件回去。

## Go 依赖

当前 Account 和 JXOne 已验证的 JXpKG 版本是：

```text
github.com/JUXON-AI/jxpkg v0.0.14-0.20260911085822-fbaafaea1139
```

新服务在仓库根目录执行：

```bash
go get github.com/JUXON-AI/jxpkg@v0.0.14-0.20260911085822-fbaafaea1139
go mod tidy
go mod verify
```

仓库提交 vendor 时再执行 `go mod vendor`，并审阅完整 vendor diff。跨仓本地联调可以临时使用 `replace`，但提交前必须删除：

```bash
go mod edit -replace github.com/JUXON-AI/jxpkg=/absolute/path/to/jxpkg
# 联调结束
go mod edit -dropreplace github.com/JUXON-AI/jxpkg
go mod tidy
```

任何 PR、镜像或发布分支都不得包含个人路径 `replace`。

## 业务后端的最小代码

### 1. 启动时安装一次

```go
import (
    "os"

    "github.com/JUXON-AI/jxpkg/apis/runtime/server"
    "github.com/JUXON-AI/jxpkg/apis/runtime/sso"
)

ssoRuntime, err := sso.LoadEnv(os.Getenv, "JXX")
if err != nil {
    return err // 配置、证书或 Host 不完整时拒绝启动
}
defer ssoRuntime.Close()

router := server.NewRouter(
    "/v1/",
    ssoRuntime.RouterOption(),
)
```

`JXX` 是该服务自己的大写环境变量前缀。不要在业务项目里创建 resolver `http.Client`、CORS、Cookie Session 或 CSRF middleware；`RouterOption()` 已按固定顺序安装完整边界。

如果业务目录需要批量读取 Account 权威公司成员快照，只注入 SDK 已创建的 client：

```go
memberDirectory.ConfigureResolver(ssoRuntime.CompanyIdentityResolver())
```

### 2. 路由只声明认证模式

```go
router.PRequireBrowserSession("jxx.ListProjects", ListProjects)
router.PRequireBrowserSession("jxx.UpdateProject", UpdateProject)
```

`PRequireBrowserSession` 固定执行：解析当前 Host 的不透明 Session Cookie、通过 mTLS 调 Account、发布 verified principal、要求已认证、对副作用请求校验 Origin/CSRF、进入业务 handler。

浏览器路由不要使用 `PRequireLogin` 或用户 Bearer。`PRequireBearer` 只用于仍在迁移的兼容接口或独立 workload credential。

### 3. handler 只读取已验证事实

```go
import jxruntime "github.com/JUXON-AI/jxpkg/apis/runtime"

func UpdateProject(ctx *gin.Context) {
    userID := jxruntime.UserID(ctx)
    uin := jxruntime.UIN(ctx)
    companyID := jxruntime.CompanyID(ctx)
    membershipEpoch := jxruntime.MembershipEpoch(ctx)

    // 这里继续执行本项目自己的 company/project RBAC。
    _ = userID
    _ = uin
    _ = companyID
    _ = membershipEpoch
}
```

可用 accessor 是 `UserID`、`UIN`、`CompanyID`、`MembershipEpoch`、`BrowserSessionExpiresAt` 和 `LoginWay`。这些函数不会自行认证，只能在正确的受保护路由内使用。

## 前端接入

业务域名下的 `/auth/*` 由 Ingress 转给 Account，不需要在业务后端再实现 OIDC callback：

- `GET /auth/login?return_to=%2Fprojects`：开始登录。
- `GET /auth/callback`：Account 完成 code exchange、写入业务 Host-only Cookie，再 303 回 `return_to`。
- `GET /auth/session`：读取当前身份和 `csrf_token`。
- `GET /auth/identities`：列出可切换身份。
- `POST /auth/switch-identity`：切换身份并轮换 Session/CSRF。
- `POST /auth/logout`：撤销并清理当前业务 Cookie，响应提供中央退出导航地址。

所有请求使用 Cookie，不把用户 token 放进 `localStorage`：

```ts
const sessionResponse = await fetch("/auth/session", {
  credentials: "include",
});

if (sessionResponse.status === 401) {
  window.location.assign("/auth/login?return_to=" + encodeURIComponent(location.pathname));
  return;
}

const session = await sessionResponse.json();

await fetch("/v1/jxx.UpdateProject", {
  method: "POST",
  credentials: "include",
  headers: {
    "Content-Type": "application/json",
    "X-CSRF-Token": session.csrf_token,
  },
  body: JSON.stringify({ project_id: 42 }),
});
```

不要从可读 CSRF Cookie 自行推导认证状态；以 `/auth/session` 的响应为准。跨域 Origin、缺失/错误 CSRF、同时携带 Browser Cookie 和 Bearer 都应被拒绝。

## 在 Account 注册新业务项目

每个业务域名在 `ACCOUNT_OIDC_CLIENTS_JSON` 中恰好有一个静态 Client。示例只展示结构，密钥值必须由受控 Secret 流程生成和保存：

```json
[
  {
    "client_id": "jxx-web",
    "business_host": "jxx.example.com",
    "service": "jxx",
    "redirect_uri": "https://jxx.example.com/auth/callback",
    "logout_uri": "https://jxx.example.com/",
    "assertion_key_id": "jxx-2026-09",
    "assertion_public_key": "<raw-base64url-ed25519-public-key>",
    "assertion_private_key": "<raw-base64url-ed25519-private-key>",
    "session_cookie_name": "__Host-jxx_session",
    "login_cookie_name": "__Host-jxx_login",
    "csrf_cookie_name": "__Host-jxx_csrf"
  }
]
```

约束：

- `business_host` 是小写、无端口的精确 DNS Host。
- callback 必须精确为该 Host 的 HTTPS `/auth/callback`。
- 三个 Cookie 名互不相同并使用 `__Host-` 前缀。
- `service` 必须与 Consumer 环境和 resolver caller registration 完全一致。
- Ed25519 private key 只留在 Account Secret，不进入业务仓库、前端或日志。
- Account 从整个 Client registry 自动生成 `/v1/account.*` 的 Browser bindings；不要再增加或读取 `ACCOUNT_BUSINESS_HOST`。

同一个变更还要在 `ACCOUNT_SESSION_RESOLVER_CALLERS_JSON` 注册工作负载：

```json
[
  {
    "principal": "spiffe://<trust-domain>/workload/jxx",
    "service": "jxx",
    "allowed_hosts": ["jxx.example.com"]
  }
]
```

`principal` 必须与 Consumer client certificate 唯一 URI SAN 完全一致；`service` 和 `allowed_hosts` 又必须与 OIDC Client registry 一致。任一侧不一致都会 fail closed。

## Consumer 环境变量

`sso.LoadEnv(os.Getenv, "JXX")` 要求以下八项全部存在：

```text
JXX_BROWSER_ALLOWED_HOSTS_JSON=["jxx.example.com"]
JXX_BROWSER_SESSION_COOKIE=__Host-jxx_session
JXX_EXTERNAL_ORIGIN=https://jxx.example.com
JXX_SESSION_RESOLVER_ENDPOINT=https://account-session-resolver.<namespace>.svc.cluster.local:8443/internal/session/resolve
JXX_SESSION_RESOLVER_SERVICE=jxx
JXX_SESSION_RESOLVER_TLS_CERT_FILE=/etc/jxx/mtls/client.crt
JXX_SESSION_RESOLVER_TLS_KEY_FILE=/etc/jxx/mtls/client.key
JXX_SESSION_RESOLVER_CA_FILE=/etc/jxx/mtls/ca.crt
```

Host、Origin、Cookie、service、证书路径和 resolver endpoint 在启动阶段统一校验。`BROWSER_ALLOWED_HOSTS_JSON` 可以包含同一服务的多个精确 Host；每个 Host 会得到自己的 Origin binding。

## 两类 TLS 证书不能混用

### 公网 HTTPS 证书

业务域名和 Account 登录域名都需要浏览器信任的公网证书。Kubernetes Ingress TLS Secret 使用标准 key：

```bash
k3s kubectl -n <namespace> create secret tls <business>-tls \
  --cert=/secure/path/fullchain.pem \
  --key=/secure/path/private-key.pem \
  --dry-run=client -o yaml | k3s kubectl apply -f -
```

证书 SAN 必须包含精确业务域名；DNS 必须先指向 Ingress。不要把公网 TLS 私钥放进 Git、ConfigMap 或 `ACCOUNT_OIDC_CLIENTS_JSON`。

Ingress 至少需要以下同源路由：

- 业务 Host 的 `/auth` 和 `/v1/account` → `account-api:8080`。
- 业务 Host 的 `/v1/<service>` → 业务 API。
- 业务 Host 的 `/` → 业务 Web。

Account 认证 Host 的 `/.well-known`、`/oauth`、`/auth` 和 `/v1/account` 继续指向 Account API。

### Account resolver mTLS 证书

resolver 是集群内部 `ClusterIP:8443`，不应创建公网 Ingress。它使用独立内部 CA/mTLS，不复用公网证书：

- Server certificate：包含 resolver Service DNS 的 SAN，EKU 为 `serverAuth`。
- Consumer certificate：EKU 为 `clientAuth`，并且叶证书恰好有一个 URI SAN；该 URI 就是 caller registration 的 SPIFFE principal。
- Provider 强制 TLS 1.3、校验 client CA，并按 `principal + service + allowed_hosts` 再授权。
- Consumer 校验 server CA 和 endpoint hostname；不会使用 `HTTP_PROXY`、自动重定向、缓存或认证失败重试。

推荐由组织 CA、Vault PKI 或 cert-manager 管理签发与轮换。手工签发也必须遵守同样的 SAN/EKU/CA 约束，私钥文件权限至少为只读 `0400`。

Provider Secret 结构：

```text
account-resolver-mtls/
  server.crt
  server.key
  ca.crt       # 用于验证 Consumer client certificate 的 CA bundle
```

Consumer Secret 结构：

```text
jxx-resolver-mtls/
  client.crt
  client.key
  ca.crt       # 用于验证 Account resolver server certificate 的 CA bundle
```

挂载示例：

```yaml
volumeMounts:
  - name: resolver-mtls
    mountPath: /etc/jxx/mtls
    readOnly: true
volumes:
  - name: resolver-mtls
    secret:
      secretName: jxx-resolver-mtls
      defaultMode: 0400
```

证书只在进程启动时加载。轮换时先让双方信任包含新旧 issuer 的 CA bundle 并滚动重启，再替换 leaf certificate，验证成功后最后移除旧 CA；不要一次性破坏现有信任链。

## Account Provider 启动

普通业务项目不实现 Provider；只有 Account 使用：

```go
authority, err := devssoauthority.New(sessions, oauthHandler, companyDirectory)
if err != nil {
    return err
}

provider, err := sso.LoadProviderEnv(os.Getenv, "ACCOUNT", authority)
if err != nil {
    return err
}
lifecycle.Std().AddCloser(provider)
defer provider.Close()

browserSession, err := oauthHandler.BrowserSessionOptions(authority)
if err != nil {
    return err
}

go func() {
    if err := provider.Serve(); err != nil {
        lifecycle.Std().Exit()
    }
}()
```

Provider 环境包含 `ACCOUNT_SESSION_RESOLVER_ADDR`、`CALLERS_JSON`、server certificate/key 和 client CA 路径。Account 自己仍负责 OIDC、Session 存储/撤销、Client registry、公司 membership/epoch、验证码、上游身份和 RBAC；JXpKG 不是另一个 IdP。

## Kubernetes 网络与安全边界

- resolver Service 使用 ClusterIP，不配置 Ingress、NodePort 或 hostPort。
- NetworkPolicy 只允许已注册业务 API Pod 到 Account `8443`。
- public Account HTTP 只允许 Ingress controller 到 `8080`；只信任集群声明的代理 CIDR。
- Secret 通过 `envFrom` 或只读 volume 注入；不要提交 Secret YAML，也不要在排障命令中打印 `.data`。
- mTLS 负责工作负载身份，Browser Cookie 负责用户身份，两者缺一不可。
- 项目/company RBAC 仍属于业务服务；通过 SSO 不等于自动拥有业务权限。

### Account 使用独立 namespace 时

namespace 拆分不改变 Go API、Cookie 或 OIDC Client 注册，但会改变服务发现、Secret
归属和网络策略：

- Consumer 的 resolver endpoint 改为完整跨 namespace DNS，例如
  `account-session-resolver.<account-namespace>.svc.cluster.local:8443`；server certificate
  SAN 必须覆盖实际使用的 DNS 名。
- Provider 的 server key/证书 Secret 留在 Account namespace；每个 Consumer 的
  client key/证书 Secret 留在自己的 namespace。Secret 是 namespaced resource，不能
  假设迁移后仍可被原 Pod 引用。
- Account resolver 的 NetworkPolicy ingress rule 必须允许目标 Consumer namespace/Pod；Consumer
  egress policy 必须允许 Account namespace 的 `8443`，两侧 selector 都要按真实 label
  验证。
- 标准 Kubernetes Ingress backend 不能直接引用另一个 namespace 的 Service。
  `/auth` 与 `/v1/account` 应由 Account namespace 内的 Ingress/Route 暴露，或使用经过
  `ReferenceGrant` 明确授权的 Gateway API 方案；不要写一个无效的跨 namespace
  `service.name`。
- 终止公网 TLS 的 Ingress/Route 必须能在自己的 namespace 读取对应证书 Secret。
  同一业务 Host 被多个资源分路径接管时，要验证当前 ingress controller 的合并规则、
  路由优先级和证书选择。

迁移期间先区分“namespace/DNS/NetworkPolicy/Secret 未对齐”和“SSO 代码回归”。只有在
release-set digest、Service endpoint、证书 SAN、caller principal 与网络连通性均确认后，
才进入 Cookie/CSRF/OIDC 层排障。

## Bearer 的当前边界

- 新浏览器前端：只使用 Host-only HttpOnly Session Cookie，不发送用户 Bearer。
- Account 的三个旧用户 Bearer action 仅为兼容而保留并已 Deprecated，不得新增调用。
- JXWorker Bearer 是 32-byte 随机 workload credential，只授权 Worker action，不是用户登录 token，必须与 Browser SSO 分开保存、轮换和审计。

## 上线前验证

代码仓库至少执行：

```bash
go test ./...
go test -race ./...
go vet ./...
go mod verify
go build ./...
```

提交 vendor 的仓库额外执行 `go mod vendor`、审阅 vendor diff，并运行 `go list -mod=vendor ./...`。

集群至少验证：

1. server-side apply dry-run 与 NetworkPolicy。
2. Account、业务 API、Worker rollout Ready，Pod `imageID` 与 release-set digest 一致。
3. 无 client certificate 在 TLS 层拒绝；合法 client certificate + 无效 Session 返回 401。
4. 匿名 Browser API 返回 401，错误 Origin 返回 403，错误 CSRF 返回 401。
5. `/auth/login` 进入 Account，callback 写 Cookie，`/auth/session` 返回当前身份。
6. 身份切换轮换 Session/CSRF；退出后旧 Session 立即失效。
7. 使用真实账号验证登录、公司/项目权限和退出导航。HTTP 302、JWKS 200 或协议 smoke 都不能替代这一步。

测试集群的可执行发布与 smoke 命令以 `k3syaml/README.md` 为准。

## 常见错误

- 在业务仓库重新创建 `PreRequireBrowserSession`、resolver client 或 CORS/CSRF wrapper。
- 把 `PRequireLogin` 当成浏览器登录；它是 legacy Bearer alias。
- 只更新业务服务，却没有同步 Account OIDC Client、resolver caller、证书和 Ingress。
- `service`、Host、Cookie 名或 SPIFFE URI 在各处配置中不一致。
- server certificate SAN 写成公网域名，但 endpoint 使用集群 Service DNS。
- client certificate 没有唯一 URI SAN，或 URI 与 `CALLERS_JSON` 不一致。
- 把 `__Host-` Cookie 改成带 Domain 的跨子域 Cookie。
- 只看 image tag，不核对 registry digest 与 Pod `imageID`。
- 把 Secret、Cookie、CSRF、OIDC code、Ed25519 private key 或证书私钥写进仓库/日志。
