# SSO SDK 独立审阅与验证

## 审阅基线

2026-09-11，两个独立 reviewer 分别检查架构与代码行为。两者先阅读各仓
AGENTS.md 和 reviewcode 规范，再检查实际 diff；没有以交接文档代替代码审阅。

| 仓库 | 审阅提交 |
|---|---|
| jxpkg | e13064a050e068f49ca19abfeb91f73b8b3e906e |
| jxone | fc40a5928ba25e14ec611525bafdb8ba539b9929 |
| jxaccount | b4935caa91964b108dad4c9c2fdb485683917c99 |

JXOne 比较基线为 3a1d89c，Account 为 2fb5beb；不能使用陈旧的本地远端引用
把历史改动纳入本次 review。

## 结论与修复

| 严重度 | 发现 | 处理 |
|---|---|---|
| P2，必须修复 | SDK 允许缺失 EXTERNAL_ORIGIN，丢失旧启动契约；TLS 在 Ingress 终止时会错误推导 HTTP Origin | b497698 在读取证书前验证八个必需配置键，逐键缺失测试覆盖 |
| P2 | 显式 injector 写入身份后返回 error，四个上下文字段仍残留 | b497698 拒绝时重新清空；callback 返回 nil 但清空 Claim、修改失败 State 或清空 epoch 时也拒绝 |
| P2 | 配置失败全部变成统一 unavailable，难以定位 | b497698 返回安全阶段或键名；JXOne 记录安全 error，测试证书路径不泄露 |
| P2，验证缺口 | 删除应用私有构造测试后，SDK 缺少真实请求、900ms 延迟预算和部署接线验证 | Account 增加隔离 Redis 与真实 HTTP/TLS/mTLS 的 SDK integration 测试，独立 reviewer 继续检查 CORS 和拒绝路径 |

第二 reviewer 对 b497698 的工作区修复执行非缓存
`go test -count=1 ./apis/runtime/server ./apis/runtime/sso`，确认原配置回归、
callback 残留身份和 nil Claim 边界已修复；无新增阻塞项。

## 可读性与方法规范

- Runtime 负责环境配置、transport 和连接生命周期；单个 RouterOption 封装共享 Session/CSRF 顺序，不向应用暴露 middleware pair 或近义 wrapper。
- Account 的 newAccountRouter 同时服务生产与测试，负责构造验证和路由装配；测试工厂仅存在于 _test.go。
- JXOne 不恢复私有 SSO 方法来让旧测试通过；测试迁到公共契约。
- Account 的 OIDC、Session writer、注册表和数据库复核保留在所属服务；业务 RBAC 不移动到 SDK。
- 新测试按装配、请求断言、场景和证书 fixture 分开。明确说明采用测试身份目录及种入的 Session，不能将它描述为真实数据库登录或浏览器注册验收。
- 所有测试错误避免输出 Cookie、CSRF、Session ID、私钥与完整请求。测试环境不读取部署 Secret。

## 证据边界

本轮先审阅并修复，再在 JX-LAN 独立临时目录构建与测试。远端现有 Account
local-sso 工作区有未提交修改，未改动或借用它；旧 fixture 不是生产 Account，
其绿色结果不能证明此次 SDK 接线。

真实浏览器、已登录业务权限、候选镜像部署、Ingress 和真实数据库验收必须分别
记录，不能从 SDK 服务链集成测试推断完成。实际运行记录随测试结果补充。

### JX-LAN 全量验证

远端目录 `/tmp/jx-sdk-validation.pzlVyF` 是新建的独立验证目录，不是开发者现有
checkout。SDK 使用 b497698，两个应用使用官方
`v0.0.14-0.20260911031544-b49769855199`，没有本地 replace 或 go.work。
应用源分别来自 fc40a59/b4935ca 加本轮依赖更新，JXOne 同时加入安全错误日志。

`go1.27.0-X:nodwarf5 linux/amd64` 下，三仓 `go test -count=1 -race ./...`、
`go vet ./...` 和构建均通过。日志分别为 sdk-race.log、account-race.log、
jxone-race.log；含测试包通过数分别为 11、21、41。
先前 macOS Go 1.26.4 的 devcanvas 数值边界失败没有在本次远端环境复现，
不因此删除或修改该测试。

远端构建二进制 SHA-256：

| 二进制 | SHA-256 |
|---|---|
| Account | dcd604e3bb8614f0f6a57dc92e9b53499fb6c8fcee6f18d121d4680481b81b1a |
| Juxonone | 985f9dcbbcc6f701c280aae4766794265cb2200382578591485f3d695a200ab8 |
| Worker | 54ddd06e0e3bee90964b7c78ba4855a12a8b7f94b3a2efff729e059f96721f87 |

这些是构建产物校验值，不是 Registry 镜像 digest；本次没有据此更改线上 Deployment。

### SDK 服务链 E2E

2026-09-11 11:22 CST，Account 的 `scripts/test-sso-sdk.sh` 在同一 JX-LAN
隔离目录实跑通过，26 个具体场景，开启 race、禁用缓存。真实使用 HTTPS入口、
HTTP backend、SDK mTLS resolver 和隔离 Redis Lua；缺 Cookie、CSRF、错误 CA、
无客户端证书、错误 SPIFFE/service/host、epoch、禁用、900ms延迟、超时、
会话轮换与全局撤销均有断言。preflight检查凭据CORS响应头及零handler/resolver调用。

测试目录与分组结果见 Account PR #3 的 `docs/sso-sdk-testing.md`。
第一 reviewer 在实现前指出缺失预检响应头与caller scope负例，已补齐；测试按
fixture、请求断言、6组场景和证书生成方法整理，避免在一个测试方法内混合全部责任。
测试只种入会话并使用受控身份目录，真实浏览器/OIDC/业务数据库验收未执行。

第二 reviewer 对最终测试代码的独立复核无阻断项：确认不是固定响应自证，成功、
拒绝、preflight 与 TLS 失败都核对调用次数，gofmt、bash语法与diff检查通过。
其指出的注释歧义已修正：IdentityValidator 和 EventSink 也为 stub，不计入
真实权威数据和事件投递验收。
