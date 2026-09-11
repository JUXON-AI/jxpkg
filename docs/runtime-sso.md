# JX Account SSO runtime

`apis/runtime/sso` provides the Consumer runtime and the internal resolver
Provider. Both use the same `auth` protocol DTOs. Account retains OIDC,
browser-session storage, revocation and company identities; Provider manages
only the internal HTTP/mTLS boundary. No external identity-provider dependency
or protocol replacement is introduced.

## Minimal application code

```go
runtime, err := sso.LoadEnv(os.Getenv, "JUXONONE")
if err != nil {
    return err // startup fails closed
}
defer runtime.Close()

devproject.ConfigureCompanyIdentityResolver(runtime.CompanyIdentityResolver())
router := server.NewRouter(
    "/v1/",
    runtime.RouterOption(),
    server.WithGracefulShutdownTimeout(drain),
)
```

`Runtime.RouterOption()` is the application's only Browser Session installation
point. It carries the validated CORS, Session resolver and CSRF middleware as one
router option. `server.PRequireBrowserSession` is the only browser-authenticated
route registrar and fixes their execution order.

The application still registers its own routes and makes its own domain
authorization decisions. For example, a project service must still decide
which project roles may modify a project.

## Account issuer integration

Account constructs one `devssoauthority.Authority` from its existing session
store, OAuth client registry and company directory. That same instance implements
`auth.SessionResolver`, `auth.CompanyIdentityResolver` and
`ServiceHostAllowed(service, host) bool`. It serves local browser routes and the
network Provider without an HTTP call back into Account itself.

```go
authority, err := devssoauthority.New(sessions, oauthHandler, devcompany.NewService(db))
if err != nil {
    return err
}
provider, err := sso.LoadProviderEnv(os.Getenv, "ACCOUNT", authority)
if err != nil {
    return err
}
lifecycle.Std().AddCloser(provider)
defer provider.Close() // fallback for ordinary startup returns

browserSession, err := oauthHandler.BrowserSessionOptions(authority)
if err != nil {
    return err
}
router, err := newAccountRouter(oauthHandler, upstreamHandler, browserSession)
if err != nil {
    return err
}
// Start serving after all application startup validation is complete.
go func() {
    if err := provider.Serve(); err != nil {
        logs.Errorf("[main] internal session resolver stopped")
        lifecycle.Std().Exit()
    }
}()
if err := router.Run(publicListener); err != nil {
    return err
}
lifecycle.Std().WaitExit()
```

`newAccountRouter` is Account's composition root. It converts the Account-owned
client/cookie/origin policy into one `server.NewBrowserSessionOption`, installs
the registered-host CORS middleware, and mounts Account routes. Account does not
assemble or reorder the Session and CSRF handlers.

### Multi-host bindings

The low-level `BrowserSessionOptions` now contains `Bindings []BrowserSessionBinding`
instead of process-wide `Service`, `CookieName`, `AllowedHosts`, and `ExternalOrigin`.
Each binding has exactly `Host`, `Service`, `CookieName`, and `ExternalOrigin`.
`server.NewBrowserSessionOption` calls the single middleware constructor
`NewBrowserSessionHandlers` once: Session, CSRF and Bearer handlers share one
startup-validated, defensively copied Host index. Empty directories, duplicate
Hosts, invalid cookies and mismatched origin Hosts fail before serving requests.
Caller changes to the binding slice or unsafe-method map cannot alter the handlers.

Requests select the exact registered Host, including its port; there is no suffix,
case, default-port or forwarded-header fallback. Browser routes resolve only that
Host's cookie using its service, and unsafe requests require that binding's exact
origin and session CSRF token. Bearer routes reject only the selected Host's cookie;
an unrelated binding's cookie alone does not block a valid Bearer credential.
Unknown Hosts fail closed on browser routes. On a Bearer route an unbound Host has
no selected browser cookie and still requires normal Bearer authentication; this
preserves Account's auth-host legacy boundary. Pure Bearer routers without browser
configuration retain their existing behavior.

`sso.LoadEnv`, `Runtime.RouterOption` and `PRequireBrowserSession` remain unchanged.
`LoadEnv` still requires `EXTERNAL_ORIGIN`, checks its Host belongs to
`BROWSER_ALLOWED_HOSTS_JSON`, then generates each explicit Host's origin using that
same scheme (`scheme://host`). CORS also selects the Host's exact origin.
Requests without an `Origin` header retain ordinary CORS pass-through, including
internal Worker service Hosts; their route's authentication still applies. A present
but empty `Origin` is not treated as absent. Browser routes continue to enforce
their own Host binding and CSRF checks independently of CORS.
Only low-level bindings may omit `ExternalOrigin` to derive it from direct TLS/Host;
trusted proxy deployments should always supply it. Account now builds every binding
from its immutable OIDC Client registry through `BrowserSessionOptions(authority)`.
`ACCOUNT_BUSINESS_HOST` is no longer part of the source, tests, examples or runtime
contract.

`LoadProviderEnv` validates configuration and binds its TLS listener. `Serve()`
and `Close() error` are concurrently idempotent; `Close` drains for three seconds
and then forces remaining connections closed. Provider implements `io.Closer`
and never closes Account's stores.
`AddCloser(provider)` is required: `lifecycle.WaitExit` terminates through
`os.Exit`, which does not run deferred functions.

Authority must check Host → registered ClientID, exact returned ClientID/Host,
and current membership/status/epoch. It maps invalid/revoked/expired sessions to
`auth.ErrInvalidCredential`, dependency failure to `auth.ErrAuthBackendUnavailable`,
and unavailable/missing companies to `auth.ErrCompanyIdentityNotFound` for the
directory endpoint. Provider preserves 401/503/404 respectively. Domain errors
are logged once with safe stage/type information; raw session IDs are never logged.

## Required deployment keys

For prefix `JUXONONE`, the SDK reads these existing keys:

| Key | Purpose |
| --- | --- |
| `JUXONONE_BROWSER_ALLOWED_HOSTS_JSON` | Exact browser hosts accepted by the service. |
| `JUXONONE_BROWSER_SESSION_COOKIE` | The `__Host-` Account-issued session cookie name. |
| `JUXONONE_EXTERNAL_ORIGIN` | Exact external HTTPS origin for CORS and CSRF. |
| `JUXONONE_SESSION_RESOLVER_ENDPOINT` | Account internal HTTPS endpoint ending in `/internal/session/resolve`. |
| `JUXONONE_SESSION_RESOLVER_SERVICE` | Static Account-registered workload service name. |
| `JUXONONE_SESSION_RESOLVER_TLS_CERT_FILE` | Client certificate file. |
| `JUXONONE_SESSION_RESOLVER_TLS_KEY_FILE` | Client private-key file. |
| `JUXONONE_SESSION_RESOLVER_CA_FILE` | Account resolver CA file. |

The endpoint, client certificate, and service value are mutually enforced by
Account's mTLS caller registration. Do not put their contents in application
configuration files or source control; mount them from a Kubernetes Secret.

For `LoadProviderEnv(getenv, "ACCOUNT", authority)`, the existing Provider keys are:

| Key | Purpose |
| --- | --- |
| `ACCOUNT_SESSION_RESOLVER_ADDR` | Internal listener address, normally port 8443. |
| `ACCOUNT_SESSION_RESOLVER_CALLERS_JSON` | SPIFFE principal, service and allowed business-host registrations. |
| `ACCOUNT_SESSION_RESOLVER_TLS_CERT_FILE` | Server certificate file. |
| `ACCOUNT_SESSION_RESOLVER_TLS_KEY_FILE` | Server private-key file. |
| `ACCOUNT_SESSION_RESOLVER_CLIENT_CA_FILE` | CA trusted to issue workload client certificates. |

Provider serves only `/internal/session/resolve` and
`/internal/company-identities/resolve`. It enforces TLS 1.3, required client
certificates, a single SPIFFE URI from verified chains, caller/service/host
binding, bounded requests and strict JSON. It shares
`auth.SessionResolveRequest` / `SessionResolveResponse` and
`auth.CompanyIdentityResolveRequest` / `CompanyIdentityResolveResponse` with
Consumer. Account no longer defines duplicate wire DTOs or protocol handlers.

## Security properties

- The resolver transport ignores proxy environment variables, uses TLS 1.3,
  requires a client certificate, and has bounded connect/handshake/response
  timeouts.
- Browser routes require the Account-resolved `__Host-` session; unsafe methods
  require exact Origin and CSRF validation.
- No user bearer token, Account Redis access, or Account database access is
  exposed to the business service.
- Invalid configuration prevents the process from starting. Account resolver
  failures deny browser access instead of falling back to a cached identity.
## Browser identity publication

`PRequireBrowserSession` publishes `UserID`, `UIN`, `CompanyID` and
`MembershipEpoch` after successful session resolution. Applications
do not need an `AuthInject` callback merely to validate or copy those fields.
The Browser Session path never executes `AuthInject`: the Account authority has
already resolved and revalidated the opaque Session. `AuthInject` is exclusively
the validator hook for `PRequireBearer` compatibility routes.

Account currently keeps three user-Bearer actions as an explicitly deprecated
compatibility boundary: `account.ListMyIdentities`, `account.SwitchIdentity` and
`account.GetCurrentIdentity`. The current JXOne and Account browser frontends use
`/auth/session`, `/auth/identities`, `/auth/switch-identity` and `/auth/logout`
instead. Do not add new user-Bearer consumers. Removal is safe only after `jxx`,
the pre-Browser-Session `jxone-web/main`, and any external clients have migrated:
the old web directly blocks removal of Account's three endpoints, while `jxx`
blocks removal of JXpKG's legacy registrar until its own routes migrate. Worker
Bearer is a separate workload credential and is not deprecated.

## Validation and handoff

The implementation commit is SDK `fbaafaea11397b928d0344b7e837478ec94dbcfc`,
merged to `main` as `53a9318278c6ea10405cc1b0bd8a78dd93f2d80a`.
Account adoption `5ab5fa012f425152f44aa4a4c8fa34f6ed70597e` was merged as
`898c3afaace25d716ab5510017ee1d0d954fcea9`; JXOne adoption
`3c5b7c6538b12002152c49826de6aebf7b2f95a6` was merged as
`bc11c5503976c10ea88aa73d071cfd863e5e9b6d`. Both
applications require the official pseudo-version
`v0.0.14-0.20260911085822-fbaafaea1139`; neither source tree nor final image
uses a `replace` directive.

Local SDK tests/vet/build and runtime race tests passed. Account full tests,
race, vet, module verification, build and SIGTERM subprocess tests passed.
JXOne module verification, build and SSO/router/startup/collaboration race tests
passed. Its full suite still has the unchanged, unrelated
`devcanvas/TestWorkshopNumbersRetainValidation` numeric-boundary failure.

The post-merge JX-LAN acceptance snapshot, taken before the separate Account
namespace migration began, is recorded by `k3syaml` merge commit
`4f26809b63dbf317f01d6d1720faf9990000b188` and deploy run `34588106613`.
Account/JXOne/Worker ready replicas were 1/1/2; release-set validation, database
migrations, runtime digest checks, module smoke and the JXOne graceful-rollout
probe all passed.

These are deployment and protocol checks, not a credentialed browser login
acceptance. No real user credential interaction was performed. Digest prefixes,
the initial host-to-ClusterIP routing limitation and rollback evidence are
recorded in the handoff below.

See [the cross-repository handoff](sso-sdk-handoff.md) for deletion inventory,
exact test commands, deployment checks and pending browser/product acceptance.
For a new service, use the maintained [JX SSO integration guide](sso-integration-guide.md).
