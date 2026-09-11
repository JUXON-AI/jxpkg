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

browserSession, err := oauthHandler.BrowserSessionOptions(
    os.Getenv("ACCOUNT_BUSINESS_HOST"), authority,
)
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

For `LoadProviderEnv(getenv, "ACCOUNT", options)`, the existing Provider keys are:

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
An explicitly registered callback still runs and can reject the principal;
Bearer routes continue to require their application validator. Do not remove an
Account validator while legacy Bearer routes still depend on database revalidation.

## Validation and handoff

The Provider implementation is in SDK commit `c318a8267d4f`; Account adoption is
`419726b7538d`; JXOne dependency adoption is
`1d8212c03808c0e5506e958e2bee13e7df870ffe`. Consumer method signatures
are unchanged. Local SDK tests/vet and full-repository
`go test -race -count=1 ./...` passed. Account full tests,
race, vet, module verification, build and real SIGTERM subprocess tests passed.

The subsequent JX-LAN Redis+mTLS integration run passed all scenarios. Isolated
image builds used a temporary `replace => ./.local-jxpkg` pointing at the exact
SDK source above; buildinfo in all three images confirmed that source. This
replacement is a build-local override, not a committed application dependency.
Rollout in namespace `jxone` completed with Account/JXOne/Worker ready replicas
1/1/2, four Pods and zero restarts. Module smoke passed 20/20. Live resolver
checks returned 401 for an invalid session with a valid mTLS client, and TLS
rejected a client without a certificate. Login bootstrap returned 302 and a
callback without required input returned 400.

These are deployment and protocol checks, not a credentialed browser login
acceptance. No real user credential interaction was performed. Digest prefixes,
the initial host-to-ClusterIP routing limitation and rollback evidence are
recorded in the handoff below.

See [the cross-repository handoff](sso-sdk-handoff.md) for deletion inventory,
exact test commands, deployment checks and pending browser/product acceptance.
