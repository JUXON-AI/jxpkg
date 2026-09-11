# JX Account SSO runtime

`apis/runtime/sso` is the application-side SDK for a business service that
uses JX Account browser sessions. It deliberately does not implement an
identity provider: Account remains the owner of OIDC, browser-session storage,
revocation, and company identities.

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
    append(runtime.RouterOptions(), server.WithGracefulShutdownTimeout(drain))...,
)
```

`Runtime.RouterOptions()` installs the public `middleware.BrowserSecurity`
pair. Its Session resolver always executes before the CSRF validator, and
`server.PRequireBrowserSession` then uses that same pair for every protected
browser route.

The application still registers its own routes and makes its own domain
authorization decisions. For example, a project service must still decide
which project roles may modify a project.

## Account issuer integration

Account does not use `LoadEnv`: it owns the authoritative SessionStore and
builds an in-process `auth.SessionResolver`. It uses the same public middleware
composition after creating its host-specific `BrowserSessionOptions`:

```go
security, err := middleware.NewBrowserSecurity(accountBrowserSessionOptions)
if err != nil {
    return err
}
router := server.NewRouter("/v1/", server.WithBrowserSecurity(security))
```

Account may retain a small domain adapter that selects a CORS origin from its
registered Client host. The CORS algorithm, browser Session resolution, CSRF
validation, and protected-route wiring remain jxpkg components.

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
