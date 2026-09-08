# jxpkg development guide

## Scope

`jxpkg` contains stable Go capabilities shared by JUXON services. Business workflows, service-owned GORM models, deployment manifests and one-off repair scripts belong in their owning repositories.

Before adding a public API, identify at least two real consumers or document why the shared protocol itself requires the type here. Prefer the smallest concrete API over speculative modes, wrappers or aliases.

## Required checks

Run these commands from the repository root before committing:

```bash
gofmt -w <changed-go-files>
go vet ./...
go test ./...
go test -race ./...
go mod verify
go list -mod=vendor ./...
make build
```

Do not edit `vendor/` manually. If dependencies intentionally change, update `go.mod`/`go.sum`, regenerate vendor data with the Go toolchain and review the resulting diff.

## Compatibility and security

- Preserve existing exported APIs unless a versioned migration plan explicitly permits a break.
- Authentication code must fail closed, reject ambiguous input and avoid logging credentials, cookies, tokens, verification codes or key material.
- Browser Session and Bearer are distinct route modes and must not silently fall back to each other.
- Database migration and external resource initialization must remain explicit application actions, never package import side effects.
- New exported identifiers require Go doc comments and focused tests for success, invalid input and boundary behavior.

## Git workflow

Use a feature branch and update the existing pull request. Never push directly to `main`, commit personal fork replacements, generated logs, IDE state, secrets, `.env.local`, or temporary repair/debug artifacts.
