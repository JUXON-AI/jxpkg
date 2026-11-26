package logtobff

import (
	"context"
	"crypto"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v5"
)

func TestResourceVerificationAcceptsIssuerClockSkewOnlyForIssuedAt(t *testing.T) {
	authority, endpoint := fixtureAuthority(t)
	runtime := &Runtime{
		config: Config{Endpoint: endpoint, APIResource: "https://resource.invalid"},
		keys:   &oidc.StaticKeySet{PublicKeys: []crypto.PublicKey{&authority.key.PublicKey}},
	}
	for _, test := range []struct {
		name      string
		iat       int64
		exp       int64
		nbf       int64
		wantValid bool
	}{
		{name: "fresh", iat: 1, exp: 60, nbf: -1, wantValid: true},
		{name: "future issue time", iat: 3, exp: 60, nbf: -1},
		{name: "expired", iat: -60, exp: 0, nbf: -60},
		{name: "future not before", iat: 0, exp: 60, nbf: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			next := time.Now().Truncate(time.Second).Add(time.Second)
			if remaining := time.Until(next); remaining < 300*time.Millisecond {
				time.Sleep(remaining)
			}
			now := time.Now().Unix()
			raw := authority.signed(jwt.MapClaims{
				"iss": endpoint + "/oidc", "aud": runtime.config.APIResource, "sub": "user-one",
				"client_id": "client-one", "organization_id": "org-one",
				"iat": now + test.iat, "exp": now + test.exp, "nbf": now + test.nbf,
			})
			_, err := runtime.verify(t.Context(), raw, "org-one", "client-one")
			if (err == nil) != test.wantValid {
				t.Fatalf("credential accepted = %t, want %t", err == nil, test.wantValid)
			}
		})
	}
}

func TestResourceReadKeepsBrowserSessionDuringJWKSOutage(t *testing.T) {
	a, authority := fixtureRuntime(t)
	cookie := loginFixture(t, a, authority)
	workingKeys := a.keys
	unavailable := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(unavailable.Close)
	a.keys = oidc.NewRemoteKeySet(oidc.ClientContext(context.Background(), unavailable.Client()), unavailable.URL)

	response := callAuth(a, http.MethodGet, "/auth/session", "", cookie, "")
	if response.Code != http.StatusServiceUnavailable || len(response.Result().Cookies()) != 0 {
		t.Fatalf("JWKS outage returned HTTP %d or changed browser cookies", response.Code)
	}

	a.keys = workingKeys
	response = callAuth(a, http.MethodGet, "/auth/session", "", cookie, "")
	if response.Code != http.StatusOK {
		t.Fatalf("existing session after JWKS recovery returned HTTP %d, want 200", response.Code)
	}
}

// TestResourceReadIssuerFailureHasOneSafeDiagnostic checks the final response
// boundary retains dependency metadata without exposing private state.
func TestResourceReadIssuerFailureHasOneSafeDiagnostic(t *testing.T) {
	var (
		a, authority = fixtureRuntime(t)
		cookie       = loginFixture(t, a, authority)
		path         = captureSessionDiagnostics(t)
		fault        = &rotationCommitFailureHook{}
	)
	a.store.db.AddHook(fault)
	base := a.http.Transport
	a.http.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		response, err := base.RoundTrip(request)
		if err == nil && request.URL.Path == "/api/my-account/organization-identity" {
			fault.armed.Store(true)
		}
		return response, err
	})
	response := callAuth(a, http.MethodGet, "/auth/session", "", cookie, "")
	if response.Code != http.StatusServiceUnavailable || !fault.failed.Load() {
		t.Fatalf("issuer dependency failure HTTP %d, injected=%t", response.Code, fault.failed.Load())
	}
	var (
		entries  = readSessionDiagnostics(t, path, cookie.Value, a.store.prefix, "synthetic rotation fixture commit failure")
		rejected = 0
	)
	for _, entry := range entries {
		if entry["msg"] != "logtobff.request.rejected" {
			continue
		}
		rejected++
		if entry["status"] != float64(http.StatusServiceUnavailable) || entry["reason"] != "identity_provider_unavailable" || entry["dependency"] != "redis" || entry["redis_operation"] != "lease_acquire" || entry["failure_kind"] != "unknown" {
			t.Errorf("issuer failure lost bounded dependency diagnostics: %v", entry)
		}
	}
	if rejected != 1 {
		t.Fatalf("issuer failure emitted %d rejection records, want one", rejected)
	}
}
