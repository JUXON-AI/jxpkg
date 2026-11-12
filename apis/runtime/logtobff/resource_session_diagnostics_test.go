package logtobff

import (
	"net/http"
	"testing"
)

// TestResourceReadIssuerFailureHasOneSafeDiagnostic checks the final response
// boundary retains dependency metadata without exposing private state.
func TestResourceReadIssuerFailureHasOneSafeDiagnostic(t *testing.T) {
	a, authority := fixtureRuntime(t)
	cookie := loginFixture(t, a, authority)
	path := captureSessionDiagnostics(t)
	fault := &rotationCommitFailureHook{}
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
	entries := readSessionDiagnostics(t, path, cookie.Value, a.store.prefix, "synthetic rotation fixture commit failure")
	rejected := 0
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
