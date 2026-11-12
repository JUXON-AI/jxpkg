package logtobff

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/logto-io/go/v2/client"
)

// Only the first API-token signature check is delayed. Resource issuance and
// its Redis commit stay real; a concurrent request uses the original verifier.
type resourceGenerationSignatureGate struct {
	base    signatureVerifier
	blocked atomic.Bool
	entered chan string
	release <-chan struct{}
}

// VerifySignature delays the first synthetic signature check and delegates all
// later checks to the fixture's real verifier.
func (g *resourceGenerationSignatureGate) VerifySignature(ctx context.Context, raw string) ([]byte, error) {
	if !g.blocked.CompareAndSwap(false, true) {
		return g.base.VerifySignature(ctx, raw)
	}
	select {
	case g.entered <- raw:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	select {
	case <-g.release:
		return nil, errors.New("synthetic resource signature rejection")
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// TestResourceVerification401UsesIssuedSDKGeneration checks destructive fencing.
// Losing the issued-generation snapshot would turn the first case into 409.
// Ignoring a later committed SDK generation would delete the second case.
func TestResourceVerification401UsesIssuedSDKGeneration(t *testing.T) {
	for _, route := range []string{"session", "protected"} {
		t.Run(route, func(t *testing.T) {
			for _, concurrent := range []bool{false, true} {
				name := "same_generation"
				if concurrent {
					name = "new_generation"
				}
				t.Run(name, func(t *testing.T) {
					var (
						a, authority  = fixtureRuntime(t)
						cookie        = loginFixture(t, a, authority)
						original      = renewalReadSession(t, a, cookie)
						businessCalls atomic.Int64
						router        = gin.New()
					)
					router.POST("/protected", a.Require("manage:credits"), func(c *gin.Context) {
						businessCalls.Add(1)
						c.Status(http.StatusNoContent)
					})
					var (
						request = func() *httptest.ResponseRecorder {
							if route == "session" {
								return callAuth(a, http.MethodGet, "/auth/session", "", cookie, "")
							}
							r := httptest.NewRequest(http.MethodPost, a.config.Origin+"/protected", nil)
							r.AddCookie(cookie)
							r.Header.Set("Origin", a.config.Origin)
							r.Header.Set("X-CSRF-Token", original.CSRF)
							r.Header.Set("X-Organization-ID", "org-one")
							r.Header.Set("X-Organization-Revision", "1")
							response := httptest.NewRecorder()
							router.ServeHTTP(response, r)
							return response
						}
						release     = make(chan struct{})
						releaseOnce sync.Once
						unblock     = func() { releaseOnce.Do(func() { close(release) }) }
						gate        = &resourceGenerationSignatureGate{base: a.keys, entered: make(chan string, 1), release: release}
					)
					a.keys = gate
					pending := make(chan *httptest.ResponseRecorder, 1)
					go func() {
						defer close(pending)
						pending <- request()
					}()
					defer func() {
						unblock()
						for range pending {
						}
					}()
					var issuedRaw string
					select {
					case issuedRaw = <-gate.entered:
					case <-time.After(3 * time.Second):
						t.Fatal("resource request did not reach post-issuance signature verification")
					}
					issued := renewalReadSession(t, a, cookie)
					// This observes the committed mint before permitting the 401. A
					// rejection during the earlier identity GET cannot satisfy it.
					assertResourceGenerationMint(t, original, issued, issuedRaw)
					var latest *session
					if concurrent {
						response := callAuth(a, http.MethodGet, "/auth/session", "", cookie, "")
						if response.Code != http.StatusOK {
							t.Fatalf("concurrent real resource request HTTP %d, want 200", response.Code)
						}
						latest = renewalReadSession(t, a, cookie)
						if latest.SDK[client.StorageKeyRefreshToken] == issued.SDK[client.StorageKeyRefreshToken] {
							t.Fatal("concurrent resource request did not persist a newer SDK generation")
						}
					}
					unblock()
					response := <-pending
					if businessCalls.Load() != 0 {
						t.Fatal("rejected resource verification reached the protected business handler")
					}
					if concurrent {
						if response.Code != http.StatusConflict || len(response.Result().Cookies()) != 0 {
							t.Fatalf("late stale verification HTTP %d, want 409 without cookie changes", response.Code)
						}
						stored := renewalReadSession(t, a, cookie)
						if !maps.Equal(stored.SDK, latest.SDK) || stored.CSRF != latest.CSRF || stored.Organization != latest.Organization || stored.Revision != latest.Revision {
							t.Fatal("late resource 401 removed or rewound the newer committed SDK generation")
						}
						return
					}
					if response.Code != http.StatusUnauthorized {
						t.Fatalf("current issued-generation verification HTTP %d, want 401", response.Code)
					}
					cleared := false
					for _, candidate := range response.Result().Cookies() {
						if candidate.Name == a.config.CookieName && candidate.MaxAge < 0 {
							cleared = true
						}
					}
					if !cleared {
						t.Fatal("current issued-generation rejection did not clear the browser cookie")
					}
					_, owner, err := a.store.acquire(context.Background(), cookie.Value)
					if err == nil {
						a.store.release(context.Background(), cookie.Value, owner)
					}
					if !errors.Is(err, _errMissing) {
						t.Fatal("current issued-generation rejection retained Redis session state")
					}
				})
			}
		})
	}
}

func assertResourceGenerationMint(t *testing.T, before, issued *session, raw string) {
	t.Helper()
	if raw == "" || maps.Equal(before.SDK, issued.SDK) || before.SDK[client.StorageKeyRefreshToken] == issued.SDK[client.StorageKeyRefreshToken] {
		t.Fatal("signature barrier was reached without a newly committed resource SDK generation")
	}
	var tokens map[string]client.AccessToken
	if json.Unmarshal([]byte(issued.SDK[client.StorageKeyAccessTokenMap]), &tokens) != nil {
		t.Fatal("issued SDK has an invalid persisted access-token map")
	}
	for key, token := range tokens {
		if key != "@" && token.Token == raw {
			return
		}
	}
	t.Fatal("signature barrier credential was not present in the committed resource SDK")
}
