package logtobff

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestDiscoveryCacheIsPublicBoundedAndDoesNotCacheAuthorization(t *testing.T) {
	var calls atomic.Int32
	var unavailable atomic.Bool
	var oversized atomic.Bool
	var invalid atomic.Bool
	var upstream *httptest.Server
	upstream = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if unavailable.Load() {
			w.WriteHeader(503)
			return
		}
		if invalid.Load() {
			if _, err := io.WriteString(w, `{}`); err != nil {
				t.Error("fixture response failed")
			}
			return
		}
		metadata := map[string]string{"issuer": upstream.URL + "/oidc", "authorization_endpoint": upstream.URL + "/oidc/auth", "token_endpoint": upstream.URL + "/oidc/token", "userinfo_endpoint": upstream.URL + "/oidc/me", "jwks_uri": upstream.URL + "/oidc/jwks"}
		large := oversized.Load()
		if large {
			metadata["padding"] = strings.Repeat("x", (1<<20)+1)
		}
		// 超限读取可提前关闭连接；只把普通响应写失败当成 fixture 故障。
		if err := json.NewEncoder(w).Encode(metadata); err != nil && !large {
			t.Error("fixture response failed")
		}
	}))
	defer upstream.Close()
	cache := &discoveryTransport{base: http.DefaultTransport, endpoint: upstream.URL + "/discovery"}
	client := &http.Client{Transport: cache, Timeout: 5 * time.Second}
	get := func(path, auth string) int {
		t.Helper()
		r, err := http.NewRequest("GET", upstream.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Authorization", auth)
		response, err := client.Do(r)
		if err != nil {
			t.Fatal("fixture request failed")
		}
		if _, err := io.Copy(io.Discard, response.Body); err != nil {
			t.Error("fixture read failed")
		}
		if err := response.Body.Close(); err != nil {
			t.Error("fixture close failed")
		}
		return response.StatusCode
	}
	if get("/discovery", "") != 200 || get("/discovery", "") != 200 || calls.Load() != 1 {
		t.Fatal("public discovery not reused")
	}
	get("/discovery", "Bearer synthetic-only")
	get("/oidc/jwks", "")
	get("/oidc/jwks", "")
	get("/api/my-account/organization-identity", "")
	get("/api/my-account/organization-identity", "")
	if calls.Load() != 6 {
		t.Fatal("authorization/JWKS response was cached")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r, err := http.NewRequestWithContext(ctx, "GET", cache.endpoint, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Do(r); err == nil {
		t.Fatal("cache ignored cancellation")
	}
	cache.mu.Lock()
	cache.until = time.Now().Add(-time.Second)
	cache.mu.Unlock()
	unavailable.Store(true)
	if get("/discovery", "") != 503 {
		t.Fatal("expired document hid an upstream outage")
	}
	unavailable.Store(false)
	oversized.Store(true)
	r, err = http.NewRequest("GET", cache.endpoint, nil)
	if err != nil {
		t.Fatal(err)
	}
	if response, err := client.Do(r); err == nil {
		if closeErr := response.Body.Close(); closeErr != nil {
			t.Error(closeErr)
		}
		t.Fatal("oversized document accepted")
	}
	oversized.Store(false)
	invalid.Store(true)
	if response, err := client.Do(r); err == nil {
		if closeErr := response.Body.Close(); closeErr != nil {
			t.Error(closeErr)
		}
		t.Fatal("semantically invalid discovery cached")
	}
	invalid.Store(false)
	if get("/discovery", "") != 200 {
		t.Fatal("invalid document prevented immediate recovery")
	}
}
