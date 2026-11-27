package logtobff

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func TestVerifyCurrentPasswordRequiresBrowserCapability(t *testing.T) {
	ctx := context.Background()
	if err := VerifyCurrentPassword(ctx, "fixture"); !errors.Is(err, ErrAuthorizationChanged) {
		t.Fatalf("without browser authority: %v", err)
	}
	calls := 0
	ctx = context.WithValue(ctx, passwordVerifierKey{}, func(_ context.Context, password string) error {
		calls++
		if password != "fixture" {
			t.Fatal("credential changed")
		}
		return nil
	})
	if err := VerifyCurrentPassword(ctx, ""); !errors.Is(err, ErrPasswordRejected) || calls != 0 {
		t.Fatalf("empty password: calls=%d err=%v", calls, err)
	}
	if err := VerifyCurrentPassword(ctx, "fixture"); err != nil || calls != 1 {
		t.Fatalf("valid password: calls=%d err=%v", calls, err)
	}
}

func TestVerifyPasswordAtAccount(t *testing.T) {
	for _, tt := range []struct {
		status int
		err    error
	}{
		{http.StatusCreated, nil},
		{http.StatusUnprocessableEntity, ErrPasswordRejected},
		{http.StatusForbidden, ErrUnavailable},
		{http.StatusTooManyRequests, ErrUnavailable},
	} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != accountPasswordVerificationPath || r.Method != http.MethodPost ||
				r.Header.Get("Authorization") != "Bearer synthetic-user-token" {
				t.Error("verification did not use the user token and fixed endpoint")
			}
			var body struct{ Password string }
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Password != "fixture" {
				t.Error("invalid password request")
			}
			w.WriteHeader(tt.status)
			if tt.status == http.StatusCreated {
				_ = json.NewEncoder(w).Encode(map[string]any{"verificationRecordId": "fixture-proof", "expiresAt": time.Now().Add(time.Minute)})
			}
		}))
		a := Runtime{config: Config{Endpoint: server.URL}, http: server.Client()}
		err := a.verifyPasswordAtAccount(context.Background(), "synthetic-user-token", "fixture")
		server.Close()
		if !errors.Is(err, tt.err) {
			t.Errorf("status %d: got %v, want %v", tt.status, err, tt.err)
		}
	}
}

func TestChangePasswordRejectsUnsafeReturn(t *testing.T) {
	a := Runtime{}
	for _, path := range []string{
		"/auth/change-password?return_to=https://elsewhere.invalid",
		"/auth/change-password?return_to=//elsewhere.invalid",
		"/auth/change-password?return_to=/%23/poc/results%3Fsecret%3Dfixture",
		"/auth/change-password?return_to=/&return_to=/",
	} {
		if got := a.changePassword(httptest.NewRequest(http.MethodGet, path, nil), nil); got.status != http.StatusBadRequest {
			t.Errorf("return path should be rejected, status=%d", got.status)
		}
	}
}

func TestPasswordUsesCurrentBrowserSession(t *testing.T) {
	a, f := fixtureRuntime(t)
	cookie := loginFixture(t, a, f)
	csrf := sessionCSRF(t, callAuth(a, http.MethodGet, "/auth/session", "", cookie, ""))
	path := "/auth/change-password?return_to=%2F%23%2Fpoc%2Fme"
	changed := callAuth(a, http.MethodGet, path, "", cookie, "")
	location, err := url.Parse(changed.Header().Get("Location"))
	if err != nil || changed.Code != http.StatusFound || location.Path != "/account/password" ||
		location.Query().Get("redirect") != a.config.Origin+"/#/poc/me" {
		t.Fatalf("change-password redirect: status=%d", changed.Code)
	}
	discovery := a.http.Transport.(*discoveryTransport)
	base := discovery.base
	revoke := false
	discovery.base = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != accountPasswordVerificationPath {
			return base.RoundTrip(r)
		}
		if r.Header.Get("Authorization") != "Bearer opaque-account-access" {
			t.Error("password verification did not use the session's user access token")
		}
		if revoke {
			logout := callAuth(a, http.MethodPost, "/auth/logout", "", cookie, csrf)
			if logout.Code/100 != 2 {
				t.Errorf("fixture logout failed with %d", logout.Code)
			}
		}
		proof, _ := json.Marshal(map[string]any{"verificationRecordId": "fixture-proof", "expiresAt": time.Now().Add(time.Minute)})
		return &http.Response{StatusCode: http.StatusCreated, Body: io.NopCloser(bytes.NewReader(proof)), Header: make(http.Header)}, nil
	})
	router := gin.New()
	router.POST("/protected", a.Require(), func(c *gin.Context) {
		if err := VerifyCurrentPassword(c.Request.Context(), "fixture"); err == nil {
			c.Status(http.StatusNoContent)
		} else {
			c.Status(http.StatusForbidden)
		}
	})
	request := func() int {
		r := httptest.NewRequest(http.MethodPost, a.config.Origin+"/protected", nil)
		r.AddCookie(cookie)
		r.Header.Set("Origin", a.config.Origin)
		r.Header.Set("X-CSRF-Token", csrf)
		r.Header.Set("X-Organization-ID", "org-one")
		r.Header.Set("X-Organization-Revision", "1")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)
		return w.Code
	}
	if got := request(); got != http.StatusNoContent {
		t.Fatalf("current cookie verification returned %d", got)
	}
	revoke = true
	if got := request(); got != http.StatusForbidden {
		t.Fatalf("proof won a race against logout, status=%d", got)
	}
}
