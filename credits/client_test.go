package credits

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/JUXON-AI/jxpkg/requestid"
)

type transportFunc func(*http.Request) (*http.Response, error)

func (f transportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestAcquireDefaultProtocol(t *testing.T) {
	for _, tc := range []struct {
		name, body, media string
		status            int
		want              error
	}{
		{"valid", `{"base_url":"https://models.example.com/v1","api_key":"employee-default"}`, "application/json", 200, nil},
		{"denied", `{"api_key":"secret"}`, "application/json", 403, ErrDenied},
		{"body_code", `{"code":403,"base_url":"https://models.example.com/v1","api_key":"secret"}`, "application/json", 200, ErrUnavailable},
		{"html", `<html>secret</html>`, "text/html", 200, ErrUnavailable},
		{"trailing", `{"base_url":"https://models.example.com/v1","api_key":"secret"} {}`, "application/json", 200, ErrUnavailable},
		{"insecure_model", `{"base_url":"http://models.example.com/v1","api_key":"secret"}`, "application/json", 200, ErrUnavailable},
		{"oversize", strings.Repeat("x", 16385), "application/json", 200, ErrUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			client, err := NewClientWithTransport(Config{Endpoint: "https://credits.example.com"}, transportFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.URL.Path != DefaultPath || r.Method != "POST" || r.Header.Get("Authorization") != "" {
					t.Fatal("unexpected credential request")
				}
				body, _ := io.ReadAll(r.Body)
				if string(body) != `{"company_id":2,"uin":3}` {
					t.Fatalf("subject: %s", body)
				}
				return &http.Response{StatusCode: tc.status, Header: http.Header{"Content-Type": []string{tc.media}}, Body: io.NopCloser(strings.NewReader(tc.body))}, nil
			}))
			if err != nil {
				t.Fatal(err)
			}
			connection, err := client.AcquireDefault(context.Background(), Subject{CompanyID: 2, UIN: 3})
			if !errors.Is(err, tc.want) || calls != 1 {
				t.Fatalf("calls=%d err=%v", calls, err)
			}
			if err != nil && connection.APIKey != "" {
				t.Fatal("credential returned on error")
			}
		})
	}
}

func TestAcquirePreservesExistingRequestID(t *testing.T) {
	c, err := NewClientWithTransport(Config{Endpoint: "https://credits.example.com"}, transportFunc(func(r *http.Request) (*http.Response, error) {
		if r.Header.Get("X-Request-Id") != "original-request" {
			t.Fatal("lost request ID")
		}
		return &http.Response{StatusCode: 403, Body: io.NopCloser(strings.NewReader(""))}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.AcquireDefault(requestid.WithContext(context.Background(), "original-request"), Subject{CompanyID: 2, UIN: 3})
	if !errors.Is(err, ErrDenied) {
		t.Fatal(err)
	}
}

func TestInvalidInputAndCancellationDoNotCallTransport(t *testing.T) {
	tr := transportFunc(func(*http.Request) (*http.Response, error) { t.Fatal("unexpected transport"); return nil, nil })
	for _, endpoint := range []string{"http://credits.example.com", "https://name:secret@credits.example.com", "https://credits.example.com/path", "https://credits.example.com?token=secret"} {
		if _, err := NewClientWithTransport(Config{Endpoint: endpoint}, tr); err == nil {
			t.Fatal("invalid endpoint accepted")
		}
	}
	c, err := NewClientWithTransport(Config{Endpoint: "https://credits.example.com", Timeout: time.Second}, tr)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = c.AcquireDefault(context.Background(), Subject{}); !errors.Is(err, ErrDenied) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = c.AcquireDefault(ctx, Subject{CompanyID: 2, UIN: 3}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestRedirectDoesNotLeakSubject(t *testing.T) {
	calls := 0
	c, err := NewClientWithTransport(Config{Endpoint: "https://credits.example.com"}, transportFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: 307, Header: http.Header{"Location": []string{"https://other.example.com"}}, Body: io.NopCloser(strings.NewReader(""))}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = c.AcquireDefault(context.Background(), Subject{CompanyID: 2, UIN: 3}); !errors.Is(err, ErrUnavailable) || calls != 1 {
		t.Fatalf("calls=%d err=%v", calls, err)
	}
}
