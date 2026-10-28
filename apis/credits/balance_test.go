package credits

import (
	"context"
	"net/http"
	"testing"

	"github.com/JUXON-AI/jxpkg/apis/runtime/server"
	clientcredits "github.com/JUXON-AI/jxpkg/credits"
)

type balanceTransport func(*http.Request) (*http.Response, error)

func (f balanceTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestRegistrationRequiresLogtoRuntime(t *testing.T) {
	router := server.NewRouter("/v1/")
	client, err := clientcredits.NewClientWithTransport(clientcredits.Config{Endpoint: "https://credits.example.com"}, balanceTransport(func(*http.Request) (*http.Response, error) {
		t.Error("unexpected remote request")
		return nil, context.DeadlineExceeded
	}))
	if err != nil {
		t.Fatal(err)
	}
	if RegisterBrowserBalance(router, "jxagent", client, nil) == nil || len(router.GinEngine().Routes()) != 0 {
		t.Fatal("unconfigured Logto authentication registered a route")
	}
}
