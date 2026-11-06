package credits

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/JUXON-AI/jxpkg/identity"
)

func TestAcquireDefaultForwardsDisplayNamesOnlyForTargetSubject(t *testing.T) {
	member := Subject{OrganizationID: "org-a", UserID: "user-a"}
	ctx, err := identity.WithDisplayNames(context.Background(), member, identity.DisplayNames{
		Username:         "user-a",
		OrganizationName: "Company A",
	})
	if err != nil {
		t.Fatal(err)
	}

	calls := 0
	client, err := NewClientWithTransport(Config{Endpoint: "https://credits.example.com"}, transportFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if len(r.Header.Values("Authorization")) != 0 {
			t.Fatal("display metadata produced Authorization")
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		switch calls {
		case 1:
			if string(body) != `{"organization_id":"org-a","user_id":"user-a","display_names":{"username":"user-a","organization_name":"Company A"}}` {
				t.Fatalf("matching subject body = %s", body)
			}
		case 2:
			if string(body) != `{"organization_id":"org-b","user_id":"user-b"}` {
				t.Fatalf("cross-subject body = %s", body)
			}
		default:
			t.Fatalf("unexpected request %d", calls)
		}
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(`{"base_url":"https://models.example.com/v1","api_key":"employee-default"}`))}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := client.AcquireDefault(ctx, member); err != nil {
		t.Fatal(err)
	}
	if _, err := client.AcquireDefault(ctx, Subject{OrganizationID: "org-b", UserID: "user-b"}); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("calls = %d", calls)
	}
}
