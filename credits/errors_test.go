package credits

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
)

type privateNetworkError struct{}

func (privateNetworkError) Error() string   { return "PRIVATE_CREDENTIAL private.example" }
func (privateNetworkError) Timeout() bool   { return true }
func (privateNetworkError) Temporary() bool { return false }

type failureTransport struct{ cause error }

func (tr failureTransport) RoundTrip(*http.Request) (*http.Response, error) { return nil, tr.cause }

func TestClientAndExecutionRetainSafeErrorChains(t *testing.T) {
	for _, cause := range []error{privateNetworkError{}, context.Canceled, context.DeadlineExceeded} {
		client, err := NewClientWithTransport(Config{Endpoint: "https://private.example"}, failureTransport{cause})
		if err != nil {
			t.Fatal(err)
		}
		subject := Subject{OrganizationID: "org-1", UserID: "user-2"}
		execution, err := NewExecution(subject, client.AcquireDefault)
		if err != nil {
			t.Fatal(err)
		}
		check := func(err error) {
			t.Helper()
			var network net.Error
			if !errors.Is(err, ErrUnavailable) || !errors.Is(err, cause) || !errors.As(err, &network) {
				t.Error("network/sentinel classification lost")
			}
			if _, ok := cause.(net.Error); ok && !network.Timeout() {
				t.Error("network timeout classification lost")
			}
			if outer := fmt.Errorf("caller: %w", err); strings.Contains(outer.Error(), "PRIVATE") || strings.Contains(outer.Error(), "private.example") {
				t.Error("outer error exposed cause")
			}
		}
		_, err = client.AcquireDefault(context.Background(), subject)
		check(err)
		var wait sync.WaitGroup
		for i := 0; i < 4; i++ {
			wait.Add(1)
			go func() { defer wait.Done(); _, err := execution.AcquireDefault(context.Background()); check(err) }()
		}
		wait.Wait()
	}
}
