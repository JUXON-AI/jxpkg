package server

import (
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/JUXON-AI/jxpkg/lifecycle"
	"github.com/gin-gonic/gin"
)

func TestRouterCloseWaitsForInflightRequest(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := NewRouter("/v1/")
	router.lc = lifecycle.New()

	requestStarted := make(chan struct{})
	releaseRequest := make(chan struct{})
	router.GinEngine().GET("/slow", func(ctx *gin.Context) {
		close(requestStarted)
		<-releaseRequest
		ctx.String(http.StatusOK, "finished")
	})

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	if err := router.Run(listener); err != nil {
		t.Fatalf("run: %v", err)
	}

	responseCh := make(chan *http.Response, 1)
	errorCh := make(chan error, 1)
	go func() {
		response, requestErr := http.Get("http://" + listener.Addr().String() + "/slow")
		if requestErr != nil {
			errorCh <- requestErr
			return
		}
		responseCh <- response
	}()

	select {
	case <-requestStarted:
	case err := <-errorCh:
		t.Fatalf("request before shutdown: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("request did not reach handler")
	}

	closeCh := make(chan error, 1)
	go func() { closeCh <- router.Close() }()
	select {
	case err := <-closeCh:
		t.Fatalf("Close returned before active request finished: %v", err)
	case <-time.After(100 * time.Millisecond):
	}

	close(releaseRequest)
	select {
	case err := <-errorCh:
		t.Fatalf("in-flight request was interrupted: %v", err)
	case response := <-responseCh:
		defer response.Body.Close()
		body, readErr := io.ReadAll(response.Body)
		if readErr != nil {
			t.Fatalf("read response: %v", readErr)
		}
		if response.StatusCode != http.StatusOK || string(body) != "finished" {
			t.Fatalf("unexpected response: status=%d body=%q", response.StatusCode, body)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("in-flight request did not complete")
	}

	select {
	case err := <-closeCh:
		if err != nil {
			t.Fatalf("close: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not return after request completed")
	}
}

func TestRouterRunRejectsInvalidReuse(t *testing.T) {
	router := NewRouter("/v1/")
	router.lc = lifecycle.New()
	if err := router.Run(nil); err == nil {
		t.Fatal("Run(nil) unexpectedly succeeded")
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	if err := router.Run(listener); err != nil {
		t.Fatalf("first Run: %v", err)
	}
	if err := router.Run(listener); err == nil {
		t.Fatal("second Run unexpectedly succeeded")
	}
	if err := router.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}
