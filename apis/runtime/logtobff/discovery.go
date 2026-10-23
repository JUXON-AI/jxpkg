package logtobff

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// discoveryTransport 缓存单个固定公开文档，不缓存用户、授权或令牌响应。
// JWKS 仍由验签器处理轮换，避免 HTTP 缓存拦截未知 kid 的重新获取。
type discoveryTransport struct {
	base     http.RoundTripper
	endpoint string
	mu       sync.Mutex
	document []byte
	until    time.Time
}

func (t *discoveryTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Method != http.MethodGet || r.URL.String() != t.endpoint || r.Header.Get("Authorization") != "" {
		return t.base.RoundTrip(r)
	}
	if err := r.Context().Err(); err != nil {
		return nil, err
	}
	t.mu.Lock()
	data, until := t.document, t.until
	t.mu.Unlock()
	if len(data) > 0 && time.Now().Before(until) {
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(bytes.NewReader(data)), Request: r}, nil
	}
	response, err := t.base.RoundTrip(r)
	if err != nil || response.StatusCode != http.StatusOK {
		return response, err
	}
	data, readErr := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil {
		return nil, errors.Join(readErr, closeErr)
	}
	if len(data) > 1<<20 {
		return nil, errors.New("identity discovery too large")
	}
	response.Body = io.NopCloser(bytes.NewReader(data))
	var metadata struct {
		Issuer        string `json:"issuer"`
		Authorization string `json:"authorization_endpoint"`
		Token         string `json:"token_endpoint"`
		UserInfo      string `json:"userinfo_endpoint"`
		JWKS          string `json:"jwks_uri"`
	}
	registered, err := url.Parse(t.endpoint)
	if err != nil || registered.Host == "" {
		return nil, errors.New("invalid discovery registration")
	}
	origin := registered.Scheme + "://" + registered.Host
	if json.Unmarshal(data, &metadata) != nil || metadata.Issuer != origin+"/oidc" {
		return nil, errors.New("invalid identity discovery")
	}
	for _, raw := range []string{metadata.Authorization, metadata.Token, metadata.UserInfo, metadata.JWKS} {
		endpoint, err := url.Parse(raw)
		if err != nil || endpoint.Scheme+"://"+endpoint.Host != origin || endpoint.User != nil || endpoint.Fragment != "" || len(raw) > 2048 {
			return nil, errors.New("unregistered discovery endpoint")
		}
	}
	t.mu.Lock()
	t.document, t.until = data, time.Now().Add(time.Hour)
	t.mu.Unlock()
	return response, nil
}
