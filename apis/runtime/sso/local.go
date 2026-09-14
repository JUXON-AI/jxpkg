package sso

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/JUXON-AI/jxpkg/apis/runtime/auth"
	"github.com/JUXON-AI/jxpkg/apis/runtime/middleware"
	"github.com/JUXON-AI/jxpkg/apis/runtime/server"
	"github.com/gin-gonic/gin"
)

const (
	localIdentityHeader       = "X-JX-Dev-UIN"
	localSessionID            = "active"
	localCookieName           = "__Host-jx_dev_session"
	localSessionTTL           = 12 * time.Hour
	localCompanyIdentityLimit = 256
)

// DevIdentity is the complete local development principal. Its zero value
// leaves Runtime mode selection unchanged. DevIdentity implements pflag.Value,
// so applications can bind it directly to a --dev flag.
type DevIdentity struct {
	UserID    uint `json:"user_id"`
	UIN       uint `json:"uin"`
	CompanyID uint `json:"company_id"`
}

// Set parses user_id:uin:company_id without partially updating the receiver.
func (identity *DevIdentity) Set(raw string) error {
	if identity == nil {
		return errors.New("development identity is nil")
	}
	parts := strings.Split(raw, ":")
	if len(parts) != 3 {
		return errors.New("expected user_id:uin:company_id")
	}
	values := make([]uint, len(parts))
	for index, part := range parts {
		value, err := strconv.ParseUint(part, 10, strconv.IntSize)
		if err != nil || value == 0 {
			return errors.New("identity IDs must be positive decimal integers")
		}
		values[index] = uint(value)
	}
	*identity = DevIdentity{UserID: values[0], UIN: values[1], CompanyID: values[2]}
	return nil
}

// String returns the flag representation, or an empty string when disabled.
func (identity DevIdentity) String() string {
	if identity.isZero() {
		return ""
	}
	return fmt.Sprintf("%d:%d:%d", identity.UserID, identity.UIN, identity.CompanyID)
}

// Type describes the value accepted by pflag and Cobra.
func (DevIdentity) Type() string { return "user_id:uin:company_id" }

func (identity DevIdentity) isZero() bool {
	return identity.UserID == 0 && identity.UIN == 0 && identity.CompanyID == 0
}

func (identity DevIdentity) valid() bool {
	return identity.UserID > 0 && identity.UIN > 0 && identity.CompanyID > 0
}

// localResolver turns the single local identity into the existing Session and
// company-directory contracts used by business services.
type localResolver struct {
	identity  DevIdentity
	service   string
	csrfToken string
	clock     func() time.Time
}

var (
	_ auth.SessionResolver         = (*localResolver)(nil)
	_ auth.CompanyIdentityResolver = (*localResolver)(nil)
)

func loadLocalEnv(getenv func(string) string, prefix string, options runtimeOptions) (*Runtime, error) {
	if strings.TrimSpace(getenv("KUBERNETES_SERVICE_HOST")) != "" {
		return nil, fmt.Errorf("%w: local SSO is unavailable in Kubernetes", auth.ErrAuthBackendUnavailable)
	}
	httpAddress, err := localHTTPAddress(getenv(env(prefix, "HTTP_ADDR")), options.httpAddress)
	if err != nil {
		return nil, err
	}
	origin := getenv(env(prefix, "EXTERNAL_ORIGIN"))
	service := getenv(env(prefix, "SESSION_RESOLVER_SERVICE"))
	if options.devIdentity != nil {
		if origin == "" {
			origin = "http://localhost:5173"
		}
		if service == "" {
			service = strings.ToLower(prefix)
		}
	}
	if !validLocalOrigin(origin) || !validLocalService(service) {
		return nil, fmt.Errorf("%w: invalid local SSO environment", auth.ErrAuthBackendUnavailable)
	}
	identity := DevIdentity{}
	if options.devIdentity != nil {
		identity = *options.devIdentity
	} else {
		authFile := getenv(env(prefix, "SSO_DEV_AUTH_FILE"))
		if authFile == "" {
			authFile = ".authjson"
		}
		identity, err = loadLocalIdentity(authFile)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", auth.ErrAuthBackendUnavailable, err)
		}
	}
	csrfToken, err := randomLocalValue()
	if err != nil {
		return nil, fmt.Errorf("%w: initialize local SSO", auth.ErrAuthBackendUnavailable)
	}
	resolver := &localResolver{identity: identity, service: service, csrfToken: csrfToken, clock: time.Now}
	hosts := localHosts(httpAddress, origin)
	bindings := make([]middleware.BrowserSessionBinding, 0, len(hosts))
	for host, externalOrigin := range hosts {
		bindings = append(bindings, middleware.BrowserSessionBinding{
			Host: host, Service: service, CookieName: localCookieName, ExternalOrigin: externalOrigin,
		})
	}
	browserSession, err := server.NewBrowserSessionOption(middleware.BrowserSessionOptions{Bindings: bindings, Resolver: resolver})
	if err != nil {
		return nil, fmt.Errorf("%w: configure local SSO middleware", auth.ErrAuthBackendUnavailable)
	}
	cors, err := middleware.NewCORS(middleware.CORSOptions{ExternalOrigin: origin})
	if err != nil {
		return nil, fmt.Errorf("%w: configure local SSO CORS", auth.ErrAuthBackendUnavailable)
	}
	routerOption := func(router *server.Router) {
		server.WithCORS(cors)(router)
		server.WithMiddleware(resolver.injectLocalIdentity)(router)
		browserSession(router)
		router.GinEngine().GET("/auth/session", resolver.session)
	}
	return &Runtime{httpAddress: httpAddress, origin: origin, resolver: resolver, routerOption: routerOption}, nil
}

func loadLocalIdentity(path string) (DevIdentity, error) {
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := writeLocalIdentityTemplate(path); err != nil {
			return DevIdentity{}, errors.New("create .authjson template")
		}
		return DevIdentity{}, fmt.Errorf("created %s; fill user_id, uin and company_id, then restart", path)
	}
	if err != nil {
		return DevIdentity{}, errors.New("read .authjson")
	}
	defer file.Close()
	var identity DevIdentity
	decoder := json.NewDecoder(io.LimitReader(file, 4096))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&identity); err != nil || decoder.Decode(&struct{}{}) != io.EOF || !identity.valid() {
		return DevIdentity{}, errors.New(".authjson must contain positive user_id, uin and company_id values")
	}
	return identity, nil
}

func writeLocalIdentityTemplate(path string) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	encodeErr := encoder.Encode(DevIdentity{})
	closeErr := file.Close()
	if encodeErr != nil {
		return encodeErr
	}
	return closeErr
}

func (resolver *localResolver) injectLocalIdentity(ctx *gin.Context) {
	if !localRequest(ctx.Request) {
		ctx.AbortWithStatus(http.StatusForbidden)
		return
	}
	values := ctx.Request.Header.Values(localIdentityHeader)
	if len(values) == 0 {
		ctx.Next()
		return
	}
	validIdentity := len(values) == 1 &&
		(values[0] == localSessionID || values[0] == strconv.FormatUint(uint64(resolver.identity.UIN), 10))
	if !validIdentity ||
		len(ctx.Request.Header.Values("Authorization")) != 0 || hasCookie(ctx.Request, localCookieName) {
		ctx.AbortWithStatus(http.StatusUnauthorized)
		return
	}
	ctx.Request.AddCookie(&http.Cookie{Name: localCookieName, Value: localSessionID})
	if ctx.Request.Method != http.MethodGet && ctx.Request.Method != http.MethodHead && ctx.Request.Method != http.MethodOptions {
		if len(ctx.Request.Header.Values("Origin")) == 0 {
			ctx.Request.Header.Set("Origin", "http://"+ctx.Request.Host)
		}
		if len(ctx.Request.Header.Values(middleware.DefaultCSRFHeader)) == 0 {
			ctx.Request.Header.Set(middleware.DefaultCSRFHeader, resolver.csrfToken)
		}
	}
	ctx.Next()
}

func (resolver *localResolver) session(ctx *gin.Context) {
	if len(ctx.Request.Header.Values(localIdentityHeader)) != 1 || !hasCookie(ctx.Request, localCookieName) {
		ctx.AbortWithStatus(http.StatusUnauthorized)
		return
	}
	now := resolver.clock().UTC()
	expiresAt := now.Add(localSessionTTL).Unix()
	ctx.Header("Cache-Control", "no-store")
	ctx.JSON(http.StatusOK, gin.H{
		"authenticated": true,
		"user_id":       resolver.identity.UserID,
		"identity": gin.H{
			"uin":          resolver.identity.UIN,
			"company_id":   resolver.identity.CompanyID,
			"company_name": fmt.Sprintf("Dev Company %d", resolver.identity.CompanyID),
			"username":     fmt.Sprintf("Dev User %d", resolver.identity.UserID),
			"avatar_url":   "",
		},
		"idle_expires_at":     expiresAt,
		"absolute_expires_at": expiresAt,
		"csrf_token":          resolver.csrfToken,
	})
}

// Resolve maps the private synthetic development cookie to the configured
// identity while preserving the production browser middleware contract.
func (resolver *localResolver) Resolve(_ context.Context, request auth.SessionResolveRequest) (*auth.SessionPrincipal, error) {
	if request.Service != resolver.service || request.SessionID != localSessionID {
		return nil, auth.ErrInvalidCredential
	}
	now := resolver.clock().UTC()
	expiresAt := now.Add(localSessionTTL).Unix()
	digest := sha256.Sum256([]byte(resolver.csrfToken))
	return &auth.SessionPrincipal{
		Claims: auth.UserClaims{
			UserID: resolver.identity.UserID, UIN: resolver.identity.UIN, CompanyID: resolver.identity.CompanyID,
			MembershipEpoch: 1, LoginWay: auth.LoginWayEmail,
		},
		Host: request.Host, ClientID: resolver.service, SessionVersion: 1,
		AuthenticatedAt: now.Unix(), IdleExpiresAt: expiresAt, AbsoluteExpiresAt: expiresAt,
		CSRFTokenHash: digest[:],
	}, nil
}

// ResolveCompanyIdentities exposes only the configured local identity through
// the same directory contract used by Account mode.
func (resolver *localResolver) ResolveCompanyIdentities(_ context.Context, request auth.CompanyIdentityResolveRequest) ([]auth.CompanyIdentity, error) {
	if request.Service != resolver.service || request.CompanyID == 0 || len(request.UINs) == 0 || len(request.UINs) > localCompanyIdentityLimit {
		return nil, auth.ErrInvalidCredential
	}
	seen := make(map[uint]struct{}, len(request.UINs))
	result := make([]auth.CompanyIdentity, 0, 1)
	for _, uin := range request.UINs {
		if uin == 0 {
			return nil, auth.ErrInvalidCredential
		}
		if _, duplicate := seen[uin]; duplicate {
			return nil, auth.ErrInvalidCredential
		}
		seen[uin] = struct{}{}
		if uin == resolver.identity.UIN && request.CompanyID == resolver.identity.CompanyID {
			result = append(result, auth.CompanyIdentity{
				UIN: uin, MembershipEpoch: 1, Username: fmt.Sprintf("Dev User %d", resolver.identity.UserID),
				Status: auth.CompanyIdentityStatusActive,
			})
		}
	}
	return result, nil
}

func validLocalHTTPAddress(address string) bool {
	host, port, err := net.SplitHostPort(address)
	portNumber, portErr := strconv.Atoi(port)
	return err == nil && localHostname(host) && portErr == nil && portNumber > 0 && portNumber <= 65535
}

func localHTTPAddress(explicit, configured string) (string, error) {
	if explicit != "" {
		if validLocalHTTPAddress(explicit) {
			return explicit, nil
		}
		return "", fmt.Errorf("%w: invalid local HTTP address", auth.ErrAuthBackendUnavailable)
	}
	host, port, err := net.SplitHostPort(configured)
	portNumber, portErr := strconv.Atoi(port)
	if err != nil || portErr != nil || portNumber <= 0 || portNumber > 65535 {
		return "", fmt.Errorf("%w: invalid local HTTP address", auth.ErrAuthBackendUnavailable)
	}
	if host == "" {
		return net.JoinHostPort("127.0.0.1", port), nil
	}
	ip := net.ParseIP(host)
	if ip != nil && ip.IsUnspecified() {
		return net.JoinHostPort("127.0.0.1", port), nil
	}
	if !localHostname(host) {
		return "", fmt.Errorf("%w: local HTTP address must use loopback", auth.ErrAuthBackendUnavailable)
	}
	return configured, nil
}

func accountHTTPAddress(explicit, configured string) (string, error) {
	address := explicit
	if address == "" {
		address = configured
	}
	if address == "" {
		return "", nil
	}
	if address != strings.TrimSpace(address) {
		return "", fmt.Errorf("%w: invalid application HTTP address", auth.ErrAuthBackendUnavailable)
	}
	_, port, err := net.SplitHostPort(address)
	portNumber, portErr := strconv.Atoi(port)
	if err != nil || portErr != nil || portNumber <= 0 || portNumber > 65535 {
		return "", fmt.Errorf("%w: invalid application HTTP address", auth.ErrAuthBackendUnavailable)
	}
	return address, nil
}

func validLocalOrigin(origin string) bool {
	parsed, err := url.Parse(origin)
	return err == nil && parsed.Scheme == "http" && parsed.Host != "" && parsed.User == nil && parsed.Path == "" &&
		parsed.RawQuery == "" && parsed.Fragment == "" && localHostname(parsed.Hostname())
}

func validLocalService(service string) bool {
	return service != "" && service == strings.TrimSpace(service) && !strings.ContainsAny(service, " /\\")
}

func localHosts(httpAddress, origin string) map[string]string {
	parsedOrigin, _ := url.Parse(origin)
	hosts := map[string]string{parsedOrigin.Host: origin}
	if _, exists := hosts[httpAddress]; !exists {
		hosts[httpAddress] = "http://" + httpAddress
	}
	return hosts
}

func localHostname(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func localRequest(request *http.Request) bool {
	host, _, err := net.SplitHostPort(request.RemoteAddr)
	parsed, parseErr := url.Parse("http://" + request.Host)
	remoteIP := net.ParseIP(host)
	return err == nil && parseErr == nil && remoteIP != nil && remoteIP.IsLoopback() && localHostname(parsed.Hostname()) &&
		len(request.Header.Values("Forwarded")) == 0 && len(request.Header.Values("X-Forwarded-For")) == 0 &&
		len(request.Header.Values("X-Forwarded-Host")) == 0 && len(request.Header.Values("X-Forwarded-Proto")) == 0
}

func hasCookie(request *http.Request, name string) bool {
	for _, cookie := range request.Cookies() {
		if cookie.Name == name {
			return true
		}
	}
	return false
}

func randomLocalValue() (string, error) {
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}
