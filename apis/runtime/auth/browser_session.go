package auth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
)

// SessionResolveRequest 描述业务服务解析浏览器会话所需的最小输入。
type SessionResolveRequest struct {
	// Host 表示经过严格校验的当前请求 Host。
	Host string `json:"host"`

	// Service 表示调用会话解析器的静态服务标识。
	Service string `json:"service"`

	// SessionID 表示当前 Host Cookie 中的原始不透明会话 ID。
	SessionID string `json:"session_id"`
}

// SessionPrincipal 表示会话解析器返回的最小认证主体快照。
type SessionPrincipal struct {
	// Claims 表示会话绑定的用户和当前公司身份。
	Claims UserClaims

	// Host 表示该会话唯一绑定的规范 Host。
	Host string

	// ClientID 表示创建该业务会话的静态客户端标识。
	ClientID string

	// SessionVersion 表示会话撤销与轮换版本。
	SessionVersion uint64

	// AuthenticatedAt 表示中央认证完成的 Unix 时间戳。
	AuthenticatedAt int64

	// IdleExpiresAt 表示会话空闲过期的 Unix 时间戳。
	IdleExpiresAt int64

	// AbsoluteExpiresAt 表示会话绝对过期的 Unix 时间戳。
	AbsoluteExpiresAt int64

	// CSRFTokenHash 表示会话绑定 CSRF Token 的 SHA-256 摘要。
	CSRFTokenHash []byte
}

// SessionResolver 按 Host、Service 和 Session ID 解析最小认证主体快照。
type SessionResolver interface {
	Resolve(context.Context, SessionResolveRequest) (*SessionPrincipal, error)
}

// sessionMetadata contains only values consumed after principal validation.
type sessionMetadata struct {
	// idleExpiresAt 保存会话空闲过期的 Unix 时间戳。
	idleExpiresAt int64

	// absoluteExpiresAt 保存会话绝对过期的 Unix 时间戳。
	absoluteExpiresAt int64

	// csrfTokenHash 保存会话绑定 CSRF Token 的 SHA-256 摘要。
	csrfTokenHash []byte
}

func newSessionMetadata(principal SessionPrincipal) sessionMetadata {
	return sessionMetadata{
		idleExpiresAt:     principal.IdleExpiresAt,
		absoluteExpiresAt: principal.AbsoluteExpiresAt,
		csrfTokenHash:     append([]byte(nil), principal.CSRFTokenHash...),
	}
}

// BrowserSessionExpiresAt returns the earlier idle or absolute expiry for a
// complete browser principal. Zero means the status is not usable.
func (ls *LoginStatus) BrowserSessionExpiresAt() int64 {
	if ls == nil || ls.State != StateSucc || ls.AuthMode != AuthModeBrowserSession || ls.Claim == nil ||
		ls.session.idleExpiresAt <= 0 || ls.session.absoluteExpiresAt <= 0 {
		return 0
	}
	if ls.session.absoluteExpiresAt < ls.session.idleExpiresAt {
		return ls.session.absoluteExpiresAt
	}
	return ls.session.idleExpiresAt
}

// MatchesBrowserCSRF reports whether token belongs to the verified browser
// Session. The raw token and stored digest are compared in constant time.
func (ls *LoginStatus) MatchesBrowserCSRF(token string) bool {
	if ls == nil || ls.State != StateSucc || ls.AuthMode != AuthModeBrowserSession || token == "" || len(ls.session.csrfTokenHash) != sha256.Size {
		return false
	}
	digest := sha256.Sum256([]byte(token))
	return subtle.ConstantTimeCompare(digest[:], ls.session.csrfTokenHash) == 1
}
