package auth

import "context"

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

// SessionMetadata 保存只能在构造时写入的浏览器会话安全元数据。
type SessionMetadata struct {
	// host 保存会话绑定的规范 Host。
	host string

	// clientID 保存创建会话的客户端标识。
	clientID string

	// sessionVersion 保存会话撤销与轮换版本。
	sessionVersion uint64

	// authenticatedAt 保存中央认证完成的 Unix 时间戳。
	authenticatedAt int64

	// idleExpiresAt 保存会话空闲过期的 Unix 时间戳。
	idleExpiresAt int64

	// absoluteExpiresAt 保存会话绝对过期的 Unix 时间戳。
	absoluteExpiresAt int64

	// csrfTokenHash 保存会话绑定 CSRF Token 的 SHA-256 摘要。
	csrfTokenHash []byte
}

// NewSessionMetadata 从已验证的主体快照创建不可变会话元数据。
func NewSessionMetadata(principal SessionPrincipal) SessionMetadata {
	return SessionMetadata{
		host:              principal.Host,
		clientID:          principal.ClientID,
		sessionVersion:    principal.SessionVersion,
		authenticatedAt:   principal.AuthenticatedAt,
		idleExpiresAt:     principal.IdleExpiresAt,
		absoluteExpiresAt: principal.AbsoluteExpiresAt,
		csrfTokenHash:     append([]byte(nil), principal.CSRFTokenHash...),
	}
}

// Host 返回会话绑定的规范 Host。
func (metadata SessionMetadata) Host() string { return metadata.host }

// ClientID 返回创建会话的客户端标识。
func (metadata SessionMetadata) ClientID() string { return metadata.clientID }

// SessionVersion 返回会话撤销与轮换版本。
func (metadata SessionMetadata) SessionVersion() uint64 { return metadata.sessionVersion }

// AuthenticatedAt 返回中央认证完成的 Unix 时间戳。
func (metadata SessionMetadata) AuthenticatedAt() int64 { return metadata.authenticatedAt }

// IdleExpiresAt 返回会话空闲过期的 Unix 时间戳。
func (metadata SessionMetadata) IdleExpiresAt() int64 { return metadata.idleExpiresAt }

// AbsoluteExpiresAt 返回会话绝对过期的 Unix 时间戳。
func (metadata SessionMetadata) AbsoluteExpiresAt() int64 { return metadata.absoluteExpiresAt }

// CSRFTokenHash 返回会话绑定 CSRF 摘要的副本。
func (metadata SessionMetadata) CSRFTokenHash() []byte {
	return append([]byte(nil), metadata.csrfTokenHash...)
}
