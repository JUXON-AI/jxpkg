package constants

// Gin Context 中使用的键常量。
const (
	// CtxKeyRequestID 表示请求链路 ID 的上下文键。
	CtxKeyRequestID = "reqid"

	// CtxKeyLogger 表示请求日志器的上下文键。
	CtxKeyLogger = "logger"

	// CtxKeyCode 表示业务响应码的上下文键。
	CtxKeyCode = "code"

	// CtxKeyLoginStatus 表示登录状态的上下文键。
	CtxKeyLoginStatus = "loginstatus"

	// CtxKeyUserID 表示当前用户 ID 的上下文键。
	CtxKeyUserID = "userid"

	// CtxKeyUIN 表示当前公司身份 ID 的上下文键。
	CtxKeyUIN = "uin"

	// CtxKeyCompanyID 表示当前公司 ID 的上下文键。
	CtxKeyCompanyID = "companyid"

	// CtxKeyMembershipEpoch 表示当前成员身份代次的上下文键。
	CtxKeyMembershipEpoch = "membershipepoch"
)
