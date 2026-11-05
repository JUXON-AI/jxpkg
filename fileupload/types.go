// Package fileupload 提供跨业务复用的文件上传会话、完整性校验和 Core 文件登记。
package fileupload

import (
	"context"
	"errors"
	"io"
	"time"

	"github.com/JUXON-AI/jxpkg/identity"
	"github.com/JUXON-AI/jxpkg/storage"
)

var (
	// ErrInvalidRequest 表示上传请求或调用参数不满足固定协议。
	ErrInvalidRequest = errors.New("invalid file upload request")
	// ErrNotFound 表示当前成员作用域内不存在指定上传会话或文件。
	ErrNotFound = errors.New("file upload not found")
	// ErrConflict 表示会话状态、租约或幂等键与当前请求冲突。
	ErrConflict = errors.New("file upload state conflict")
	// ErrExpired 表示上传会话已超过允许完成或签发分片地址的时间。
	ErrExpired = errors.New("file upload expired")
	// ErrIntegrity 表示对象大小、摘要、MIME 或路径未通过完整性校验。
	ErrIntegrity = errors.New("file upload integrity check failed")
	// ErrUnavailable 表示数据库或对象存储暂时无法完成请求。
	ErrUnavailable = errors.New("file upload dependency unavailable")
)

// Mode 表示客户端完成上传所采用的协议。
type Mode string

const (
	// ModeSingle 表示客户端通过单个预签名 PUT 上传完整对象。
	ModeSingle Mode = "single"
	// ModeMultipart 表示客户端通过预签名分片 URL 上传并最终合并对象。
	ModeMultipart Mode = "multipart"
	// ModeReused 表示可信服务复用了已经验证的物理对象。
	ModeReused Mode = "reused"
)

// State 表示上传会话的持久化生命周期状态。
type State string

const (
	// StateActive 表示会话可以继续上传、完成或中止。
	StateActive State = "active"
	// StateCompleting 表示完成请求持有短租约，正在合并或校验对象。
	StateCompleting State = "completing"
	// StateAborting 表示中止或清理请求持有短租约，正在删除临时对象。
	StateAborting State = "aborting"
	// StateCompleted 表示 Core 文件登记与会话完成已在同一事务提交。
	StateCompleted State = "completed"
	// StateAborted 表示调用方主动中止了未完成会话。
	StateAborted State = "aborted"
	// StateExpired 表示清理任务回收了超期的未完成会话。
	StateExpired State = "expired"
)

// ObjectStorage 是上传 SDK 所需的对象存储最小读写契约。
type ObjectStorage interface {
	// GetPresignedURL 返回 method 和 storagePath 对应的短期预签名地址。
	GetPresignedURL(ctx context.Context, method, storagePath string) (string, error)
	// HeadFile 返回对象存储记录的原始大小、MIME 和实体标签。
	HeadFile(ctx context.Context, storagePath string) (*storage.FileMetadata, error)
	// ReadFile 打开完整对象流，用于默认大小和 SHA256 校验。
	ReadFile(ctx context.Context, storagePath string) (io.ReadCloser, error)
	// DeleteFile 删除本 SDK 创建的未完成对象路径，调用必须可安全重试。
	DeleteFile(ctx context.Context, storagePath string) error
}

type multipartStorage interface {
	CreateMultipartUpload(ctx context.Context, storagePath, contentType string) (string, error)
	GetMultipartUploadPartPresignedURL(ctx context.Context, storagePath, uploadID string, partNumber int32) (string, error)
	ListMultipartUploadParts(ctx context.Context, storagePath, uploadID string) ([]storage.MultipartUploadPart, error)
	CompleteMultipartUpload(ctx context.Context, storagePath, uploadID string, parts map[int32]string) error
	AbortMultipartUpload(ctx context.Context, storagePath, uploadID string) error
}

// Options 配置通用上传服务的默认值和有限租约。
type Options struct {
	// Now 返回当前时间；为空时使用 time.Now。
	Now func() time.Time
	// MultipartThreshold 是自动切换分片上传的字节阈值，默认 64 MiB。
	MultipartThreshold int64
	// PartSize 是单个分片的目标字节数，默认 16 MiB，最大片数 10000。
	PartSize int64
	// CompletionTimeout 是完成或中止租约最长持有时间，默认 10 分钟。
	CompletionTimeout time.Duration
	// CleanupGrace 是上传过期后保留的清理宽限，默认 24 小时。
	CleanupGrace time.Duration
}

// Request 描述创建上传会话或可信登记已有对象所需的固定元数据。
type Request struct {
	// ID 是服务端生成的 UUID；JXX 传入其 AttachmentID，空值由 SDK 生成。
	ID string
	// Owner 是经调用方验证的组织成员，不能取自客户端身体字段。
	Owner identity.Member
	// Purpose 是文件用途分类，限制为 32 个安全字符。
	Purpose string
	// Filename 是最大 255 个字符的原始展示文件名。
	Filename string
	// FileExt 是包含点号且最大 16 个字符的规范扩展名。
	FileExt string
	// MIMEType 是调用方声明的对象媒体类型。
	MIMEType string
	// SizeBytes 是对象完整内容的精确字节数。
	SizeBytes int64
	// SHA256 是可选的小写十六进制完整内容摘要；提供时完成校验必须匹配。
	SHA256 string
	// AllowMultipart 表示达到阈值时允许使用分片上传。
	AllowMultipart bool
	// ExpiresAt 是上传截止时间；空值按上传模式使用默认值。
	ExpiresAt time.Time
}

// Session 是对外可见的上传会话，同时映射 core_file_upload_sessions。
type Session struct {
	// ID 是服务端生成的 UUID，也是 Request.ID 的持久化幂等键。
	ID string `gorm:"column:id;type:char(36);primaryKey;comment:上传会话ID" json:"id"`
	// OrganizationID 是会话所属组织。
	OrganizationID string `gorm:"column:organization_id;type:varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin;not null;comment:所属组织ID" json:"organization_id"`
	// UserID 是会话所属组织成员。
	UserID string `gorm:"column:user_id;type:varchar(128) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin;not null;comment:所属用户ID" json:"user_id"`
	// Purpose 是文件用途分类。
	Purpose string `gorm:"column:purpose;type:varchar(32);not null;comment:用途分类" json:"purpose"`
	// Filename 是原始展示文件名。
	Filename string `gorm:"column:filename;type:varchar(255);not null;comment:原始文件名" json:"filename"`
	// FileExt 是包含点号的规范文件扩展名。
	FileExt string `gorm:"column:file_ext;type:varchar(16);not null;comment:文件扩展名" json:"file_ext"`
	// MIMEType 是创建时声明并由完成校验确认的 MIME 类型。
	MIMEType string `gorm:"column:mime_type;type:varchar(128);not null;comment:MIME类型" json:"mime_type"`
	// SizeBytes 是对象完整内容的精确字节数。
	SizeBytes int64 `gorm:"column:size_bytes;type:bigint;not null;comment:文件字节数" json:"size_bytes"`
	// SHA256 是创建时可选声明的小写十六进制 SHA256；空值不表示对象不受完整性验证。
	SHA256 string `gorm:"column:sha256;type:char(64);not null;comment:文件SHA256" json:"sha256"`
	// StoragePath 是私有对象路径，不通过客户端响应主动暴露。
	StoragePath string `gorm:"column:storage_path;type:varchar(512);not null;comment:对象存储路径" json:"-"`
	// MultipartID 是对象存储返回的分片上传标识。
	MultipartID string `gorm:"column:multipart_id;type:varchar(255);not null;default:'';comment:分片上传ID" json:"-"`
	// Mode 是 single、multipart 或 reused 上传模式。
	Mode Mode `gorm:"column:mode;type:varchar(16);not null;comment:上传模式" json:"mode"`
	// PartSize 是分片模式下的目标分片字节数。
	PartSize int64 `gorm:"column:part_size;type:bigint;not null;default:0;comment:分片字节数" json:"part_size"`
	// PartCount 是分片模式下的总片数。
	PartCount int32 `gorm:"column:part_count;type:int;not null;default:0;comment:分片总数" json:"part_count"`
	// ExpiresAt 是上传截止时间。
	ExpiresAt time.Time `gorm:"column:expires_at;type:datetime(3);not null;index:idx_core_file_upload_sessions_cleanup,priority:2;comment:上传过期时间" json:"expires_at"`
	// FileID 是完成登记后的 core_upload_files 主键。
	FileID *uint `gorm:"column:file_id;type:bigint unsigned;comment:Core文件ID" json:"file_id"`
	// State 是会话生命周期状态。
	State State `gorm:"column:state;type:varchar(16);not null;index:idx_core_file_upload_sessions_cleanup,priority:1;comment:会话状态" json:"state"`
	// LeaseToken 是完成或中止操作的随机 fencing token。
	LeaseToken string `gorm:"column:lease_token;type:char(64);not null;default:'';comment:租约令牌" json:"-"`
	// LeaseExpiresAt 是当前短租约的截止时间。
	LeaseExpiresAt *time.Time `gorm:"column:lease_expires_at;type:datetime(3);comment:租约过期时间" json:"-"`
	// CreatedAt 是会话创建时间。
	CreatedAt time.Time `gorm:"column:created_at;type:datetime(3);not null;comment:创建时间" json:"created_at"`
	// UpdatedAt 是会话最后更新时间。
	UpdatedAt time.Time `gorm:"column:updated_at;type:datetime(3);not null;comment:更新时间" json:"updated_at"`
}

// TableName 返回 Core 上传会话表名。
func (*Session) TableName() string { return TableNameUploadSession }

// Started 返回会话和客户端需要采用的上传协议。
type Started struct {
	// Session 是已经持久化的上传会话。
	Session *Session `json:"session"`
	// UploadURL 是单文件上传地址；分片模式为空。
	UploadURL string `json:"upload_url"`
	// Mode 是客户端应采用的上传模式。
	Mode Mode `json:"mode"`
	// PartSize 是分片模式的目标字节数。
	PartSize int64 `json:"part_size"`
	// PartCount 是分片模式的总片数。
	PartCount int32 `json:"part_count"`
}

// PartURL 返回一个分片的短期上传地址。
type PartURL struct {
	// PartNumber 是从 1 开始的分片序号。
	PartNumber int32 `json:"part_number"`
	// UploadURL 是对应分片的预签名 PUT 地址。
	UploadURL string `json:"upload_url"`
}

// VerifiedObject 是可信验证器返回的规范化物理对象元数据。
type VerifiedObject struct {
	// SizeBytes 是经服务端确认的完整对象字节数。
	SizeBytes int64
	// SHA256 是经可信服务计算的完整对象小写十六进制摘要，完成登记时必需。
	SHA256 string
	// MIMEType 是经服务端确认的对象 MIME。
	MIMEType string
	// StoragePath 是经可信服务确认或改写的同 purpose 私有对象路径，可复用其他 owner 的已验证物理对象。
	StoragePath string
	// ETag 是对象存储实体标签，仅作元数据，绝不是内容摘要。
	ETag string
}

// Verifier 验证合并后的对象，并返回可供统一完整性检查的元数据。
type Verifier func(context.Context, *Session, ObjectStorage) (VerifiedObject, error)

// Repository 是上传会话的持久化端口，供服务测试注入内存实现。
type Repository interface {
	// CreateSession 插入新的 active 会话。
	CreateSession(ctx context.Context, session *Session) error
	// GetSession 按组织和成员作用域读取会话。
	GetSession(ctx context.Context, owner identity.Member, id string) (*Session, error)
	// ClaimLease 按目标状态以 CAS 获取 active 或允许抢占的已过期租约；aborting 不可回到 completing。
	ClaimLease(ctx context.Context, owner identity.Member, id string, state State, token string, now, until time.Time) (*Session, error)
	// ReleaseLease 仅在持有 fencing token 时把 completing 会话退回 active。
	ReleaseLease(ctx context.Context, owner identity.Member, id, token string) error
	// Finish 在持有 fencing token 时将非终态会话写入 aborted 或 expired。
	Finish(ctx context.Context, owner identity.Member, id, token string, state State, now time.Time) error
	// FinalizeComplete 在同一事务中登记 Core 文件并将会话标记为 completed。
	FinalizeComplete(ctx context.Context, owner identity.Member, id, token string, now time.Time, file *storage.CoreFileInfo) (*storage.CoreFileInfo, error)
	// RegisterExisting 在同一事务中登记可信对象和 completed 会话。
	RegisterExisting(ctx context.Context, session *Session, file *storage.CoreFileInfo) (*storage.CoreFileInfo, error)
	// UpdateFilePath 在 Core 事务中锁定 completed session 和文件，以期望路径为 CAS 仅更新文件路径。
	UpdateFilePath(ctx context.Context, owner identity.Member, id string, fileID uint, expectedPath, storagePath string) (*storage.CoreFileInfo, error)
	// ListExpired 返回到期且未完成的限量会话，仅供 CleanupExpired 调用。
	ListExpired(ctx context.Context, before time.Time, limit int) ([]*Session, error)
	// GetFile 按组织成员作用域读取已登记的 Core 文件。
	GetFile(ctx context.Context, owner identity.Member, id uint) (*storage.CoreFileInfo, error)
}
