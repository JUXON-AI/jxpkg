package fileupload

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"path"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/JUXON-AI/jxpkg/identity"
	"github.com/JUXON-AI/jxpkg/storage"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

const (
	defaultMultipartThreshold = int64(64 << 20)
	defaultPartSize           = int64(16 << 20)
	defaultCompletionTimeout  = 10 * time.Minute
	defaultCleanupGrace       = 24 * time.Hour
	defaultSingleUploadTTL    = 15 * time.Minute
	defaultMultipartUploadTTL = 24 * time.Hour
	maxPartCount              = 10000
	maxPartURLBatch           = 100
	maxCleanupBatch           = 1000
	leaseReleaseTimeout       = 5 * time.Second
)

// Service 负责上传会话生命周期、对象完整性校验和 Core 文件登记。
type Service struct {
	repository    Repository
	objectStorage ObjectStorage
	options       Options
}

// New 使用显式 Core 数据库连接和对象存储创建上传服务。
func New(db *gorm.DB, objectStorage ObjectStorage, options Options) (*Service, error) {
	if db == nil {
		return nil, fmt.Errorf("%w: core database is required", ErrInvalidRequest)
	}
	return newWithRepository(NewGORMRepository(db), objectStorage, options)
}

func newWithRepository(repository Repository, objectStorage ObjectStorage, options Options) (*Service, error) {
	if repository == nil || objectStorage == nil {
		return nil, fmt.Errorf("%w: repository and object storage are required", ErrInvalidRequest)
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.MultipartThreshold == 0 {
		options.MultipartThreshold = defaultMultipartThreshold
	}
	if options.PartSize == 0 {
		options.PartSize = defaultPartSize
	}
	if options.CompletionTimeout == 0 {
		options.CompletionTimeout = defaultCompletionTimeout
	}
	if options.CleanupGrace == 0 {
		options.CleanupGrace = defaultCleanupGrace
	}
	if options.MultipartThreshold < 0 || options.PartSize < 0 || options.CompletionTimeout < 0 || options.CleanupGrace < 0 {
		return nil, fmt.Errorf("%w: upload option must not be negative", ErrInvalidRequest)
	}
	if options.PartSize <= 0 || options.CompletionTimeout <= 0 || options.CleanupGrace <= 0 {
		return nil, fmt.Errorf("%w: upload timing option must be positive", ErrInvalidRequest)
	}
	return &Service{repository: repository, objectStorage: objectStorage, options: options}, nil
}

// Start 创建并持久化独立上传会话，返回客户端应使用的上传协议。
func (service *Service) Start(ctx context.Context, request Request) (*Started, error) {
	if err := validateContext(ctx); err != nil {
		return nil, err
	}
	now := service.options.Now().UTC()
	normalized, err := normalizeRequest(request, now, true)
	if err != nil {
		return nil, err
	}
	mode, partSize, partCount := service.uploadMode(normalized)
	if mode == ModeMultipart && (partCount < 1 || partCount > maxPartCount) {
		return nil, fmt.Errorf("%w: multipart part count exceeds limit", ErrInvalidRequest)
	}
	if normalized.ExpiresAt.IsZero() {
		if mode == ModeMultipart {
			normalized.ExpiresAt = now.Add(defaultMultipartUploadTTL)
		} else {
			normalized.ExpiresAt = now.Add(defaultSingleUploadTTL)
		}
	}
	if !normalized.ExpiresAt.After(now) {
		return nil, fmt.Errorf("%w: expires_at must be in the future", ErrInvalidRequest)
	}
	storagePath, err := storage.GenerateFileStoragePath(normalized.Purpose, normalized.Owner, normalized.FileExt)
	if err != nil {
		return nil, fmt.Errorf("%w: generate storage path", ErrInvalidRequest)
	}
	session := &Session{
		ID: normalized.ID, OrganizationID: normalized.Owner.OrganizationID, UserID: normalized.Owner.UserID,
		Purpose: normalized.Purpose, Filename: normalized.Filename, FileExt: normalized.FileExt,
		MIMEType: normalized.MIMEType, SizeBytes: normalized.SizeBytes, SHA256: normalized.SHA256,
		StoragePath: storagePath, Mode: mode, PartSize: partSize, PartCount: partCount,
		ExpiresAt: normalized.ExpiresAt, State: StateActive, CreatedAt: now, UpdatedAt: now,
	}
	uploadURL := ""
	switch mode {
	case ModeMultipart:
		multipart, ok := service.objectStorage.(multipartStorage)
		if !ok {
			return nil, fmt.Errorf("%w: multipart storage is unavailable", ErrUnavailable)
		}
		session.MultipartID, err = multipart.CreateMultipartUpload(ctx, storagePath, normalized.MIMEType)
		if err != nil {
			return nil, fmt.Errorf("%w: create multipart upload", ErrUnavailable)
		}
		if strings.TrimSpace(session.MultipartID) == "" {
			return nil, fmt.Errorf("%w: multipart upload ID is empty", ErrUnavailable)
		}
	case ModeSingle:
		uploadURL, err = service.objectStorage.GetPresignedURL(ctx, http.MethodPut, storagePath)
		if err != nil || uploadURL == "" {
			return nil, fmt.Errorf("%w: create upload URL", ErrUnavailable)
		}
	default:
		return nil, ErrInvalidRequest
	}
	if err := service.repository.CreateSession(ctx, session); err != nil {
		if mode == ModeMultipart {
			if multipart, ok := service.objectStorage.(multipartStorage); ok && session.MultipartID != "" {
				abortCtx, cancel := context.WithTimeout(context.Background(), leaseReleaseTimeout)
				_ = multipart.AbortMultipartUpload(abortCtx, storagePath, session.MultipartID)
				cancel()
			}
		}
		return nil, mapServiceError(err)
	}
	return &Started{Session: session, UploadURL: uploadURL, Mode: mode, PartSize: partSize, PartCount: partCount}, nil
}

// Get 按当前成员作用域读取上传会话，用于跨库登记恢复和业务清理。
func (service *Service) Get(ctx context.Context, owner identity.Member, id string) (*Session, error) {
	if err := validateContext(ctx); err != nil {
		return nil, err
	}
	if err := validateOwnerAndID(owner, id); err != nil {
		return nil, err
	}
	session, err := service.repository.GetSession(ctx, owner, id)
	if err != nil {
		return nil, mapServiceError(err)
	}
	return session, nil
}

// PartURLs 为 active 分片会话签发有限批次的分片上传地址。
func (service *Service) PartURLs(ctx context.Context, owner identity.Member, id string, partNumbers []int32) ([]PartURL, error) {
	if err := validateContext(ctx); err != nil {
		return nil, err
	}
	if err := validateOwnerAndID(owner, id); err != nil {
		return nil, err
	}
	if len(partNumbers) == 0 || len(partNumbers) > maxPartURLBatch {
		return nil, fmt.Errorf("%w: invalid part URL batch", ErrInvalidRequest)
	}
	session, err := service.repository.GetSession(ctx, owner, id)
	if err != nil {
		return nil, mapServiceError(err)
	}
	if !service.options.Now().UTC().Before(session.ExpiresAt) && session.State == StateActive {
		return nil, ErrExpired
	}
	if session.State != StateActive || session.Mode != ModeMultipart || session.MultipartID == "" {
		return nil, ErrConflict
	}
	seen := make(map[int32]struct{}, len(partNumbers))
	for _, partNumber := range partNumbers {
		if partNumber < 1 || partNumber > session.PartCount {
			return nil, fmt.Errorf("%w: part number out of range", ErrInvalidRequest)
		}
		if _, exists := seen[partNumber]; exists {
			return nil, fmt.Errorf("%w: duplicate part number", ErrInvalidRequest)
		}
		seen[partNumber] = struct{}{}
	}
	multipart, ok := service.objectStorage.(multipartStorage)
	if !ok {
		return nil, fmt.Errorf("%w: multipart storage is unavailable", ErrUnavailable)
	}
	result := make([]PartURL, 0, len(partNumbers))
	for _, partNumber := range partNumbers {
		uploadURL, err := multipart.GetMultipartUploadPartPresignedURL(ctx, session.StoragePath, session.MultipartID, partNumber)
		if err != nil || uploadURL == "" {
			return nil, fmt.Errorf("%w: create part upload URL", ErrUnavailable)
		}
		result = append(result, PartURL{PartNumber: partNumber, UploadURL: uploadURL})
	}
	return result, nil
}

// Parts 返回对象存储已经接收的分片，用于客户端恢复分片上传。
func (service *Service) Parts(ctx context.Context, owner identity.Member, id string) ([]storage.MultipartUploadPart, error) {
	if err := validateContext(ctx); err != nil {
		return nil, err
	}
	if err := validateOwnerAndID(owner, id); err != nil {
		return nil, err
	}
	session, err := service.repository.GetSession(ctx, owner, id)
	if err != nil {
		return nil, mapServiceError(err)
	}
	if !service.options.Now().UTC().Before(session.ExpiresAt) && session.State == StateActive {
		return nil, ErrExpired
	}
	if session.State != StateActive || session.Mode != ModeMultipart || session.MultipartID == "" {
		return nil, ErrConflict
	}
	multipart, ok := service.objectStorage.(multipartStorage)
	if !ok {
		return nil, fmt.Errorf("%w: multipart storage is unavailable", ErrUnavailable)
	}
	parts, err := multipart.ListMultipartUploadParts(ctx, session.StoragePath, session.MultipartID)
	if err != nil {
		return nil, fmt.Errorf("%w: list uploaded parts", ErrUnavailable)
	}
	return parts, nil
}

// Complete 在独占租约下合并、验证并登记 Core 文件；重复完成返回同一文件。
func (service *Service) Complete(
	ctx context.Context,
	owner identity.Member,
	id string,
	parts []storage.MultipartUploadPart,
	verifier Verifier,
) (*storage.CoreFileInfo, error) {
	if err := validateContext(ctx); err != nil {
		return nil, err
	}
	if err := validateOwnerAndID(owner, id); err != nil {
		return nil, err
	}
	operationCtx, cancel := context.WithTimeout(ctx, service.options.CompletionTimeout)
	defer cancel()
	session, err := service.repository.GetSession(operationCtx, owner, id)
	if err != nil {
		return nil, mapServiceError(err)
	}
	if session.State == StateCompleted {
		return service.completedFile(ctx, owner, session)
	}
	if session.State == StateAborted || session.State == StateExpired {
		return nil, ErrConflict
	}
	now := service.options.Now().UTC()
	if !now.Before(session.ExpiresAt) {
		return nil, ErrExpired
	}
	token, err := newLeaseToken()
	if err != nil {
		return nil, fmt.Errorf("%w: generate lease token", ErrUnavailable)
	}
	claimed, err := service.repository.ClaimLease(operationCtx, owner, id, StateCompleting, token, now, now.Add(service.options.CompletionTimeout))
	if err != nil {
		if errors.Is(err, ErrConflict) {
			latest, getErr := service.repository.GetSession(operationCtx, owner, id)
			if getErr == nil && latest.State == StateCompleted {
				return service.completedFile(operationCtx, owner, latest)
			}
		}
		return nil, mapServiceError(err)
	}
	if !service.options.Now().UTC().Before(claimed.ExpiresAt) {
		service.releaseLease(owner, id, token)
		return nil, ErrExpired
	}
	file, completionErr := service.completeClaimed(operationCtx, claimed, token, parts, verifier)
	if completionErr != nil {
		service.releaseLease(owner, id, token)
		if errors.Is(completionErr, ErrConflict) {
			lookupCtx, lookupCancel := context.WithTimeout(context.Background(), leaseReleaseTimeout)
			latest, getErr := service.repository.GetSession(lookupCtx, owner, id)
			if getErr == nil && latest.State == StateCompleted {
				file, fileErr := service.completedFile(lookupCtx, owner, latest)
				lookupCancel()
				return file, fileErr
			}
			lookupCancel()
		}
		return nil, completionErr
	}
	if claimed.StoragePath != file.StoragePath {
		service.deleteTemporaryObject(claimed.StoragePath)
	}
	return file, nil
}

// RegisterExisting 登记可信服务已经验证的对象，不执行对象存储操作或跨 owner 去重。
func (service *Service) RegisterExisting(ctx context.Context, request Request, verified VerifiedObject) (*storage.CoreFileInfo, error) {
	if err := validateContext(ctx); err != nil {
		return nil, err
	}
	now := service.options.Now().UTC()
	// RegisterExisting 只登记已经完成的对象，原上传截止时间不再决定其可用性。
	request.ExpiresAt = time.Time{}
	normalized, err := normalizeRequest(request, now, true)
	if err != nil {
		return nil, err
	}
	if err := validateVerifiedObject(normalized, verified); err != nil {
		return nil, err
	}
	if existing, getErr := service.repository.GetSession(ctx, normalized.Owner, normalized.ID); getErr == nil {
		return service.existingRegistration(ctx, normalized.Owner, existing, normalized, verified)
	} else if !errors.Is(getErr, ErrNotFound) {
		return nil, mapServiceError(getErr)
	}
	session := &Session{
		ID: normalized.ID, OrganizationID: normalized.Owner.OrganizationID, UserID: normalized.Owner.UserID,
		Purpose: normalized.Purpose, Filename: normalized.Filename, FileExt: normalized.FileExt,
		MIMEType: normalized.MIMEType, SizeBytes: normalized.SizeBytes, SHA256: normalized.SHA256,
		StoragePath: verified.StoragePath, Mode: ModeReused, ExpiresAt: now, State: StateCompleted,
		CreatedAt: now, UpdatedAt: now,
	}
	file := coreFileFromVerified(session, verified)
	registered, err := service.repository.RegisterExisting(ctx, session, file)
	if err != nil {
		if errors.Is(err, ErrConflict) {
			existing, getErr := service.repository.GetSession(ctx, normalized.Owner, normalized.ID)
			if getErr == nil && existing.State == StateCompleted {
				return service.existingRegistration(ctx, normalized.Owner, existing, normalized, verified)
			}
		}
		return nil, mapServiceError(err)
	}
	stored, getErr := service.repository.GetSession(ctx, normalized.Owner, normalized.ID)
	if getErr != nil {
		return nil, mapServiceError(getErr)
	}
	registeredFile, fileErr := service.completedFile(ctx, normalized.Owner, stored)
	if fileErr != nil {
		return nil, fileErr
	}
	if err := validateRegisterExistingRetry(stored, registeredFile, normalized, verified); err != nil {
		return nil, err
	}
	return registered, nil
}

// UseVerifiedObject 将已完成的 Core 文件重指向可信服务确认的同内容物理对象。
func (service *Service) UseVerifiedObject(ctx context.Context, owner identity.Member, id string, verified VerifiedObject) (*storage.CoreFileInfo, error) {
	if err := validateContext(ctx); err != nil {
		return nil, err
	}
	if err := validateOwnerAndID(owner, id); err != nil {
		return nil, err
	}
	session, err := service.repository.GetSession(ctx, owner, id)
	if err != nil {
		return nil, mapServiceError(err)
	}
	if session.State != StateCompleted || session.FileID == nil {
		return nil, ErrConflict
	}
	file, err := service.completedFile(ctx, owner, session)
	if err != nil {
		return nil, err
	}
	if err := validateUseVerifiedObject(file, verified); err != nil {
		return nil, err
	}
	updated, err := service.repository.UpdateFilePath(ctx, owner, id, *session.FileID, file.StoragePath, verified.StoragePath)
	if err != nil {
		return nil, mapServiceError(err)
	}
	return updated, nil
}

// Abort 中止未完成会话并删除该会话自己的临时对象；completed 会话拒绝中止。
func (service *Service) Abort(ctx context.Context, owner identity.Member, id string) error {
	if err := validateContext(ctx); err != nil {
		return err
	}
	if err := validateOwnerAndID(owner, id); err != nil {
		return err
	}
	operationCtx, cancel := context.WithTimeout(ctx, service.options.CompletionTimeout)
	defer cancel()
	session, err := service.repository.GetSession(operationCtx, owner, id)
	if err != nil {
		return mapServiceError(err)
	}
	switch session.State {
	case StateCompleted:
		return ErrConflict
	case StateAborted, StateExpired:
		return nil
	}
	now := service.options.Now().UTC()
	token, err := newLeaseToken()
	if err != nil {
		return fmt.Errorf("%w: generate lease token", ErrUnavailable)
	}
	claimed, err := service.repository.ClaimLease(operationCtx, owner, id, StateAborting, token, now, now.Add(service.options.CompletionTimeout))
	if err != nil {
		return mapServiceError(err)
	}
	if err := service.removeUnfinishedObject(operationCtx, claimed); err != nil {
		return err
	}
	if err := service.repository.Finish(operationCtx, owner, id, token, StateAborted, service.options.Now().UTC()); err != nil {
		return mapServiceError(err)
	}
	return nil
}

// CleanupExpired 限量回收超过到期和宽限时间的未完成会话，绝不处理 completed 文件。
func (service *Service) CleanupExpired(ctx context.Context, before time.Time, limit int) (int64, error) {
	if err := validateContext(ctx); err != nil {
		return 0, err
	}
	if before.IsZero() || limit < 1 || limit > maxCleanupBatch {
		return 0, fmt.Errorf("%w: invalid cleanup bound", ErrInvalidRequest)
	}
	cutoff := before.UTC().Add(-service.options.CleanupGrace)
	listCtx, listCancel := context.WithTimeout(ctx, service.options.CompletionTimeout)
	sessions, err := service.repository.ListExpired(listCtx, cutoff, limit)
	listCancel()
	if err != nil {
		return 0, mapServiceError(err)
	}
	var removed int64
	for _, candidate := range sessions {
		operationCtx, operationCancel := context.WithTimeout(ctx, service.options.CompletionTimeout)
		owner := identity.Member{OrganizationID: candidate.OrganizationID, UserID: candidate.UserID}
		now := service.options.Now().UTC()
		token, tokenErr := newLeaseToken()
		if tokenErr != nil {
			operationCancel()
			return removed, fmt.Errorf("%w: generate cleanup lease token", ErrUnavailable)
		}
		claimed, claimErr := service.repository.ClaimLease(operationCtx, owner, candidate.ID, StateAborting, token, now, now.Add(service.options.CompletionTimeout))
		if claimErr != nil {
			if errors.Is(claimErr, ErrConflict) || errors.Is(claimErr, ErrNotFound) {
				operationCancel()
				continue
			}
			operationCancel()
			return removed, mapServiceError(claimErr)
		}
		if err := service.removeUnfinishedObject(operationCtx, claimed); err != nil {
			operationCancel()
			return removed, err
		}
		if err := service.repository.Finish(operationCtx, owner, candidate.ID, token, StateExpired, service.options.Now().UTC()); err != nil {
			operationCancel()
			if errors.Is(err, ErrConflict) {
				continue
			}
			return removed, mapServiceError(err)
		}
		operationCancel()
		removed++
	}
	return removed, nil
}

func (service *Service) completeClaimed(
	ctx context.Context,
	session *Session,
	token string,
	parts []storage.MultipartUploadPart,
	verifier Verifier,
) (*storage.CoreFileInfo, error) {
	if session.Mode == ModeMultipart {
		if err := validateMultipartParts(session, parts); err != nil {
			return nil, err
		}
		multipart, ok := service.objectStorage.(multipartStorage)
		if !ok {
			return nil, fmt.Errorf("%w: multipart storage is unavailable", ErrUnavailable)
		}
		partMap := make(map[int32]string, len(parts))
		for _, part := range parts {
			partMap[part.PartNumber] = part.ETag
		}
		if err := multipart.CompleteMultipartUpload(ctx, session.StoragePath, session.MultipartID, partMap); err != nil {
			if err := ctx.Err(); err != nil {
				return nil, fmt.Errorf("%w: %w", ErrUnavailable, err)
			}
			// COS 已完成合并但响应丢失或上次 DB 事务失败时，Head 可直接恢复。
			if _, headErr := service.objectStorage.HeadFile(ctx, session.StoragePath); headErr != nil {
				return nil, fmt.Errorf("%w: merge multipart upload", ErrUnavailable)
			}
		}
	} else if len(parts) != 0 {
		return nil, fmt.Errorf("%w: parts are only valid for multipart uploads", ErrInvalidRequest)
	}
	if verifier == nil {
		verifier = defaultVerifier
	}
	verified, err := verifier(ctx, session, service.objectStorage)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, fmt.Errorf("%w: %w", ErrUnavailable, ctxErr)
		}
		if errors.Is(err, ErrIntegrity) || errors.Is(err, ErrInvalidRequest) || errors.Is(err, ErrExpired) {
			return nil, mapServiceError(err)
		}
		return nil, fmt.Errorf("%w: object verifier failed", ErrUnavailable)
	}
	if err := validateVerifiedObjectFromSession(session, verified); err != nil {
		return nil, err
	}
	file := coreFileFromVerified(session, verified)
	registered, err := service.repository.FinalizeComplete(ctx, identity.Member{OrganizationID: session.OrganizationID, UserID: session.UserID}, session.ID, token, service.options.Now().UTC(), file)
	if err != nil {
		return nil, mapServiceError(err)
	}
	return registered, nil
}

func (service *Service) completedFile(ctx context.Context, owner identity.Member, session *Session) (*storage.CoreFileInfo, error) {
	if session.FileID == nil || *session.FileID == 0 {
		return nil, fmt.Errorf("%w: completed session has no file ID", ErrConflict)
	}
	file, err := service.repository.GetFile(ctx, owner, *session.FileID)
	if err != nil {
		return nil, mapServiceError(err)
	}
	return file, nil
}

func (service *Service) existingRegistration(
	ctx context.Context,
	owner identity.Member,
	session *Session,
	request Request,
	verified VerifiedObject,
) (*storage.CoreFileInfo, error) {
	if session.State != StateCompleted {
		return nil, ErrConflict
	}
	file, err := service.completedFile(ctx, owner, session)
	if err != nil {
		return nil, err
	}
	if err := validateRegisterExistingRetry(session, file, request, verified); err != nil {
		return nil, err
	}
	return file, nil
}

func validateRegisterExistingRetry(session *Session, file *storage.CoreFileInfo, request Request, verified VerifiedObject) error {
	if file == nil || session.State != StateCompleted || session.FileID == nil || *session.FileID != file.ID {
		return fmt.Errorf("%w: existing file registration is incomplete", ErrConflict)
	}
	if session.OrganizationID != request.Owner.OrganizationID || session.UserID != request.Owner.UserID ||
		session.Purpose != request.Purpose || session.Filename != request.Filename || session.FileExt != request.FileExt ||
		session.MIMEType != request.MIMEType || session.SizeBytes != request.SizeBytes || session.SHA256 != request.SHA256 {
		return fmt.Errorf("%w: existing upload request metadata differs", ErrConflict)
	}
	canonicalSHA256 := strings.ToLower(strings.TrimSpace(verified.SHA256))
	if file.OrganizationID != request.Owner.OrganizationID || file.UserID != request.Owner.UserID ||
		file.Purpose != request.Purpose || file.Filename != request.Filename || file.FileExt != request.FileExt ||
		file.Size != verified.SizeBytes || file.Hash != "sha256:"+canonicalSHA256 ||
		file.MIMEType != verified.MIMEType || file.StoragePath != verified.StoragePath {
		return fmt.Errorf("%w: existing file metadata differs", ErrConflict)
	}
	return nil
}

func validateUseVerifiedObject(file *storage.CoreFileInfo, verified VerifiedObject) error {
	if file == nil {
		return ErrConflict
	}
	if !validLowerSHA256(verified.SHA256) || file.Hash != "sha256:"+strings.ToLower(strings.TrimSpace(verified.SHA256)) || file.Size != verified.SizeBytes {
		return fmt.Errorf("%w: verified object metadata differs from completed file", ErrIntegrity)
	}
	if !mimeEqual(file.MIMEType, verified.MIMEType) {
		return fmt.Errorf("%w: verified object MIME differs from completed file", ErrIntegrity)
	}
	if err := validateStoragePath(Request{Purpose: file.Purpose}, verified.StoragePath); err != nil {
		return err
	}
	return nil
}

func (service *Service) removeUnfinishedObject(ctx context.Context, session *Session) error {
	if session == nil || session.StoragePath == "" || session.State != StateAborting {
		return ErrConflict
	}
	if session.Mode == ModeMultipart && session.MultipartID != "" {
		merged := false
		if metadata, err := service.objectStorage.HeadFile(ctx, session.StoragePath); err == nil && metadata != nil {
			merged = true
		}
		if !merged {
			multipart, ok := service.objectStorage.(multipartStorage)
			if !ok {
				return fmt.Errorf("%w: multipart storage is unavailable", ErrUnavailable)
			}
			if err := multipart.AbortMultipartUpload(ctx, session.StoragePath, session.MultipartID); err != nil {
				if ctxErr := ctx.Err(); ctxErr != nil {
					return fmt.Errorf("%w: %w", ErrUnavailable, ctxErr)
				}
				if !multipartUploadAlreadyAborted(err) {
					return fmt.Errorf("%w: abort multipart upload", ErrUnavailable)
				}
			}
		}
	}
	if session.Mode == ModeReused {
		return nil
	}
	if err := service.objectStorage.DeleteFile(ctx, session.StoragePath); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return fmt.Errorf("%w: %w", ErrUnavailable, ctxErr)
		}
		return fmt.Errorf("%w: delete unfinished object", ErrUnavailable)
	}
	return nil
}

func multipartUploadAlreadyAborted(err error) bool {
	var coded interface{ ErrorCode() string }
	return errors.As(err, &coded) && coded.ErrorCode() == "NoSuchUpload"
}

func (service *Service) releaseLease(owner identity.Member, id, token string) {
	ctx, cancel := context.WithTimeout(context.Background(), leaseReleaseTimeout)
	defer cancel()
	_ = service.repository.ReleaseLease(ctx, owner, id, token)
}

func (service *Service) deleteTemporaryObject(storagePath string) {
	ctx, cancel := context.WithTimeout(context.Background(), leaseReleaseTimeout)
	defer cancel()
	_ = service.objectStorage.DeleteFile(ctx, storagePath)
}

func (service *Service) uploadMode(request Request) (Mode, int64, int32) {
	if request.AllowMultipart && request.SizeBytes > service.options.MultipartThreshold {
		partCount := (request.SizeBytes-1)/service.options.PartSize + 1
		if partCount > maxPartCount {
			return ModeMultipart, service.options.PartSize, maxPartCount + 1
		}
		return ModeMultipart, service.options.PartSize, int32(partCount)
	}
	return ModeSingle, 0, 0
}

func normalizeRequest(request Request, now time.Time, allowEmptyID bool) (Request, error) {
	if err := request.Owner.Validate(); err != nil {
		return Request{}, fmt.Errorf("%w: invalid owner", ErrInvalidRequest)
	}
	request.ID = strings.TrimSpace(request.ID)
	if request.ID == "" {
		if !allowEmptyID {
			return Request{}, fmt.Errorf("%w: id is required", ErrInvalidRequest)
		}
		request.ID = uuid.NewString()
	}
	if parsed, err := uuid.Parse(request.ID); err != nil || parsed.String() != strings.ToLower(request.ID) {
		return Request{}, fmt.Errorf("%w: id must be a canonical UUID", ErrInvalidRequest)
	}
	if !validPurpose(request.Purpose) {
		return Request{}, fmt.Errorf("%w: invalid purpose", ErrInvalidRequest)
	}
	if !validFilename(request.Filename) {
		return Request{}, fmt.Errorf("%w: invalid filename", ErrInvalidRequest)
	}
	request.FileExt = strings.ToLower(strings.TrimSpace(request.FileExt))
	if !validFileExt(request.FileExt) {
		return Request{}, fmt.Errorf("%w: invalid file extension", ErrInvalidRequest)
	}
	request.MIMEType = strings.TrimSpace(request.MIMEType)
	if _, err := canonicalMIME(request.MIMEType); err != nil || len(request.MIMEType) > 128 || !utf8.ValidString(request.MIMEType) {
		return Request{}, fmt.Errorf("%w: invalid MIME type", ErrInvalidRequest)
	}
	if request.SizeBytes <= 0 {
		return Request{}, fmt.Errorf("%w: size_bytes must be positive", ErrInvalidRequest)
	}
	request.SHA256 = strings.ToLower(strings.TrimSpace(request.SHA256))
	if request.SHA256 != "" && !validSHA256(request.SHA256) {
		return Request{}, fmt.Errorf("%w: sha256 must be 64 hexadecimal characters", ErrInvalidRequest)
	}
	if !request.ExpiresAt.IsZero() && !request.ExpiresAt.After(now) {
		return Request{}, fmt.Errorf("%w: expires_at must be in the future", ErrInvalidRequest)
	}
	return request, nil
}

func validateVerifiedObject(request Request, verified VerifiedObject) error {
	if !validLowerSHA256(verified.SHA256) {
		return fmt.Errorf("%w: verified SHA256 is invalid", ErrIntegrity)
	}
	if request.SHA256 != "" && verified.SHA256 != request.SHA256 {
		return fmt.Errorf("%w: verified SHA256 mismatch", ErrIntegrity)
	}
	if verified.SizeBytes != request.SizeBytes {
		return fmt.Errorf("%w: verified size mismatch", ErrIntegrity)
	}
	if _, err := canonicalMIME(verified.MIMEType); err != nil || len(verified.MIMEType) > 128 || !utf8.ValidString(verified.MIMEType) {
		return fmt.Errorf("%w: verified MIME is invalid", ErrIntegrity)
	}
	if err := validateStoragePath(request, verified.StoragePath); err != nil {
		return err
	}
	return nil
}

func validateVerifiedObjectFromSession(session *Session, verified VerifiedObject) error {
	request := Request{
		Owner:   identity.Member{OrganizationID: session.OrganizationID, UserID: session.UserID},
		Purpose: session.Purpose, Filename: session.Filename, FileExt: session.FileExt,
		MIMEType: session.MIMEType, SizeBytes: session.SizeBytes, SHA256: session.SHA256,
	}
	return validateVerifiedObject(request, verified)
}

func coreFileFromVerified(session *Session, verified VerifiedObject) *storage.CoreFileInfo {
	canonicalSHA256 := strings.ToLower(strings.TrimSpace(verified.SHA256))
	return &storage.CoreFileInfo{
		OrganizationID: session.OrganizationID, UserID: session.UserID, Purpose: session.Purpose,
		Filename: session.Filename, FileExt: session.FileExt, MIMEType: verified.MIMEType,
		Size: verified.SizeBytes, Hash: "sha256:" + canonicalSHA256, StoragePath: verified.StoragePath,
	}
}

func validateMultipartParts(session *Session, parts []storage.MultipartUploadPart) error {
	if len(parts) != int(session.PartCount) || len(parts) > maxPartCount {
		return fmt.Errorf("%w: multipart part count mismatch", ErrInvalidRequest)
	}
	seen := make(map[int32]struct{}, len(parts))
	for _, part := range parts {
		if part.PartNumber < 1 || part.PartNumber > session.PartCount || strings.TrimSpace(part.ETag) == "" || strings.ContainsAny(part.ETag, "\r\n") || len(part.ETag) > 1024 {
			return fmt.Errorf("%w: invalid multipart part", ErrInvalidRequest)
		}
		if _, exists := seen[part.PartNumber]; exists {
			return fmt.Errorf("%w: duplicate multipart part", ErrInvalidRequest)
		}
		seen[part.PartNumber] = struct{}{}
	}
	return nil
}

func validateStoragePath(request Request, storagePath string) error {
	if storagePath == "" || len(storagePath) > 512 || !utf8.ValidString(storagePath) || strings.Contains(storagePath, "\\") || path.Clean(storagePath) != storagePath || path.IsAbs(storagePath) {
		return fmt.Errorf("%w: invalid storage path", ErrIntegrity)
	}
	for _, character := range storagePath {
		if unicode.IsControl(character) {
			return fmt.Errorf("%w: invalid storage path", ErrIntegrity)
		}
	}
	components := strings.Split(storagePath, "/")
	if len(components) < 2 || components[0] != request.Purpose {
		return fmt.Errorf("%w: storage path is outside the upload namespace", ErrIntegrity)
	}
	return nil
}

func validPurpose(value string) bool {
	if value == "" || len(value) > 32 || !utf8.ValidString(value) {
		return false
	}
	return strings.Trim(value, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_") == ""
}

func validFilename(value string) bool {
	if value == "" || value == "." || value == ".." || !utf8.ValidString(value) || utf8.RuneCountInString(value) > 255 || strings.ContainsAny(value, "/\\") {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func validFileExt(value string) bool {
	if len(value) < 2 || len(value) > 16 || value[0] != '.' {
		return false
	}
	for _, character := range value[1:] {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') {
			return false
		}
	}
	return true
}

func validSHA256(value string) bool { return len(value) == 64 && isHex(value) }

func validLowerSHA256(value string) bool {
	return len(value) == 64 && strings.Trim(value, "0123456789abcdef") == ""
}

func isHex(value string) bool {
	for _, character := range value {
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f') || (character >= 'A' && character <= 'F')) {
			return false
		}
	}
	return value != ""
}

func validateOwnerAndID(owner identity.Member, id string) error {
	if err := owner.Validate(); err != nil {
		return fmt.Errorf("%w: invalid owner", ErrInvalidRequest)
	}
	id = strings.TrimSpace(id)
	parsed, err := uuid.Parse(id)
	if err != nil || parsed.String() != strings.ToLower(id) {
		return fmt.Errorf("%w: id must be a canonical UUID", ErrInvalidRequest)
	}
	return nil
}

func validateContext(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("%w: context is required", ErrInvalidRequest)
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	return nil
}

func newLeaseToken() (string, error) {
	var token [32]byte
	if _, err := rand.Read(token[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(token[:]), nil
}

func mapServiceError(err error) error {
	if err == nil {
		return nil
	}
	for _, stable := range []error{ErrInvalidRequest, ErrNotFound, ErrConflict, ErrExpired, ErrIntegrity, ErrUnavailable} {
		if errors.Is(err, stable) {
			return err
		}
	}
	return fmt.Errorf("%w: upload operation", ErrUnavailable)
}
