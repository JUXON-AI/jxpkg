package fileupload

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/JUXON-AI/jxpkg/dbtools"
	"github.com/JUXON-AI/jxpkg/identity"
	"github.com/JUXON-AI/jxpkg/storage"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const (
	// TableNameUploadSession 是 Core 通用上传会话表名。
	TableNameUploadSession = "core_file_upload_sessions"
)

// MigrationModels 返回通用上传需要显式迁移的 Core 模型。
func MigrationModels() []any {
	return []any{&Session{}, &storage.CoreFileInfo{}}
}

// InitDB 使用已初始化的 Core 连接显式迁移通用上传模型。
func InitDB() error {
	return dbtools.InitModel(dbtools.Core(), MigrationModels()...)
}

type gormRepository struct {
	db *gorm.DB
}

// NewGORMRepository 使用显式 Core 数据库连接创建上传会话仓储。
func NewGORMRepository(db *gorm.DB) Repository {
	return &gormRepository{db: db}
}

func (repository *gormRepository) CreateSession(ctx context.Context, session *Session) error {
	if repository.db == nil || ctx == nil || session == nil {
		return ErrInvalidRequest
	}
	result := repository.db.WithContext(ctx).
		Clauses(clause.OnConflict{DoNothing: true}).
		Create(session)
	if result.Error != nil {
		return fmt.Errorf("%w: insert upload session", ErrUnavailable)
	}
	if result.RowsAffected != 1 {
		return ErrConflict
	}
	return nil
}

func (repository *gormRepository) GetSession(ctx context.Context, owner identity.Member, id string) (*Session, error) {
	if err := validateRepositoryRead(repository.db, ctx, owner, id); err != nil {
		return nil, err
	}
	session := &Session{}
	result := repository.db.WithContext(ctx).
		Where("id = ? AND organization_id = ? AND user_id = ?", id, owner.OrganizationID, owner.UserID).
		First(session)
	if errors.Is(result.Error, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	if result.Error != nil {
		return nil, fmt.Errorf("%w: read upload session", ErrUnavailable)
	}
	return session, nil
}

func (repository *gormRepository) ClaimLease(
	ctx context.Context,
	owner identity.Member,
	id string,
	state State,
	token string,
	now, until time.Time,
) (*Session, error) {
	if err := validateRepositoryRead(repository.db, ctx, owner, id); err != nil {
		return nil, err
	}
	if (state != StateCompleting && state != StateAborting) || token == "" || !until.After(now) {
		return nil, ErrInvalidRequest
	}
	query := repository.db.WithContext(ctx).Model(&Session{}).
		Where("id = ? AND organization_id = ? AND user_id = ?", id, owner.OrganizationID, owner.UserID)
	switch state {
	case StateCompleting:
		query = query.Where("state = ? OR (state = ? AND lease_expires_at IS NOT NULL AND lease_expires_at <= ?)", StateActive, StateCompleting, now)
	case StateAborting:
		query = query.Where("state = ? OR (state IN (?, ?) AND lease_expires_at IS NOT NULL AND lease_expires_at <= ?)", StateActive, StateCompleting, StateAborting, now)
	}
	result := query.
		Updates(map[string]any{
			"state": state, "lease_token": token, "lease_expires_at": until, "updated_at": now,
		})
	if result.Error != nil {
		return nil, fmt.Errorf("%w: claim upload lease", ErrUnavailable)
	}
	if result.RowsAffected != 1 {
		return nil, ErrConflict
	}
	return repository.GetSession(ctx, owner, id)
}

func (repository *gormRepository) ReleaseLease(ctx context.Context, owner identity.Member, id, token string) error {
	if err := validateRepositoryRead(repository.db, ctx, owner, id); err != nil {
		return err
	}
	if token == "" {
		return ErrInvalidRequest
	}
	result := repository.db.WithContext(ctx).Model(&Session{}).
		Where("id = ? AND organization_id = ? AND user_id = ?", id, owner.OrganizationID, owner.UserID).
		Where("lease_token = ? AND state = ?", token, StateCompleting).
		Updates(map[string]any{
			"state": StateActive, "lease_token": "", "lease_expires_at": nil,
		})
	if result.Error != nil {
		return fmt.Errorf("%w: release upload lease", ErrUnavailable)
	}
	if result.RowsAffected != 1 {
		return ErrConflict
	}
	return nil
}

func (repository *gormRepository) Finish(
	ctx context.Context,
	owner identity.Member,
	id, token string,
	state State,
	now time.Time,
) error {
	if err := validateRepositoryRead(repository.db, ctx, owner, id); err != nil {
		return err
	}
	if token == "" || (state != StateAborted && state != StateExpired) {
		return ErrInvalidRequest
	}
	result := repository.db.WithContext(ctx).Model(&Session{}).
		Where("id = ? AND organization_id = ? AND user_id = ?", id, owner.OrganizationID, owner.UserID).
		Where("lease_token = ? AND state IN (?, ?) AND lease_expires_at > ?", token, StateCompleting, StateAborting, now).
		Updates(map[string]any{
			"state": state, "lease_token": "", "lease_expires_at": nil, "updated_at": now,
		})
	if result.Error != nil {
		return fmt.Errorf("%w: finish upload session", ErrUnavailable)
	}
	if result.RowsAffected != 1 {
		return ErrConflict
	}
	return nil
}

func (repository *gormRepository) FinalizeComplete(
	ctx context.Context,
	owner identity.Member,
	id, token string,
	now time.Time,
	file *storage.CoreFileInfo,
) (*storage.CoreFileInfo, error) {
	if err := validateRepositoryRead(repository.db, ctx, owner, id); err != nil {
		return nil, err
	}
	if token == "" || file == nil {
		return nil, ErrInvalidRequest
	}
	var completed *storage.CoreFileInfo
	err := repository.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		session := &Session{}
		result := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			Where("id = ? AND organization_id = ? AND user_id = ?", id, owner.OrganizationID, owner.UserID).
			First(session)
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return ErrNotFound
		}
		if result.Error != nil {
			return fmt.Errorf("%w: lock upload session", ErrUnavailable)
		}
		if session.State == StateCompleted && session.FileID != nil {
			existing := &storage.CoreFileInfo{}
			if err := tx.Where("id = ? AND organization_id = ? AND user_id = ?", *session.FileID, owner.OrganizationID, owner.UserID).First(existing).Error; err != nil {
				if errors.Is(err, gorm.ErrRecordNotFound) {
					return ErrConflict
				}
				return fmt.Errorf("%w: read completed file", ErrUnavailable)
			}
			completed = existing
			return nil
		}
		if session.State != StateCompleting || session.LeaseToken != token || session.LeaseExpiresAt == nil || !now.Before(*session.LeaseExpiresAt) {
			return ErrConflict
		}
		if err := tx.Create(file).Error; err != nil {
			return fmt.Errorf("%w: register core file", ErrUnavailable)
		}
		fileID := file.ID
		update := tx.Model(&Session{}).
			Where("id = ? AND organization_id = ? AND user_id = ?", id, owner.OrganizationID, owner.UserID).
			Where("state = ? AND lease_token = ? AND lease_expires_at > ?", StateCompleting, token, now).
			Updates(map[string]any{
				"state": StateCompleted, "file_id": fileID, "lease_token": "", "lease_expires_at": nil, "updated_at": now,
			})
		if update.Error != nil {
			return fmt.Errorf("%w: complete upload session", ErrUnavailable)
		}
		if update.RowsAffected != 1 {
			return ErrConflict
		}
		completed = file
		return nil
	})
	if err != nil {
		return nil, mapRepositoryError(err)
	}
	return completed, nil
}

func (repository *gormRepository) RegisterExisting(ctx context.Context, session *Session, file *storage.CoreFileInfo) (*storage.CoreFileInfo, error) {
	if session == nil || file == nil {
		return nil, ErrInvalidRequest
	}
	if err := validateRepositoryRead(repository.db, ctx, identity.Member{OrganizationID: session.OrganizationID, UserID: session.UserID}, session.ID); err != nil {
		return nil, err
	}
	var registered *storage.CoreFileInfo
	err := repository.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		existingSession := &Session{}
		result := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			Where("id = ? AND organization_id = ? AND user_id = ?", session.ID, session.OrganizationID, session.UserID).
			First(existingSession)
		switch {
		case result.Error == nil:
			if existingSession.State != StateCompleted || existingSession.FileID == nil {
				return ErrConflict
			}
			existingFile := &storage.CoreFileInfo{}
			if err := tx.Where("id = ? AND organization_id = ? AND user_id = ?", *existingSession.FileID, session.OrganizationID, session.UserID).First(existingFile).Error; err != nil {
				if errors.Is(err, gorm.ErrRecordNotFound) {
					return ErrConflict
				}
				return fmt.Errorf("%w: read existing core file", ErrUnavailable)
			}
			registered = existingFile
			return nil
		case !errors.Is(result.Error, gorm.ErrRecordNotFound):
			return fmt.Errorf("%w: read existing upload session", ErrUnavailable)
		}
		if err := tx.Create(file).Error; err != nil {
			return fmt.Errorf("%w: register existing core file", ErrUnavailable)
		}
		fileID := file.ID
		session.State, session.FileID = StateCompleted, &fileID
		insert := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(session)
		if insert.Error != nil {
			return fmt.Errorf("%w: register existing upload session", ErrUnavailable)
		}
		if insert.RowsAffected != 1 {
			return ErrConflict
		}
		registered = file
		return nil
	})
	if err != nil {
		return nil, mapRepositoryError(err)
	}
	return registered, nil
}

func (repository *gormRepository) UpdateFilePath(
	ctx context.Context,
	owner identity.Member,
	id string,
	fileID uint,
	expectedPath, storagePath string,
) (*storage.CoreFileInfo, error) {
	if err := validateRepositoryRead(repository.db, ctx, owner, id); err != nil {
		return nil, err
	}
	if fileID == 0 || expectedPath == "" || storagePath == "" {
		return nil, ErrInvalidRequest
	}
	var updated *storage.CoreFileInfo
	err := repository.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		session := &Session{}
		result := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			Where("id = ? AND organization_id = ? AND user_id = ?", id, owner.OrganizationID, owner.UserID).
			First(session)
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return ErrNotFound
		}
		if result.Error != nil {
			return fmt.Errorf("%w: lock completed upload session", ErrUnavailable)
		}
		if session.State != StateCompleted || session.FileID == nil || *session.FileID != fileID {
			return ErrConflict
		}
		file := &storage.CoreFileInfo{}
		result = tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			Where("id = ? AND organization_id = ? AND user_id = ?", fileID, owner.OrganizationID, owner.UserID).
			First(file)
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return ErrConflict
		}
		if result.Error != nil {
			return fmt.Errorf("%w: lock completed core file", ErrUnavailable)
		}
		if file.StoragePath == storagePath {
			updated = file
			return nil
		}
		if file.StoragePath != expectedPath {
			return ErrConflict
		}
		update := tx.Model(&storage.CoreFileInfo{}).
			Where("id = ? AND organization_id = ? AND user_id = ? AND storage_path = ?", fileID, owner.OrganizationID, owner.UserID, expectedPath).
			Update("storage_path", storagePath)
		if update.Error != nil {
			return fmt.Errorf("%w: update core file path", ErrUnavailable)
		}
		if update.RowsAffected != 1 {
			return ErrConflict
		}
		file.StoragePath = storagePath
		updated = file
		return nil
	})
	if err != nil {
		return nil, mapRepositoryError(err)
	}
	return updated, nil
}

func (repository *gormRepository) ListExpired(ctx context.Context, before time.Time, limit int) ([]*Session, error) {
	if repository.db == nil || ctx == nil || before.IsZero() || limit < 1 || limit > maxCleanupBatch {
		return nil, ErrInvalidRequest
	}
	sessions := make([]*Session, 0, limit)
	result := repository.db.WithContext(ctx).
		Where(
			"expires_at < ? AND (state = ? OR (state IN (?, ?) AND (lease_expires_at IS NULL OR lease_expires_at <= UTC_TIMESTAMP(3))))",
			before, StateActive, StateCompleting, StateAborting,
		).
		Order("expires_at ASC, id ASC").
		Limit(limit).
		Find(&sessions)
	if result.Error != nil {
		return nil, fmt.Errorf("%w: list expired upload sessions", ErrUnavailable)
	}
	return sessions, nil
}

func (repository *gormRepository) GetFile(ctx context.Context, owner identity.Member, id uint) (*storage.CoreFileInfo, error) {
	if repository.db == nil || ctx == nil || id == 0 {
		return nil, ErrInvalidRequest
	}
	file, err := storage.GetFileByID(repository.db.WithContext(ctx), owner, id)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		if errors.Is(err, identity.ErrInvalidMember) {
			return nil, ErrInvalidRequest
		}
		return nil, fmt.Errorf("%w: read core file", ErrUnavailable)
	}
	return file, nil
}

func validateRepositoryRead(db *gorm.DB, ctx context.Context, owner identity.Member, id string) error {
	if db == nil || ctx == nil || id == "" {
		return ErrInvalidRequest
	}
	if err := owner.Validate(); err != nil {
		return ErrInvalidRequest
	}
	return nil
}

func mapRepositoryError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, ErrInvalidRequest), errors.Is(err, ErrNotFound), errors.Is(err, ErrConflict), errors.Is(err, ErrUnavailable):
		return err
	default:
		return fmt.Errorf("%w: upload repository operation", ErrUnavailable)
	}
}
