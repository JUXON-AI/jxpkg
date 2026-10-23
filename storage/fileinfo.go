package storage

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/JUXON-AI/jxpkg/dbtools"
	"github.com/JUXON-AI/jxpkg/identity"
	"gorm.io/gorm"
)

const (
	TableNameFileInfo = "core_upload_files"
)

// CoreFileInfo .
type CoreFileInfo struct {
	gorm.Model

	// OrganizationID 与 UserID 共同标识文件的成员归属，不从对象路径推断权限。
	OrganizationID string `gorm:"column:organization_id;type:varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin;not null;index:idx_core_upload_files_member,priority:1;comment:文件所属组织" json:"organization_id"`

	// UserID 保留完整 Logto 用户标识，不能脱离组织查询文件。
	UserID string `gorm:"column:user_id;type:varchar(128) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin;not null;index:idx_core_upload_files_member,priority:2;comment:文件所属用户" json:"user_id"`

	// Purpose 用途分类
	Purpose string `gorm:"column:purpose;type:varchar(32);comment:用途分类" json:"purpose"`
	// Filename 原始文件名
	Filename string `gorm:"column:filename;type:varchar(128);comment:原始文件名" json:"filename"`
	// FileExt 文件扩展名
	FileExt string `gorm:"column:file_ext;type:varchar(8);comment:文件扩展名" json:"file_ext"`
	// MIMEType MIME类型
	MIMEType string `gorm:"column:mime_type;type:varchar(128);comment:MIME类型" json:"mime_type"`
	// Size 文件大小
	Size int64 `gorm:"column:size;type:bigint;comment:文件大小" json:"size"`
	// Hash 文件hash hashMethod:hashValue
	Hash string `gorm:"column:hash;type:varchar(256);comment:文件hash ;index" json:"hash"`
	// StoragePath 存储的相对路径
	StoragePath string `gorm:"column:storage_path;type:varchar(255)" json:"storage_path"`
	// PublicURL 公网访问地址，如果为空，则表示只能通过预签名URL访问
	PublicURL string `gorm:"column:public_url;type:varchar(256);index" json:"public_url"`
}

// TableName table name
func (*CoreFileInfo) TableName() string {
	return TableNameFileInfo
}

// InitDB .
func InitDB() error {
	return dbtools.InitModel(
		dbtools.Core(), &CoreFileInfo{},
	)
}

// GetFileByHash 按已验证成员及内容哈希查询文件，不跨组织或用户去重。
func GetFileByHash(db *gorm.DB, member identity.Member, hashstr string) (*CoreFileInfo, error) {
	return findMemberFile(db, member, "hash", hashstr)
}

// GetFileByPublicURL 按已验证成员及地址查询文件；地址本身不代表访问权限。
func GetFileByPublicURL(db *gorm.DB, member identity.Member, publicURL string) (*CoreFileInfo, error) {
	return findMemberFile(db, member, "public_url", publicURL)
}

// GetFileByID 按已验证成员及文件 ID 查询，不用全局用户标识替代组织成员身份。
func GetFileByID(db *gorm.DB, member identity.Member, id uint) (*CoreFileInfo, error) {
	if id == 0 {
		return nil, gorm.ErrRecordNotFound
	}
	return findMemberFile(db, member, "id", id)
}

// column is chosen only by the three fixed lookup methods above, never by a request.
func findMemberFile(db *gorm.DB, member identity.Member, column string, value any) (*CoreFileInfo, error) {
	if err := member.Validate(); err != nil {
		return nil, err
	}
	if db == nil {
		return nil, errors.New("file metadata database unavailable")
	}
	fi := &CoreFileInfo{}
	if err := db.Where("organization_id = ? AND user_id = ?", member.OrganizationID, member.UserID).
		Where(column+" = ?", value).First(fi).Error; err != nil {
		return nil, err
	}
	return fi, nil
}

// GenerateFileStoragePath 为新对象生成路径；旧对象继续使用数据库里保存的原始路径。
func GenerateFileStoragePath(purpose string, owner identity.Member, fileExt string) (string, error) {
	if fileExt == "" || len(fileExt) > 16 || !strings.HasPrefix(fileExt, ".") || strings.Trim(fileExt[1:], "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") != "" || len(fileExt) == 1 {
		return "", errors.New("invalid file extension")
	}
	return GenerateFileStoragePathWithName(purpose, owner, "file"+fileExt)
}

// GenerateFileStoragePathWithName 使用组织、用户与随机对象目录分隔对象，名称不参与授权。
func GenerateFileStoragePathWithName(purpose string, owner identity.Member, fileName string) (string, error) {
	if err := owner.Validate(); err != nil {
		return "", err
	}
	if purpose == "" || len(purpose) > 32 || strings.Trim(purpose, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_") != "" || fileName == "" || !utf8.ValidString(fileName) || len(fileName) > 128 || fileName == "." || fileName == ".." || strings.ContainsAny(fileName, "/\\") {
		return "", errors.New("invalid file path component")
	}
	for _, character := range fileName {
		if unicode.IsControl(character) {
			return "", errors.New("invalid file path component")
		}
	}
	var entropy [16]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		return "", errors.New("file path entropy unavailable")
	}
	// NUL is forbidden by Member.Validate, so it unambiguously separates both identity fields.
	ownerHash := sha256.Sum256([]byte("jxfile-owner-v1\x00" + owner.OrganizationID + "\x00" + owner.UserID))
	return path.Join(purpose, time.Now().UTC().Format("20060102"), fmt.Sprintf("%x-%x", ownerHash[:8], entropy), fileName), nil
}

// GenerateFileHashByContent 根据文件内容生成文件hash
func GenerateFileHashByContent(content []byte) string {
	sum := md5.Sum(content)
	return "md5:" + hex.EncodeToString(sum[:])
}
