package storage

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/JUXON-AI/jxpkg/dbtools"
	"github.com/JUXON-AI/jxpkg/logs"
	"github.com/JUXON-AI/jxpkg/random"
	"gorm.io/gorm"
)

const (
	TableNameFileInfo = "core_upload_files"
)

// CoreFileInfo .
type CoreFileInfo struct {
	gorm.Model

	// CompanyID 表示文件所属的公司 ID。
	CompanyID uint `gorm:"column:company_id;type:bigint unsigned;not null;index:idx_core_upload_files_company_uin,priority:1;comment:文件所属公司ID" json:"company_id"`

	// UIN 表示文件所属的账户身份 ID。
	UIN uint `gorm:"column:uin;type:bigint unsigned;not null;index:idx_core_upload_files_company_uin,priority:2;comment:文件所属账户身份ID" json:"uin"`

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

// GetFileByHash 按公司、UIN 和内容哈希获取文件信息。
func GetFileByHash(db *gorm.DB, companyID, uin uint, hashstr string) (*CoreFileInfo, error) {
	fi := &CoreFileInfo{}
	sql := db.Model(fi).
		Where("company_id = ? AND uin = ? AND hash = ?", companyID, uin, hashstr)

	err := sql.First(fi).Error
	if err != nil {
		if err != gorm.ErrRecordNotFound {
			logs.Errorf("get file by hash failed, %v error: %v", hashstr, err)
		}
		return nil, err
	}
	if fi.ID == 0 {
		return nil, gorm.ErrRecordNotFound
	}
	return fi, nil
}

// GetFileByPublicURL 按公司、UIN 和公网地址获取文件信息。
func GetFileByPublicURL(db *gorm.DB, companyID, uin uint, publicURL string) (*CoreFileInfo, error) {
	fi := &CoreFileInfo{}
	sql := db.Model(fi).
		Where("company_id = ? AND uin = ? AND public_url = ?", companyID, uin, publicURL)

	err := sql.First(fi).Error
	if err != nil {
		if err != gorm.ErrRecordNotFound {
			logs.Errorf("get file by public url failed, %v error: %v", publicURL, err)
		}
		return nil, err
	}
	if fi.ID == 0 {
		return nil, gorm.ErrRecordNotFound
	}
	return fi, nil
}

// GetFileByID 按公司、UIN 和文件 ID 获取文件信息。
func GetFileByID(db *gorm.DB, companyID, uin, id uint) (*CoreFileInfo, error) {
	if companyID == 0 || uin == 0 || id == 0 {
		return nil, gorm.ErrRecordNotFound
	}
	fi := &CoreFileInfo{}
	sql := db.Model(fi).
		Where("company_id = ? AND uin = ? AND id = ?", companyID, uin, id)
	err := sql.First(fi).Error
	if err != nil {
		if err != gorm.ErrRecordNotFound {
			logs.Warnf("get file by id failed, id = %v,error: %v", id, err)
		}
		return nil, err
	}

	return fi, nil
}

// GenerateFileStoragePath 生成文件存储路径
func GenerateFileStoragePath(purpose string, owner uint, fileExt string) string {
	storagePath := fmt.Sprintf("%s/%s/%d-%s%s",
		purpose, time.Now().Format("20060102"), owner, random.String(9), fileExt)
	return storagePath
}

// GenerateFileStoragePathWithName 生成文件存储路径
func GenerateFileStoragePathWithName(purpose string, owner uint, fileName string) string {
	storagePath := fmt.Sprintf("%s/%s/%d-%s/%s",
		purpose, time.Now().Format("20060102"), owner, random.String(9), fileName)
	return storagePath
}

// GenerateFileHashByContent 根据文件内容生成文件hash
func GenerateFileHashByContent(content []byte) string {
	sum := md5.Sum(content)
	return "md5:" + hex.EncodeToString(sum[:])
}
