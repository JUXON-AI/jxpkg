package fileupload

import (
	"reflect"
	"sync"
	"testing"

	"github.com/JUXON-AI/jxpkg/storage"
	"gorm.io/gorm/schema"
)

func TestSessionModelPersistsPublicStateAndFencedLease(t *testing.T) {
	model, err := schema.Parse(&Session{}, &sync.Map{}, schema.NamingStrategy{})
	if err != nil {
		t.Fatal(err)
	}
	if model.Table != TableNameUploadSession {
		t.Fatalf("table = %q, want %q", model.Table, TableNameUploadSession)
	}
	wants := map[string]string{
		"OrganizationID": "varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin",
		"UserID":         "varchar(128) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin",
		"Filename":       "varchar(255)",
		"FileExt":        "varchar(16)",
		"StoragePath":    "varchar(512)",
		"SHA256":         "char(64)",
		"Mode":           "varchar(16)",
		"State":          "varchar(16)",
		"LeaseToken":     "char(64)",
	}
	for name, want := range wants {
		field := model.LookUpField(name)
		if field == nil || field.TagSettings["TYPE"] != want {
			t.Errorf("session field %s type = %#v, want %q", name, field, want)
		}
	}
	fileIDField, exists := reflect.TypeOf(Session{}).FieldByName("FileID")
	if !exists || fileIDField.Type != reflect.TypeOf((*uint)(nil)) {
		t.Fatalf("Session.FileID type = %v, want *uint", fileIDField.Type)
	}
	if StateCompleted != "completed" {
		t.Fatalf("StateCompleted = %q", StateCompleted)
	}
	indexes := model.ParseIndexes()
	if len(indexes) != 1 || indexes[0].Name != "idx_core_file_upload_sessions_cleanup" || len(indexes[0].Fields) != 2 || indexes[0].Fields[0].Name != "State" || indexes[0].Fields[1].Name != "ExpiresAt" {
		t.Fatalf("cleanup indexes = %#v, want only (state, expires_at)", indexes)
	}
}

func TestCoreFileInfoWidthsMatchUploadContract(t *testing.T) {
	model, err := schema.Parse(&storage.CoreFileInfo{}, &sync.Map{}, schema.NamingStrategy{})
	if err != nil {
		t.Fatal(err)
	}
	wants := map[string]string{
		"Filename":    "varchar(255)",
		"FileExt":     "varchar(16)",
		"StoragePath": "varchar(512)",
	}
	for name, want := range wants {
		field := model.LookUpField(name)
		if field == nil || field.TagSettings["TYPE"] != want {
			t.Errorf("core file field %s type = %#v, want %q", name, field, want)
		}
	}
}
