package storage

import (
	"reflect"
	"sync"
	"testing"

	"gorm.io/gorm/schema"
)

func TestFileMetadataStoresCompleteOrganizationMembership(t *testing.T) {
	model, err := schema.Parse(&CoreFileInfo{}, &sync.Map{}, schema.NamingStrategy{})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"CompanyID", "UIN", "Issuer"} {
		if _, ok := reflect.TypeOf(CoreFileInfo{}).FieldByName(name); ok {
			t.Errorf("obsolete file identity field remains: %s", name)
		}
	}
	for name, kind := range map[string]string{"OrganizationID": "varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin", "UserID": "varchar(128) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin"} {
		if field := model.LookUpField(name); field == nil || field.TagSettings["TYPE"] != kind {
			t.Errorf("file field %s cannot preserve complete case-sensitive identity", name)
		}
	}
}
