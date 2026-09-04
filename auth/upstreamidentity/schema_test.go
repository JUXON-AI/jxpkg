package upstreamidentity

import (
	"crypto/sha256"
	"fmt"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"

	"gorm.io/gorm/schema"
)

var schemaMetadataFingerprints = map[string]string{
	TableNameUpstreamFederation: "68eb8317d6eb60fcdc31df48aa822e527c289c6b652411fa0581fa2d0a65b27a",
	TableNameExternalIdentity:   "6f0975b2497fd35a3f818cb2d990d24c1d87e4876be481798fc3a33e042cb4da",
	TableNameUpstreamEvent:      "a4a93ffeac3986ea25a799292712e3f2a00582cd35c5f204569e2b572b9d4a2c",
}

func schemaMetadataFingerprint(model any) string {
	typeOf := reflect.TypeOf(model)
	hash := sha256.New()
	for index := 0; index < typeOf.NumField(); index++ {
		field := typeOf.Field(index)
		fmt.Fprintf(hash, "%s\x00%s\x00%s\x00%s\n", field.Name, field.Type, field.Tag.Get("gorm"), field.Tag.Get("json"))
	}
	return fmt.Sprintf("%x", hash.Sum(nil))
}

func TestSharedModelsKeepTableAndFieldMetadataStable(t *testing.T) {
	tests := []struct {
		model     any
		tableName string
		fields    []string
	}{
		{
			model:     UpstreamFederation{},
			tableName: TableNameUpstreamFederation,
			fields:    []string{"ID", "ConnectionID", "TenantKey", "CompanyID", "Status", "Generation", "LastEventOrder", "Reconcile", "CreatedAt", "UpdatedAt"},
		},
		{
			model:     ExternalIdentity{},
			tableName: TableNameExternalIdentity,
			fields:    []string{"ID", "ProviderRegion", "ConnectionID", "TenantKey", "OpenID", "UnionID", "UpstreamUserID", "UserID", "Status", "Generation", "LastEventOrder", "Reconcile", "CreatedAt", "UpdatedAt"},
		},
		{
			model:     UpstreamEvent{},
			tableName: TableNameUpstreamEvent,
			fields:    []string{"ID", "ConnectionID", "EventID", "EventType", "ProviderRegion", "OpenID", "LifecycleStatus", "TenantKey", "PayloadHash", "EventOrder", "Disposition", "ProcessingStatus", "AffectedUserIDs", "CreatedAt", "ClaimUntil", "CompletedAt"},
		},
	}

	for _, test := range tests {
		t.Run(test.tableName, func(t *testing.T) {
			parsed, err := schema.Parse(test.model, &sync.Map{}, schema.NamingStrategy{})
			if err != nil {
				t.Fatal(err)
			}
			if parsed.Table != test.tableName {
				t.Fatalf("table = %q, want %q", parsed.Table, test.tableName)
			}

			if got := schemaMetadataFingerprint(test.model); got != schemaMetadataFingerprints[test.tableName] {
				t.Fatalf("schema metadata fingerprint = %s, want %s", got, schemaMetadataFingerprints[test.tableName])
			}

			typeOf := reflect.TypeOf(test.model)
			if typeOf.NumField() != len(test.fields) {
				t.Fatalf("field count = %d, want %d", typeOf.NumField(), len(test.fields))
			}
			for index, name := range test.fields {
				field := typeOf.Field(index)
				if field.Name != name {
					t.Fatalf("field %d = %q, want %q", index, field.Name, name)
				}
				if field.Tag.Get("gorm") == "" || field.Tag.Get("json") == "" {
					t.Fatalf("field %s must retain gorm and json metadata", field.Name)
				}
			}
		})
	}
}

func TestExternalIdentityKeepsLiteralCompositeUniqueConstraint(t *testing.T) {
	parsed, err := schema.Parse(&ExternalIdentity{}, &sync.Map{}, schema.NamingStrategy{})
	if err != nil {
		t.Fatal(err)
	}
	index := parsed.LookIndex("uk_external_identity_principal")
	if index == nil || index.Class != "UNIQUE" {
		t.Fatalf("unique index = %#v", index)
	}
	want := []string{"provider_region", "connection_id", "tenant_key", "open_id"}
	if len(index.Fields) != len(want) {
		t.Fatalf("fields = %#v", index.Fields)
	}
	for position, field := range index.Fields {
		if field.DBName != want[position] || field.Expression != "" || field.Length != 0 {
			t.Fatalf("field %d = %#v, want literal %q", position, field, want[position])
		}
	}
}

func TestSharedModelsExcludeSecretsAndMigrationBehavior(t *testing.T) {
	for _, model := range []any{UpstreamFederation{}, ExternalIdentity{}, UpstreamEvent{}} {
		typeOf := reflect.TypeOf(model)
		for index := 0; index < typeOf.NumField(); index++ {
			field := typeOf.Field(index)
			metadata := strings.ToLower(field.Name + " " + field.Tag.Get("json") + " " + field.Tag.Get("gorm"))
			for _, forbidden := range []string{"secret", "credential", "token", "authorization_code", "session", "csrf"} {
				if strings.Contains(metadata, forbidden) {
					t.Fatalf("%s exposes forbidden data %q", typeOf.Name(), forbidden)
				}
			}
		}
	}

	source, err := os.ReadFile("schema.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"AutoMigrate", "Migrator", "InitDB", "MigrationModels", "dbtools."} {
		if strings.Contains(string(source), forbidden) {
			t.Fatalf("schema contract must not offer migration behavior %q", forbidden)
		}
	}
}
