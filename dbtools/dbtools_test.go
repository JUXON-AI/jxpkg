package dbtools

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/JUXON-AI/jxpkg/logs"
)

func TestRedactedDatabaseURL(t *testing.T) {
	t.Parallel()

	raw := "mysql://private-user:private-password@db.internal:3306/account?charset=utf8mb4&tls=true#private-fragment"
	got := redactedDatabaseURL(raw)
	if want := "mysql://db.internal:3306/account"; got != want {
		t.Fatalf("redactedDatabaseURL() = %q, want %q", got, want)
	}
	for _, secret := range []string{"private-user", "private-password", "charset", "private-fragment"} {
		if strings.Contains(got, secret) {
			t.Fatalf("redactedDatabaseURL() leaked %q in %q", secret, got)
		}
	}
}

func TestRedactedDatabaseURLRejectsIncompleteInput(t *testing.T) {
	t.Parallel()

	for _, raw := range []string{"", "not-a-url", "://broken"} {
		if got := redactedDatabaseURL(raw); got != "<invalid-database-url>" {
			t.Errorf("redactedDatabaseURL(%q) = %q", raw, got)
		}
	}
}

func TestConnect(t *testing.T) {
	ctx := context.Background()
	err := InitMutilDBConn(testDatabaseConns(t))
	if err != nil {
		logs.ErrorContextf(ctx, "[main] connect mysql failed, %s", err)
		return
	}
}

func TestMigrate(t *testing.T) {
	ctx := context.Background()
	err := InitMutilDBConn(testDatabaseConns(t))
	if err != nil {
		logs.ErrorContextf(ctx, "[main] connect mysql failed, %s", err)
		return
	}

	err = DoInitModels(InitDB)
	if err != nil {
		logs.ErrorContextf(ctx, "[main] migrate failed, %s", err)
		return
	}
}

func testDatabaseConns(t *testing.T) map[string]string {
	t.Helper()
	conns := map[string]string{
		"core":    os.Getenv("JXPKG_TEST_DB_CORE"),
		"account": os.Getenv("JXPKG_TEST_DB_ACCOUNT"),
		"jxone":   os.Getenv("JXPKG_TEST_DB_JXONE"),
	}
	for name, dsn := range conns {
		if dsn == "" {
			t.Skipf("skip database integration test: JXPKG_TEST_DB_%s is not set", name)
		}
	}
	return conns
}

type TestModel struct {
	ID   uint   `gorm:"primaryKey"`
	Name string `gorm:"size:255"`
}

func (TestModel) TableName() string {
	return "test_model"
}

func InitDB() error {
	return InitModel(
		Core(),
		&TestModel{},
	)
}
