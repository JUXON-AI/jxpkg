package dbtools

import (
	"context"
	"os"
	"testing"

	"github.com/JUXON-AI/jxpkg/logs"
)

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
