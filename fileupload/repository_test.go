package fileupload

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/JUXON-AI/jxpkg/identity"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

func TestGORMRepositoryLeaseSQLRequiresOwnerStateExpiryAndRowsAffected(t *testing.T) {
	db := newCASCaptureDB(t)
	repository := NewGORMRepository(db.db)
	owner := identity.Member{OrganizationID: "org-a", UserID: "user-a"}
	now := time.Date(2026, 11, 5, 8, 0, 0, 0, time.UTC)

	if _, err := repository.ClaimLease(context.Background(), owner, "00000000-0000-4000-8000-000000000001", StateCompleting, "lease-token", now, now.Add(time.Minute)); !errors.Is(err, ErrConflict) {
		t.Fatalf("ClaimLease() error = %v, want ErrConflict", err)
	}
	claimSQL := db.capture.last()
	for _, condition := range []string{
		"UPDATE `core_file_upload_sessions` SET",
		"organization_id = ?",
		"user_id = ?",
		"state = ? OR (state = ? AND lease_expires_at IS NOT NULL AND lease_expires_at <= ?)",
		"`lease_token`=?",
	} {
		if !strings.Contains(claimSQL, condition) {
			t.Fatalf("claim SQL = %q, want condition %q", claimSQL, condition)
		}
	}
	_, _ = repository.ClaimLease(context.Background(), owner, "00000000-0000-4000-8000-000000000001", StateAborting, "abort-token", now, now.Add(time.Minute))
	abortSQL := db.capture.last()
	for _, condition := range []string{
		"state = ? OR (state IN (?, ?) AND lease_expires_at IS NOT NULL AND lease_expires_at <= ?)",
		"`lease_token`=?",
	} {
		if !strings.Contains(abortSQL, condition) {
			t.Fatalf("abort claim SQL = %q, want condition %q", abortSQL, condition)
		}
	}

	if err := repository.ReleaseLease(context.Background(), owner, "00000000-0000-4000-8000-000000000001", "lease-token"); !errors.Is(err, ErrConflict) {
		t.Fatalf("ReleaseLease() error = %v, want ErrConflict", err)
	}
	releaseSQL := db.capture.last()
	for _, condition := range []string{"lease_token = ? AND state = ?", "`state`=?"} {
		if !strings.Contains(releaseSQL, condition) {
			t.Fatalf("release SQL = %q, want condition %q", releaseSQL, condition)
		}
	}
	if strings.Contains(releaseSQL, "lease_token = ? AND state IN") {
		t.Fatalf("release SQL can release aborting lease: %q", releaseSQL)
	}
}

func TestGORMRepositoryExpiredQueryExcludesTerminalStatesAndIsBounded(t *testing.T) {
	db := newCASCaptureDB(t)
	repository := NewGORMRepository(db.db)
	_, err := repository.ListExpired(context.Background(), time.Date(2026, 11, 5, 0, 0, 0, 0, time.UTC), 17)
	if err != nil {
		t.Fatal(err)
	}
	query := db.capture.last()
	for _, condition := range []string{
		"expires_at < ",
		"state = ? OR (state IN (?, ?) AND (lease_expires_at IS NULL OR lease_expires_at <= UTC_TIMESTAMP(3)))",
		"ORDER BY expires_at ASC, id ASC",
		"LIMIT ?",
	} {
		if !strings.Contains(query, condition) {
			t.Fatalf("expired SQL = %q, want condition %q", query, condition)
		}
	}
}

type captureDB struct {
	db      *gorm.DB
	capture *sqlCapture
}

func newCASCaptureDB(t *testing.T) captureDB {
	t.Helper()
	capture := &sqlCapture{}
	connection := sql.OpenDB(&sqlConnector{capture: capture})
	t.Cleanup(func() {
		if err := connection.Close(); err != nil {
			t.Error(err)
		}
	})
	db, err := gorm.Open(mysql.New(mysql.Config{Conn: connection, SkipInitializeWithVersion: true}), &gorm.Config{
		DisableAutomaticPing:   true,
		SkipDefaultTransaction: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return captureDB{db: db, capture: capture}
}

type sqlCapture struct {
	mu    sync.Mutex
	query string
}

func (capture *sqlCapture) set(query string) {
	capture.mu.Lock()
	capture.query = query
	capture.mu.Unlock()
}

func (capture *sqlCapture) last() string {
	capture.mu.Lock()
	defer capture.mu.Unlock()
	return capture.query
}

type sqlConnector struct{ capture *sqlCapture }

func (connector *sqlConnector) Connect(context.Context) (driver.Conn, error) {
	return &sqlConnection{capture: connector.capture}, nil
}
func (*sqlConnector) Driver() driver.Driver { return sqlDriver{} }

type sqlDriver struct{}

func (sqlDriver) Open(string) (driver.Conn, error) { return nil, errors.New("use isolated connector") }

type sqlConnection struct{ capture *sqlCapture }

func (*sqlConnection) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("unexpected prepare")
}
func (*sqlConnection) Begin() (driver.Tx, error) { return nil, errors.New("unexpected transaction") }
func (*sqlConnection) Close() error              { return nil }
func (connection *sqlConnection) ExecContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Result, error) {
	connection.capture.set(query)
	return driver.RowsAffected(0), nil
}
func (connection *sqlConnection) QueryContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Rows, error) {
	connection.capture.set(query)
	return emptyRows{}, nil
}

type emptyRows struct{}

func (emptyRows) Columns() []string         { return nil }
func (emptyRows) Close() error              { return nil }
func (emptyRows) Next([]driver.Value) error { return io.EOF }
