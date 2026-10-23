package settings

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type _settingsTestConnector struct {
	query func(context.Context, string, []driver.NamedValue) (driver.Rows, error)
}

func (connector *_settingsTestConnector) Connect(context.Context) (driver.Conn, error) {
	return &_settingsTestConn{query: connector.query}, nil
}

func (*_settingsTestConnector) Driver() driver.Driver { return _settingsTestDriver{} }

type _settingsTestDriver struct{}

func (_settingsTestDriver) Open(string) (driver.Conn, error) {
	return nil, errors.New("test connector requires Connect")
}

type _settingsTestConn struct {
	query func(context.Context, string, []driver.NamedValue) (driver.Rows, error)
}

func (*_settingsTestConn) Prepare(string) (driver.Stmt, error) { return nil, driver.ErrSkip }
func (*_settingsTestConn) Close() error                        { return nil }
func (*_settingsTestConn) Begin() (driver.Tx, error) {
	return nil, errors.New("transactions unsupported")
}
func (*_settingsTestConn) Ping(context.Context) error { return nil }

func (conn *_settingsTestConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	return conn.query(ctx, query, args)
}

type _settingsTestRows struct {
	columns []string
	values  []driver.Value
	done    bool
}

func (rows *_settingsTestRows) Columns() []string { return rows.columns }
func (*_settingsTestRows) Close() error           { return nil }
func (rows *_settingsTestRows) Next(destination []driver.Value) error {
	if rows.done {
		return io.EOF
	}
	rows.done = true
	copy(destination, rows.values)
	return nil
}

type _settingsQueryCapture struct {
	query string
	args  []driver.NamedValue
}

func TestGetYamlContextCarriesDeadlineIntoSQL(t *testing.T) {
	var (
		deadlineSeen = make(chan time.Time, 1)
		capture      = make(chan _settingsQueryCapture, 1)
		db, _        = openSettingsTestDB(t, func(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
			deadline, _ := ctx.Deadline()
			deadlineSeen <- deadline
			capture <- _settingsQueryCapture{query: query, args: append([]driver.NamedValue(nil), args...)}
			<-ctx.Done()
			return nil, ctx.Err()
		})
		deadline    = time.Now().Add(200 * time.Millisecond)
		ctx, cancel = context.WithDeadline(context.Background(), deadline)
	)
	defer cancel()

	var (
		value struct {
			InstanceID string `yaml:"instance_id"`
		}
		err = getYamlContext(ctx, db, "jxcredits", "newapi", &value)
	)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("getYamlContext error=%v", err)
	}
	if observed := <-deadlineSeen; !observed.Equal(deadline) {
		t.Fatalf("SQL deadline=%v want=%v", observed, deadline)
	}
	query := <-capture
	assertSettingsQueryShape(t, query)
}

func TestGetYamlContextStopsDuringConnectionPoolWait(t *testing.T) {
	var (
		queryCalled = make(chan struct{}, 1)
		db, sqlDB   = openSettingsTestDB(t, func(context.Context, string, []driver.NamedValue) (driver.Rows, error) {
			queryCalled <- struct{}{}
			return settingsRows("instance_id: unexpected\n"), nil
		})
	)
	sqlDB.SetMaxOpenConns(1)
	held, err := sqlDB.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if closeErr := held.Close(); closeErr != nil {
			t.Errorf("release held connection: %v", closeErr)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	var value struct {
		InstanceID string `yaml:"instance_id"`
	}
	err = getYamlContext(ctx, db, "jxcredits", "newapi", &value)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("pool wait error=%v", err)
	}
	select {
	case <-queryCalled:
		t.Fatal("expired pool wait still reached SQL")
	default:
	}
}

func TestGetYamlContextPreservesRowAndYAMLSemantics(t *testing.T) {
	t.Run("valid yaml", func(t *testing.T) {
		var (
			capture = make(chan _settingsQueryCapture, 1)
			db, _   = openSettingsTestDB(t, func(_ context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
				capture <- _settingsQueryCapture{query: query, args: append([]driver.NamedValue(nil), args...)}
				return settingsRows("instance_id: instance-a\nbase_url: https://models.example.com\nadmin_user_id: 7\nadmin_pat: nap_synthetic_test_pat_only\n"), nil
			})
			value struct {
				InstanceID string `yaml:"instance_id"`
				BaseURL    string `yaml:"base_url"`
				AdminID    int64  `yaml:"admin_user_id"`
				AdminPAT   string `yaml:"admin_pat"`
			}
		)
		if err := getYamlContext(context.Background(), db, "jxcredits", "newapi", &value); err != nil {
			t.Fatal(err)
		}
		if value.InstanceID != "instance-a" || value.BaseURL != "https://models.example.com" || value.AdminID != 7 || value.AdminPAT == "" {
			t.Fatalf("unexpected YAML value: %+v", value)
		}
		assertSettingsQueryShape(t, <-capture)
	})

	t.Run("missing row", func(t *testing.T) {
		var (
			db, _ = openSettingsTestDB(t, func(context.Context, string, []driver.NamedValue) (driver.Rows, error) {
				return emptySettingsRows(), nil
			})
			value any
		)
		if err := getYamlContext(context.Background(), db, "jxcredits", "newapi", &value); !errors.Is(err, gorm.ErrRecordNotFound) {
			t.Fatalf("missing row error=%v", err)
		}
	})

	t.Run("invalid yaml", func(t *testing.T) {
		var (
			db, _ = openSettingsTestDB(t, func(context.Context, string, []driver.NamedValue) (driver.Rows, error) {
				return settingsRows("instance_id: [broken\n"), nil
			})
			value map[string]any
		)
		if err := getYamlContext(context.Background(), db, "jxcredits", "newapi", &value); err == nil || errors.Is(err, gorm.ErrRecordNotFound) {
			t.Fatalf("invalid YAML error=%v", err)
		}
	})
}

func TestGetContextRejectsNilAndCanceledContexts(t *testing.T) {
	var (
		db, _ = openSettingsTestDB(t, func(context.Context, string, []driver.NamedValue) (driver.Rows, error) {
			return settingsRows("unused"), nil
		})
		nilCtx context.Context
	)
	if _, err := getContext(nilCtx, db, "jxcredits", "newapi"); !errors.Is(err, gorm.ErrInvalidDB) {
		t.Fatalf("nil context error=%v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := getContext(ctx, db, "jxcredits", "newapi"); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled context error=%v", err)
	}
}

func TestGetYamlContextRejectsNilContext(t *testing.T) {
	var (
		value  any
		nilCtx context.Context
	)
	if err := GetYamlContext(nilCtx, "jxcredits", "newapi", &value); !errors.Is(err, gorm.ErrInvalidDB) {
		t.Fatalf("nil public context error=%v", err)
	}
}

func TestGetYamlContextFailsClosedWithoutCoreDatabase(t *testing.T) {
	var value any
	if err := GetYamlContext(context.Background(), "jxcredits", "newapi", &value); !errors.Is(err, gorm.ErrInvalidDB) {
		t.Fatalf("missing core database error=%v", err)
	}
}

func openSettingsTestDB(t *testing.T, query func(context.Context, string, []driver.NamedValue) (driver.Rows, error)) (*gorm.DB, *sql.DB) {
	t.Helper()
	sqlDB := sql.OpenDB(&_settingsTestConnector{query: query})
	t.Cleanup(func() {
		if err := sqlDB.Close(); err != nil {
			t.Errorf("close settings test database: %v", err)
		}
	})
	db, err := gorm.Open(mysql.New(mysql.Config{Conn: sqlDB, SkipInitializeWithVersion: true}), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatal(err)
	}
	return db, sqlDB
}

func settingsRows(yamlValue string) driver.Rows {
	now := time.Unix(1, 0).UTC()
	return &_settingsTestRows{
		columns: []string{"id", "created_at", "updated_at", "deleted_at", "group", "name", "key", "describe", "value_type", "value", "default"},
		values: []driver.Value{
			int64(1), now, now, nil, "jxcredits", "New API", "newapi", "credits configuration", "yaml", yamlValue, "",
		},
	}
}

func emptySettingsRows() driver.Rows {
	return &_settingsTestRows{
		columns: []string{"id", "created_at", "updated_at", "deleted_at", "group", "name", "key", "describe", "value_type", "value", "default"},
		done:    true,
	}
}

func assertSettingsQueryShape(t *testing.T, capture _settingsQueryCapture) {
	t.Helper()
	if !strings.Contains(capture.query, "FROM `core_settings`") ||
		!strings.Contains(capture.query, "`group` = ?") ||
		!strings.Contains(capture.query, "`key` = ?") {
		t.Fatalf("unexpected settings query: %s", capture.query)
	}
	if len(capture.args) != 3 ||
		capture.args[0].Value != "jxcredits" ||
		capture.args[1].Value != "newapi" ||
		capture.args[2].Value != int64(1) {
		t.Fatalf("settings query args=%+v", capture.args)
	}
}

var (
	_ driver.QueryerContext = (*_settingsTestConn)(nil)
	_ driver.Pinger         = (*_settingsTestConn)(nil)
	_ driver.Connector      = (*_settingsTestConnector)(nil)
)
