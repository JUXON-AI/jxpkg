package dbtools

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestDatabasePoolOptions(t *testing.T) {
	for _, test := range []struct {
		name    string
		env     map[string]string
		want    poolOptions
		invalid bool
	}{
		{name: "standard defaults", want: poolOptions{maxIdle: 2}},
		{name: "configured", env: map[string]string{"JX_DB_ACCOUNT_MAX_OPEN_CONNS": "16", "JX_DB_ACCOUNT_MAX_IDLE_CONNS": "8", "JX_DB_ACCOUNT_CONN_MAX_IDLE_TIME": "10m", "JX_DB_ACCOUNT_CONN_MAX_LIFETIME": "30m"}, want: poolOptions{maxOpen: 16, maxIdle: 8, idleTime: 10 * time.Minute, lifetime: 30 * time.Minute}},
		{name: "other database isolated", env: map[string]string{"JX_DB_JXX_MAX_IDLE_CONNS": "8"}, want: poolOptions{maxIdle: 2}},
		{name: "zero idle", env: map[string]string{"JX_DB_ACCOUNT_MAX_IDLE_CONNS": "0"}},
		{name: "invalid number", env: map[string]string{"JX_DB_ACCOUNT_MAX_OPEN_CONNS": "oops"}, invalid: true},
		{name: "negative idle", env: map[string]string{"JX_DB_ACCOUNT_MAX_IDLE_CONNS": "-1"}, invalid: true},
		{name: "negative duration", env: map[string]string{"JX_DB_ACCOUNT_CONN_MAX_LIFETIME": "-1s"}, invalid: true},
		{name: "invalid duration", env: map[string]string{"JX_DB_ACCOUNT_CONN_MAX_IDLE_TIME": "oops"}, invalid: true},
		{name: "idle exceeds open", env: map[string]string{"JX_DB_ACCOUNT_MAX_OPEN_CONNS": "1"}, invalid: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := databasePoolOptions("account", func(key string) string { return test.env[key] })
			if (err != nil) != test.invalid || (!test.invalid && got != test.want) {
				t.Fatalf("options=%+v err=%v", got, err)
			}
		})
	}
}

type poolTestConnector struct {
	opened atomic.Int64
	closed atomic.Int64
}

func (connector *poolTestConnector) Connect(context.Context) (driver.Conn, error) {
	connector.opened.Add(1)
	return &poolTestConn{connector}, nil
}
func (connector *poolTestConnector) Driver() driver.Driver { return poolTestDriver{} }

type poolTestDriver struct{}

func (poolTestDriver) Open(string) (driver.Conn, error) { return nil, errors.New("use connector") }

type poolTestConn struct{ connector *poolTestConnector }

func (connection *poolTestConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("not used")
}
func (connection *poolTestConn) Begin() (driver.Tx, error) { return nil, errors.New("not used") }
func (connection *poolTestConn) Close() error              { connection.connector.closed.Add(1); return nil }

func TestConfiguredPoolRetainsBurstConnections(t *testing.T) {
	connector := &poolTestConnector{}
	db := sql.OpenDB(connector)
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Error(err)
		}
	})
	poolOptions{maxOpen: 16, maxIdle: 8}.apply(db)
	connections := make([]*sql.Conn, 6)
	for index := range connections {
		connection, err := db.Conn(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		connections[index] = connection
	}
	for _, connection := range connections {
		if err := connection.Close(); err != nil {
			t.Fatal(err)
		}
	}
	for range 6 {
		connection, err := db.Conn(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if err := connection.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if stats := db.Stats(); stats.Idle != 6 || stats.MaxOpenConnections != 16 || connector.opened.Load() != 6 || connector.closed.Load() != 0 {
		t.Fatalf("stats=%+v opened=%d closed=%d", stats, connector.opened.Load(), connector.closed.Load())
	}
}

func TestConfiguredPoolBoundsConcurrencyAndHonorsCancellation(t *testing.T) {
	db := sql.OpenDB(&poolTestConnector{})
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Error(err)
		}
	})
	poolOptions{maxOpen: 1, maxIdle: 1}.apply(db)
	connection, err := db.Conn(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := connection.Close(); err != nil {
			t.Error(err)
		}
	})
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Millisecond)
	defer cancel()
	if _, err := db.Conn(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error=%v", err)
	}
	if db.Stats().WaitCount != 1 {
		t.Fatalf("stats=%+v", db.Stats())
	}
}
