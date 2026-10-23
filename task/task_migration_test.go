package task

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"slices"
	"strings"
	"sync"
	"testing"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type taskMigrationTestIndex struct {
	name          string
	columns       []string
	unique        bool
	prefix        int64
	indexType     string
	collation     string
	invalidColumn bool
	sequenceStart int
	isVisible     string
}

type taskMigrationTestConnector struct {
	mu                sync.Mutex
	indexes           []taskMigrationTestIndex
	indexQueryErr     error
	createErr         error
	failCreateAt      int
	createCalls       int
	noDatabase        bool
	includeVisible    bool
	statisticsQueries []taskMigrationTestQuery
	execs             []string
}

type taskMigrationTestQuery struct {
	query string
	args  []driver.NamedValue
}

func (connector *taskMigrationTestConnector) Connect(context.Context) (driver.Conn, error) {
	return &taskMigrationTestConn{state: connector}, nil
}

func (*taskMigrationTestConnector) Driver() driver.Driver { return taskMigrationTestDriver{} }

type taskMigrationTestDriver struct{}

func (taskMigrationTestDriver) Open(string) (driver.Conn, error) {
	return nil, errors.New("task migration test requires its connector")
}

type taskMigrationTestConn struct {
	state *taskMigrationTestConnector
}

func (*taskMigrationTestConn) Prepare(string) (driver.Stmt, error) { return nil, driver.ErrSkip }
func (*taskMigrationTestConn) Close() error                        { return nil }
func (*taskMigrationTestConn) Begin() (driver.Tx, error) {
	return nil, errors.New("task migration test does not use transactions")
}

func (conn *taskMigrationTestConn) QueryContext(_ context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	conn.state.mu.Lock()
	defer conn.state.mu.Unlock()

	switch {
	case strings.Contains(query, "SELECT DATABASE()"):
		if conn.state.noDatabase {
			return &taskMigrationTestRows{columns: []string{"DATABASE()"}}, nil
		}
		return taskMigrationTestRowsFor("DATABASE()", "core"), nil
	case strings.Contains(query, "Information_schema.SCHEMATA"):
		if conn.state.noDatabase {
			return &taskMigrationTestRows{columns: []string{"SCHEMA_NAME"}}, nil
		}
		return taskMigrationTestRowsFor("SCHEMA_NAME", "core"), nil
	case strings.Contains(query, "STATISTICS"):
		conn.state.statisticsQueries = append(conn.state.statisticsQueries, taskMigrationTestQuery{
			query: query,
			args:  append([]driver.NamedValue(nil), args...),
		})
		if conn.state.indexQueryErr != nil {
			return nil, conn.state.indexQueryErr
		}
		rows := make([][]driver.Value, 0)
		for _, index := range conn.state.indexes {
			nonUnique := int64(1)
			if index.unique {
				nonUnique = 0
			}
			indexType := index.indexType
			if indexType == "" {
				indexType = "BTREE"
			}
			collation := index.collation
			if collation == "" {
				collation = "A"
			}
			for at, column := range index.columns {
				var columnName driver.Value = column
				if index.invalidColumn {
					columnName = nil
				}
				var prefix driver.Value
				if index.prefix > 0 {
					prefix = index.prefix
				}
				sequence := at + 1 + index.sequenceStart
				row := []driver.Value{index.name, columnName, nonUnique, int64(sequence), collation, prefix, indexType}
				if conn.state.includeVisible {
					visible := index.isVisible
					if visible == "" {
						visible = "YES"
					}
					row = append(row, visible)
				}
				rows = append(rows, row)
			}
		}
		columns := []string{"INDEX_NAME", "COLUMN_NAME", "NON_UNIQUE", "SEQ_IN_INDEX", "COLLATION", "SUB_PART", "INDEX_TYPE"}
		if conn.state.includeVisible {
			columns = append(columns, "IS_VISIBLE")
		}
		return &taskMigrationTestRows{columns: columns, rows: rows}, nil
	default:
		return nil, errors.New("unexpected task migration query")
	}
}

func (conn *taskMigrationTestConn) ExecContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Result, error) {
	conn.state.mu.Lock()
	defer conn.state.mu.Unlock()
	conn.state.execs = append(conn.state.execs, query)
	conn.state.createCalls++
	if conn.state.createErr != nil && (conn.state.failCreateAt == 0 || conn.state.createCalls == conn.state.failCreateAt) {
		return nil, conn.state.createErr
	}

	const prefix = "CREATE INDEX `"
	start := strings.Index(query, prefix)
	if start < 0 {
		return nil, errors.New("unexpected task index DDL")
	}
	start += len(prefix)
	end := strings.IndexByte(query[start:], '`')
	open := strings.IndexByte(query, '(')
	close := strings.LastIndexByte(query, ')')
	if end < 0 || open < 0 || close <= open {
		return nil, errors.New("malformed task index DDL")
	}

	columns := make([]string, 0)
	for _, column := range strings.Split(query[open+1:close], ",") {
		columns = append(columns, strings.Trim(strings.TrimSpace(column), "`"))
	}
	conn.state.indexes = append(conn.state.indexes, taskMigrationTestIndex{
		name:    query[start : start+end],
		columns: columns,
	})
	return driver.RowsAffected(0), nil
}

type taskMigrationTestRows struct {
	columns []string
	rows    [][]driver.Value
	at      int
}

func taskMigrationTestRowsFor(column string, value driver.Value) *taskMigrationTestRows {
	return &taskMigrationTestRows{columns: []string{column}, rows: [][]driver.Value{{value}}}
}

func (rows *taskMigrationTestRows) Columns() []string { return rows.columns }
func (*taskMigrationTestRows) Close() error           { return nil }
func (rows *taskMigrationTestRows) Next(destination []driver.Value) error {
	if rows.at >= len(rows.rows) {
		return io.EOF
	}
	copy(destination, rows.rows[rows.at])
	rows.at++
	return nil
}

func openTaskMigrationTestDB(t *testing.T, connector *taskMigrationTestConnector) *gorm.DB {
	t.Helper()
	sqlDB := sql.OpenDB(connector)
	t.Cleanup(func() {
		if err := sqlDB.Close(); err != nil {
			t.Errorf("close task migration test database: %v", err)
		}
	})
	db, err := gorm.Open(mysql.New(mysql.Config{
		Conn:                      sqlDB,
		SkipInitializeWithVersion: true,
	}), &gorm.Config{
		DisableAutomaticPing: true,
		Logger:               logger.Discard,
	})
	if err != nil {
		t.Fatal(err)
	}
	return db
}

func TestEnsureTaskIndexesCreatesExactMySQLDDLAndRepeats(t *testing.T) {
	connector := &taskMigrationTestConnector{indexes: []taskMigrationTestIndex{{
		name:    "idx_core_task_dependency",
		columns: []string{"subject_id", "app_group", "step", "deleted_at", "task_status"},
	}}}
	db := openTaskMigrationTestDB(t, connector)

	if err := ensureTaskIndexes(db); err != nil {
		t.Fatalf("first task index migration: %v", err)
	}
	connector.mu.Lock()
	execs := slices.Clone(connector.execs)
	connector.mu.Unlock()
	want := []string{
		"CREATE INDEX `idx_core_task_claim` ON `core_task`(`task_type`,`deleted_at`,`task_status`,`priority`,`updated_at`)",
		"CREATE INDEX `idx_core_task_member_dependency` ON `core_task`(`organization_id`,`user_id`,`subject_id`,`app_group`,`step`,`deleted_at`,`task_status`)",
	}
	if !slices.Equal(execs, want) {
		t.Fatalf("index DDL=%q want=%q", execs, want)
	}

	if err := ensureTaskIndexes(db); err != nil {
		t.Fatalf("repeated task index migration: %v", err)
	}
	connector.mu.Lock()
	defer connector.mu.Unlock()
	if len(connector.execs) != len(want) {
		t.Fatalf("repeated migration executed %d DDL statements; want %d", len(connector.execs), len(want))
	}
	if !slices.ContainsFunc(connector.indexes, func(index taskMigrationTestIndex) bool {
		return index.name == "idx_core_task_dependency"
	}) {
		t.Fatal("legacy subject/app-group dependency index was removed")
	}
}

func TestEnsureTaskIndexesRejectsSameNameWrongColumns(t *testing.T) {
	tests := []struct {
		name    string
		columns []string
	}{
		{name: _taskClaimIndexName, columns: []string{"deleted_at", "task_type", "task_status", "priority", "updated_at"}},
		{name: _taskMemberDependencyIndexName, columns: []string{"organization_id", "user_id", "subject_id", "app_group", "deleted_at", "step", "task_status"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			connector := &taskMigrationTestConnector{indexes: []taskMigrationTestIndex{{
				name:    test.name,
				columns: test.columns,
			}}}
			db := openTaskMigrationTestDB(t, connector)

			err := ensureTaskIndexes(db)
			if err == nil || !strings.Contains(err.Error(), test.name) || !strings.Contains(err.Error(), "has columns") {
				t.Fatalf("wrong-column index error=%v", err)
			}
			connector.mu.Lock()
			defer connector.mu.Unlock()
			if len(connector.execs) != 0 {
				t.Fatalf("wrong-column migration changed indexes: %q", connector.execs)
			}
		})
	}
}

func TestEnsureTaskIndexesRejectsIncompleteSameNameIndex(t *testing.T) {
	tests := []struct {
		name      string
		index     taskMigrationTestIndex
		wantError string
	}{
		{
			name: "prefix",
			index: taskMigrationTestIndex{
				name:    _taskClaimIndexName,
				columns: []string{"task_type", "deleted_at", "task_status", "priority", "updated_at"},
				prefix:  12,
			},
			wantError: "column prefix",
		},
		{
			name: "fulltext",
			index: taskMigrationTestIndex{
				name:      _taskClaimIndexName,
				columns:   []string{"task_type", "deleted_at", "task_status", "priority", "updated_at"},
				indexType: "FULLTEXT",
			},
			wantError: "want BTREE",
		},
		{
			name: "descending",
			index: taskMigrationTestIndex{
				name:      _taskClaimIndexName,
				columns:   []string{"task_type", "deleted_at", "task_status", "priority", "updated_at"},
				collation: "D",
			},
			wantError: "ascending column order",
		},
		{
			name: "unique",
			index: taskMigrationTestIndex{
				name:    _taskClaimIndexName,
				columns: []string{"task_type", "deleted_at", "task_status", "priority", "updated_at"},
				unique:  true,
			},
			wantError: "want a non-unique index",
		},
		{
			name: "column count",
			index: taskMigrationTestIndex{
				name:    _taskClaimIndexName,
				columns: []string{"task_type", "deleted_at", "task_status", "priority"},
			},
			wantError: "has columns",
		},
		{
			name: "expression",
			index: taskMigrationTestIndex{
				name:          _taskClaimIndexName,
				columns:       []string{"task_type", "deleted_at", "task_status", "priority", "updated_at"},
				invalidColumn: true,
			},
			wantError: "not a full column",
		},
		{
			name: "sequence",
			index: taskMigrationTestIndex{
				name:          _taskClaimIndexName,
				columns:       []string{"task_type", "deleted_at", "task_status", "priority", "updated_at"},
				sequenceStart: 1,
			},
			wantError: "has sequence",
		},
		{
			name: "invisible",
			index: taskMigrationTestIndex{
				name:      _taskClaimIndexName,
				columns:   []string{"task_type", "deleted_at", "task_status", "priority", "updated_at"},
				isVisible: "NO",
			},
			wantError: "is hidden",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			connector := &taskMigrationTestConnector{
				indexes:        []taskMigrationTestIndex{test.index},
				includeVisible: test.index.isVisible != "",
			}
			db := openTaskMigrationTestDB(t, connector)

			err := ensureTaskIndexes(db)
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("incomplete index error=%v", err)
			}
			connector.mu.Lock()
			defer connector.mu.Unlock()
			if len(connector.execs) != 0 {
				t.Fatalf("incomplete index caused DDL: %q", connector.execs)
			}
		})
	}
}

func TestEnsureTaskIndexesAcceptsMySQL8VisibleIndexes(t *testing.T) {
	connector := &taskMigrationTestConnector{
		includeVisible: true,
		indexes: []taskMigrationTestIndex{
			{
				name:      _taskClaimIndexName,
				columns:   []string{"task_type", "deleted_at", "task_status", "priority", "updated_at"},
				isVisible: "YES",
			},
			{
				name:      _taskMemberDependencyIndexName,
				columns:   []string{"organization_id", "user_id", "subject_id", "app_group", "step", "deleted_at", "task_status"},
				isVisible: "YES",
			},
		},
	}
	db := openTaskMigrationTestDB(t, connector)

	if err := ensureTaskIndexes(db); err != nil {
		t.Fatalf("visible MySQL 8 indexes: %v", err)
	}
	connector.mu.Lock()
	defer connector.mu.Unlock()
	if len(connector.execs) != 0 {
		t.Fatalf("visible MySQL 8 indexes caused DDL: %q", connector.execs)
	}
}

func TestReadTaskIndexStatisticsRejectsMissingCurrentDatabase(t *testing.T) {
	connector := &taskMigrationTestConnector{noDatabase: true}
	db := openTaskMigrationTestDB(t, connector)

	_, err := readTaskIndexStatistics(db)
	if err == nil || !strings.Contains(err.Error(), "current database is unavailable") {
		t.Fatalf("missing current database error=%v", err)
	}
}

func TestTaskIndexColumnsRejectsUnknownMetadata(t *testing.T) {
	connector := &taskMigrationTestConnector{}
	db := openTaskMigrationTestDB(t, connector)

	_, err := taskIndexColumns(db, &taskClaimIndexMetadata{}, "missing_index")
	if err == nil || !strings.Contains(err.Error(), "is unavailable") {
		t.Fatalf("unknown index metadata error=%v", err)
	}

	var invalidMetadata int
	_, err = taskIndexColumns(db, &invalidMetadata, "invalid_metadata")
	if err == nil || !strings.Contains(err.Error(), "parse index metadata") {
		t.Fatalf("invalid index metadata error=%v", err)
	}
}

func TestReadTaskIndexStatisticsUsesOptionalColumns(t *testing.T) {
	connector := &taskMigrationTestConnector{}
	db := openTaskMigrationTestDB(t, connector)

	if _, err := readTaskIndexStatistics(db); err != nil {
		t.Fatalf("read task index statistics: %v", err)
	}
	connector.mu.Lock()
	defer connector.mu.Unlock()
	if len(connector.statisticsQueries) != 1 {
		t.Fatalf("statistics queries=%d want=1", len(connector.statisticsQueries))
	}
	query := connector.statisticsQueries[0]
	for _, fragment := range []string{
		"FROM `information_schema`.`STATISTICS`",
		"WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ?",
		"ORDER BY INDEX_NAME ASC, SEQ_IN_INDEX ASC",
	} {
		if !strings.Contains(query.query, fragment) {
			t.Fatalf("statistics query missing %q: %s", fragment, query.query)
		}
	}
	if strings.Contains(strings.ToUpper(query.query), "IS_VISIBLE") {
		t.Fatalf("statistics query hard-codes MySQL 8 columns: %s", query.query)
	}
	if len(query.args) != 2 || query.args[0].Value != "core" || query.args[1].Value != TableNameCoreTask {
		t.Fatalf("statistics query args=%+v", query.args)
	}
}

func TestEnsureTaskIndexesPropagatesMetadataReadFailure(t *testing.T) {
	readErr := errors.New("index metadata unavailable")
	connector := &taskMigrationTestConnector{indexQueryErr: readErr}
	db := openTaskMigrationTestDB(t, connector)

	if err := ensureTaskIndexes(db); !errors.Is(err, readErr) {
		t.Fatalf("metadata read error=%v", err)
	}
}

func TestEnsureTaskIndexesPropagatesCreateFailure(t *testing.T) {
	createErr := errors.New("index build rejected")
	connector := &taskMigrationTestConnector{createErr: createErr}
	db := openTaskMigrationTestDB(t, connector)

	if err := ensureTaskIndexes(db); !errors.Is(err, createErr) {
		t.Fatalf("index create error=%v", err)
	}
}

func TestEnsureTaskIndexesPropagatesSecondCreateFailure(t *testing.T) {
	createErr := errors.New("dependency index build rejected")
	connector := &taskMigrationTestConnector{createErr: createErr, failCreateAt: 2}
	db := openTaskMigrationTestDB(t, connector)

	if err := ensureTaskIndexes(db); !errors.Is(err, createErr) {
		t.Fatalf("dependency index create error=%v", err)
	}
}
