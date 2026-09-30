package task

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// casConnector executes generated GORM predicates against an isolated row.
// The worker and timestamp deliberately stay identical across attempts.
type casConnector struct {
	mu     sync.Mutex
	status TaskStatus
	redo   int64
	start  time.Time
	execs  int
}

func (c *casConnector) Connect(context.Context) (driver.Conn, error) { return &casConn{c}, nil }
func (c *casConnector) Driver() driver.Driver                        { return casDriver{} }

type casDriver struct{}

func (casDriver) Open(string) (driver.Conn, error) { return nil, errors.New("use connector") }

type casConn struct{ row *casConnector }

func (*casConn) Prepare(string) (driver.Stmt, error) { return nil, errors.New("unexpected prepare") }
func (*casConn) Close() error                        { return nil }
func (*casConn) Begin() (driver.Tx, error)           { return nil, errors.New("unexpected transaction") }
func (c *casConn) ExecContext(_ context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	c.row.mu.Lock()
	defer c.row.mu.Unlock()
	c.row.execs++
	if !strings.Contains(query, "id = ? AND worker_id = ? AND start_at = ? AND redo = ? AND task_status = ?") {
		return nil, errors.New("UPDATE has no full execution fence")
	}
	where := strings.Index(query, " WHERE ")
	if where < 0 {
		return nil, errors.New("UPDATE has no WHERE")
	}
	setArgs := strings.Count(query[:where], "?")
	if len(args) != setArgs+5 {
		return nil, errors.New("unexpected UPDATE arguments")
	}
	predicate := args[setArgs:]
	if predicate[0].Value != int64(7) || predicate[1].Value != "same-worker" || !predicate[2].Value.(time.Time).Equal(c.row.start) || predicate[3].Value != c.row.redo || predicate[4].Value != string(c.row.status) {
		return driver.RowsAffected(0), nil
	}
	set := query[strings.Index(query, " SET ")+5 : where]
	for i, assignment := range strings.Split(set, ",") {
		if strings.Contains(assignment, "`task_status`") {
			c.row.status = TaskStatus(args[i].Value.(string))
		}
		if strings.Contains(assignment, "`redo`") {
			c.row.redo = args[i].Value.(int64)
		}
	}
	return driver.RowsAffected(1), nil
}
func callbackCASDB(t *testing.T, redo int) (*gorm.DB, *Task, *casConnector) {
	t.Helper()
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	row := &casConnector{status: TaskStatusRunning, redo: int64(redo), start: now}
	connection := sql.OpenDB(row)
	t.Cleanup(func() { _ = connection.Close() })
	db, err := gorm.Open(mysql.New(mysql.Config{Conn: connection, SkipInitializeWithVersion: true}), &gorm.Config{SkipDefaultTransaction: true, DisableAutomaticPing: true})
	if err != nil {
		t.Fatal(err)
	}
	tsk := &Task{Model: gorm.Model{ID: 7}, WorkerID: "same-worker", StartAt: &now, Redo: redo, TaskStatus: TaskStatusRunning}
	return db, tsk, row
}
func TestCallbackRejectsOldAttemptWithFreshLookup(t *testing.T) {
	db, current, row := callbackCASDB(t, 1)
	claimed, err := claimCallback(context.Background(), db, current, 1)
	if err != nil || claimed || row.execs != 0 {
		t.Fatalf("old callback reached reservation: %v %v execs=%d", claimed, err, row.execs)
	}
	claimed, err = claimCallback(context.Background(), db, current, 2)
	if err != nil || !claimed {
		t.Fatalf("current execution refused: %v %v", claimed, err)
	}
}
func TestCallbackReclaimBetweenLookupAndReservation(t *testing.T) {
	db, old, row := callbackCASDB(t, 0)
	row.redo = 1
	if claimed, err := claimCallback(context.Background(), db, old, 1); err != nil || claimed {
		t.Fatalf("old reservation won new execution: %v %v", claimed, err)
	}
}
func TestCallbackConcurrentDuplicatesRunSideEffectOnce(t *testing.T) {
	db, current, _ := callbackCASDB(t, 2)
	var sideEffects atomic.Int32
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			claimed, err := claimCallback(context.Background(), db, current, 3)
			if err != nil {
				t.Error(err)
				return
			}
			if claimed {
				sideEffects.Add(1)
			}
		})
	}
	wg.Wait()
	if sideEffects.Load() != 1 {
		t.Fatalf("side effects=%d want 1", sideEffects.Load())
	}
}
func TestFinishClaimKeepsOriginalRedoInPredicate(t *testing.T) {
	for _, reclaimed := range []bool{false, true} {
		t.Run(map[bool]string{false: "current failure", true: "stale timeout"}[reclaimed], func(t *testing.T) {
			db, tsk, row := callbackCASDB(t, 1)
			if reclaimed {
				row.redo = 2
			}
			end := row.start.Add(time.Minute)
			tsk.TaskStatus, tsk.EndAt = TaskStatusFail, &end
			saved, err := finishClaim(context.Background(), db, tsk)
			if err != nil || saved == reclaimed {
				t.Fatalf("saved=%v reclaimed=%v err=%v", saved, reclaimed, err)
			}
			if row.redo != 2 {
				t.Fatalf("redo=%d want 2", row.redo)
			}
			if reclaimed && row.status != TaskStatusRunning {
				t.Fatal("old timeout changed new execution")
			}
		})
	}
}
func TestCallbackValidityRequiresAttemptAndTerminalOutcome(t *testing.T) {
	for _, attempt := range []int64{-1, 0, 1} {
		for _, status := range []TaskStatus{"", TaskStatusPending, TaskStatusRunning, TaskStatusCompleting, TaskStatusCancel, TaskStatusTimeout, TaskStatusSuccess, TaskStatusFail} {
			req := &TaskCallBackRequest{}
			req.Request.TaskID, req.Request.WorkerID, req.Request.Attempt, req.Request.Status = 7, "worker", attempt, status
			resp := &TaskCallBackResponse{}
			req.Validity(resp)
			want := attempt > 0 && (status == TaskStatusSuccess || status == TaskStatusFail)
			if (resp.Code == 0) != want {
				t.Errorf("attempt=%d status=%q accepted=%v want=%v", attempt, status, resp.Code == 0, want)
			}
		}
	}
}
