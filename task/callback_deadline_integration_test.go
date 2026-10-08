//go:build integration

package task

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestCallbackLookupHonorsDeadlineWhileDatabaseReadIsBlocked(t *testing.T) {
	db := throughputDB(t)
	row := taskFixture(t, db, 0, TaskStatusRunning, "callback-deadline", 1)
	pool, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	lock, err := pool.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if _, err := lock.ExecContext(context.Background(), "LOCK TABLES core_task WRITE"); err != nil {
		t.Fatal(err)
	}
	defer lock.ExecContext(context.Background(), "UNLOCK TABLES")
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, err = getTaskByIDAndWorkerID(ctx, row.ID, row.WorkerID)
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(started) > 2*time.Second {
		t.Fatalf("blocked callback lookup ignored deadline: %v, elapsed=%s", err, time.Since(started))
	}
}
