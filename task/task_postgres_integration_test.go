//go:build integration

package task

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/JUXON-AI/jxpkg/dbtools"
)

func TestPostgresTaskInitDBAndCallback(t *testing.T) {
	raw := os.Getenv("JX_TASK_TEST_DATABASE_URL")
	u, err := url.Parse(raw)
	if err != nil || !strings.HasSuffix(u.Path, "_test") {
		t.Fatal("dedicated *_test database URL required")
	}
	if u.Scheme != "postgres" && u.Scheme != "postgresql" {
		t.Skip("requires PostgreSQL")
	}
	db, err := dbtools.InitDBConn("core", raw)
	if err != nil {
		t.Fatal("test database unavailable")
	}
	if err := InitDB(); err != nil {
		t.Fatalf("provision task schema: %v", err)
	}

	group := fmt.Sprintf("pgcallback%d", time.Now().UnixNano())
	ctx := context.Background()
	row := &Task{
		OrganizationID: "Org-A", UserID: "User-A", AppGroup: group, SubjectID: 1 << 31,
		TaskType: group, TaskStatus: TaskStatusPending,
		Payload: `{"source":"战绩"}`, TaskConfigTimeout: time.Minute,
	}
	if err := createTasks(ctx, []*Task{row}, dbtools.Core, func(context.Context, []string) error { return nil }); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := db.Unscoped().Delete(row).Error; err != nil {
			t.Errorf("remove task fixture: %v", err)
		}
	})
	if row.ID == 0 {
		t.Fatal("creation did not populate the PostgreSQL identity")
	}
	if err := InitDB(); err != nil {
		t.Fatalf("re-run task schema migration: %v", err)
	}
	if count, err := GetPendingTaskCount(ctx, group); err != nil || count != 1 {
		t.Fatalf("pending count = %d, error = %v", count, err)
	}

	claimed, err := claimPendingTask(ctx, db, group, "pg-worker")
	if err != nil || claimed == nil || claimed.ID != row.ID || claimed.Payload != row.Payload {
		t.Fatalf("claim did not return the expected task: %v", err)
	}
	// Read the stored claim timestamp before testing callback fencing. The DB
	// stores microseconds and the worker obtains the same value via lookup.
	claimed, err = getTaskByIDAndWorkerID(ctx, row.ID, "pg-worker")
	if err != nil || claimed.StartAt == nil {
		t.Fatalf("read task claim: %v", err)
	}
	if ok, err := claimCallback(ctx, db, claimed, 1); err != nil || !ok {
		t.Fatalf("claim callback: %t, %v", ok, err)
	}
	if ok, err := claimCallback(ctx, db, claimed, 1); err != nil || ok {
		t.Fatalf("duplicate callback: %t, %v", ok, err)
	}
	now := time.Now()
	claimed.TaskStatus, claimed.Result, claimed.EndAt = TaskStatusSuccess, `{"done":true}`, &now
	if ok, err := finishClaimFromStatus(ctx, db, claimed, TaskStatusCompleting); err != nil || !ok {
		t.Fatalf("finish claim: %t, %v", ok, err)
	}
	saved, err := GetTaskByID(row.ID)
	if err != nil || saved.TaskStatus != TaskStatusSuccess || saved.Result != claimed.Result {
		t.Fatalf("read task outcome: %v", err)
	}
}
