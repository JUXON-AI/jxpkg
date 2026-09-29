//go:build integration

package task

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/JUXON-AI/jxpkg/dbtools"
	"gorm.io/gorm"
)

func throughputDB(t *testing.T) *gorm.DB {
	t.Helper()
	raw := os.Getenv("JX_TASK_TEST_DATABASE_URL")
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "mysql" || !strings.HasSuffix(u.Path, "_test") {
		t.Fatal("dedicated *_test MySQL database URL required")
	}
	db, err := dbtools.InitDBConn("core", raw)
	if err != nil {
		t.Fatal("test database unavailable")
	}
	if !db.Migrator().HasTable(&Task{}) {
		t.Fatal("explicit test schema setup required")
	}
	return db
}

func taskFixture(t *testing.T, db *gorm.DB, step int, status TaskStatus, group string, subject uint) *Task {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Millisecond)
	x := &Task{AppGroup: group, SubjectID: subject, TaskType: group, Step: step, TaskStatus: status, WorkerID: "test-worker", StartAt: &now, Payload: "fixture", TaskConfigRedo: 1, TaskConfigTimeout: time.Minute}
	if err := db.Create(x).Error; err != nil {
		t.Fatal(err)
	}
	return x
}

func TestThroughputIndependentTasksDoNotWakeTheirPeers(t *testing.T) {
	db := throughputDB(t)
	for _, size := range []int{300, 912} {
		group := fmt.Sprintf("perf%d", time.Now().UnixNano())
		tasks := make([]*Task, size)
		for i := range tasks {
			tasks[i] = &Task{AppGroup: group, SubjectID: 7, TaskType: group, Step: 0, TaskStatus: TaskStatusPending, Payload: "fixture"}
		}
		if err := db.CreateInBatches(tasks, 200).Error; err != nil {
			t.Fatal(err)
		}
		completed := tasks[0]
		completed.TaskStatus = TaskStatusSuccess
		if err := db.Model(completed).Update("task_status", TaskStatusSuccess).Error; err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		for range 20 {
			got, err := nextStepTasks(context.Background(), db, completed)
			if err != nil || len(got) != 0 {
				t.Fatalf("independent peers were broadcast again: count=%d err=%v", len(got), err)
			}
		}
		t.Logf("images=%d next-step lookups=20 elapsed=%s new-wakeups=0", size, time.Since(start))
	}
}

func TestThroughputNextStepHonorsDependenciesAndRetryBudget(t *testing.T) {
	db := throughputDB(t)
	group := fmt.Sprintf("step%d", time.Now().UnixNano())
	done := taskFixture(t, db, 0, TaskStatusSuccess, group, 8)
	blocker := taskFixture(t, db, 0, TaskStatusRunning, group, 8)
	queued := taskFixture(t, db, 1, TaskStatusPending, group, 8)
	taskFixture(t, db, 1, TaskStatusRunning, group, 8)
	exhausted := taskFixture(t, db, 1, TaskStatusFail, group, 8)
	if err := db.Model(exhausted).Update("redo", 2).Error; err != nil {
		t.Fatal(err)
	}
	taskFixture(t, db, 2, TaskStatusPending, group, 8)
	got, err := nextStepTasks(context.Background(), db, done)
	if err != nil || len(got) != 0 {
		t.Fatalf("blocked next step was queued: %v %v", got, err)
	}
	if err := db.Model(blocker).Update("task_status", TaskStatusCancel).Error; err != nil {
		t.Fatal(err)
	}
	got, err = nextStepTasks(context.Background(), db, done)
	if err != nil || len(got) != 1 || got[0].ID != queued.ID {
		t.Fatalf("cancel/success did not unblock exactly eligible next task: %v %v", got, err)
	}
}

func TestThroughputConcurrentClaimsAreUnique(t *testing.T) {
	db := throughputDB(t)
	group := fmt.Sprintf("claim%d", time.Now().UnixNano())
	for range 32 {
		taskFixture(t, db, 0, TaskStatusPending, group, 9)
	}
	var mu sync.Mutex
	ids := map[uint]bool{}
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Go(func() {
			for acquired, attempts := 0, 0; acquired < 2 && attempts < 1000; attempts++ {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				x, err := claimPendingTask(ctx, db, group, fmt.Sprint(i))
				cancel()
				if err != nil {
					t.Error(err)
					return
				}
				if x == nil {
					time.Sleep(time.Millisecond)
					continue
				}
				acquired++
				mu.Lock()
				if ids[x.ID] {
					t.Errorf("duplicate claim %d", x.ID)
				}
				ids[x.ID] = true
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	if len(ids) != 32 {
		t.Fatalf("claims=%d want 32", len(ids))
	}
}

func TestThroughputNotificationOutageDoesNotReportCreationFailure(t *testing.T) {
	db := throughputDB(t)
	group := fmt.Sprintf("notify%d", time.Now().UnixNano())
	x := &Task{AppGroup: group, SubjectID: 13, TaskType: group, Payload: "fixture", TaskConfigTimeout: time.Minute}
	err := createTasks(context.Background(), []*Task{x}, func() *gorm.DB { return db }, func(context.Context, []string) error { return errors.New("notification unavailable") })
	if err != nil || x.ID == 0 {
		t.Fatalf("committed task reported as failed: id=%d err=%v", x.ID, err)
	}
	var count int64
	if err := db.Model(&Task{}).Where("app_group = ?", group).Count(&count).Error; err != nil || count != 1 {
		t.Fatalf("durable tasks=%d err=%v", count, err)
	}
}

func TestThroughputTerminalAndReclaimedTasksCannotBeOverwritten(t *testing.T) {
	db := throughputDB(t)
	for _, state := range []TaskStatus{TaskStatusCancel, TaskStatusSuccess, TaskStatusFail} {
		group := fmt.Sprintf("end%d", time.Now().UnixNano())
		x := taskFixture(t, db, 0, TaskStatusRunning, group, 10)
		if err := db.Model(x).Update("task_status", state).Error; err != nil {
			t.Fatal(err)
		}
		x.TaskStatus = TaskStatusSuccess
		now := time.Now()
		x.EndAt = &now
		saved, err := finishClaim(context.Background(), db, x)
		if err != nil || saved {
			t.Fatalf("terminal overwritten: state=%s saved=%v err=%v", state, saved, err)
		}
	}
	x := taskFixture(t, db, 0, TaskStatusRunning, fmt.Sprintf("lease%d", time.Now().UnixNano()), 11)
	newStart := x.StartAt.Add(time.Second)
	if err := db.Model(&Task{}).Where("id = ?", x.ID).Update("start_at", newStart).Error; err != nil {
		t.Fatal(err)
	}
	x.TaskStatus = TaskStatusSuccess
	now := time.Now()
	x.EndAt = &now
	if saved, err := finishClaim(context.Background(), db, x); err != nil || saved {
		t.Fatalf("old claim overwrote new claim: %v %v", saved, err)
	}
}
