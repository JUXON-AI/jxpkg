//go:build integration

package task

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/JUXON-AI/jxpkg/identity"
)

func TestMemberDependencyIsolation(t *testing.T) {
	db := throughputDB(t)
	for _, mode := range []string{"discovery", "recheck", "wakeup", "own-blocker"} {
		t.Run(mode, func(t *testing.T) {
			group := fmt.Sprintf("member%d", time.Now().UnixNano())
			members := []identity.Member{
				{OrganizationID: "org-a", UserID: "user-a"},
				{OrganizationID: "org-b", UserID: "user-a"},
				{OrganizationID: "org-a", UserID: "user-b"},
			}
			var done, candidate *Task
			for at, member := range members {
				status := TaskStatusRunning
				if at == 0 || mode == "wakeup" {
					status = TaskStatusSuccess
				}
				if mode == "own-blocker" && at == 0 {
					status = TaskStatusRunning
				}
				predecessor := &Task{OrganizationID: member.OrganizationID, UserID: member.UserID, SubjectID: 42, AppGroup: group, TaskType: group, Step: 0, TaskStatus: status, TaskConfigRedo: 1}
				next := &Task{OrganizationID: member.OrganizationID, UserID: member.UserID, SubjectID: 42, AppGroup: group, TaskType: group, Step: 1, TaskStatus: TaskStatusPending, TaskConfigRedo: 1}
				if err := db.Create([]*Task{predecessor, next}).Error; err != nil {
					t.Fatal(err)
				}
				if at == 0 {
					done, candidate = predecessor, next
				}
			}
			t.Cleanup(func() {
				if err := db.Unscoped().Where("app_group = ?", group).Delete(&Task{}).Error; err != nil {
					t.Error(err)
				}
			})
			switch mode {
			case "discovery", "recheck", "own-blocker":
				var got *Task
				var err error
				if mode == "discovery" {
					got, err = claimPendingTask(context.Background(), db, group, "member-worker")
				} else {
					got, err = claimCandidate(context.Background(), db, candidate.ID, group, "member-worker")
				}
				if err != nil {
					t.Fatal(err)
				}
				if mode == "own-blocker" {
					if got != nil {
						t.Fatal("same-member predecessor did not block claim")
					}
				} else if got == nil || got.ID != candidate.ID {
					t.Fatal("another member's predecessor blocked the eligible task")
				}
			case "wakeup":
				got, err := nextStepTasks(context.Background(), db, done)
				if err != nil || len(got) != 1 || got[0].ID != candidate.ID {
					t.Fatalf("completion woke another member's tasks: count=%d err=%v", len(got), err)
				}
			}
		})
	}
}
