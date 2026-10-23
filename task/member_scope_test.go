package task

import (
	"context"
	"strings"
	"sync"
	"testing"

	"gorm.io/gorm"
	"gorm.io/gorm/schema"
)

func TestTaskMemberPredicateUsesBothIdentityFieldsAndFailsClosed(t *testing.T) {
	db, _, _ := callbackCASDB(t, 0)
	for _, tc := range []struct {
		org, user string
		valid     bool
	}{{"org-a", "user-a", true}, {"org-b", "user-a", true}, {"org-a", "user-b", true}, {"", "user-a", false}, {"org-a", "", false}, {"org-a", strings.Repeat("u", 129), false}} {
		var row Task
		result := NewTaskDao().BuildCondition(db.Session(&gorm.Session{DryRun: true}), &TaskCond{BaseCond: BaseCond{OrganizationID: tc.org, UserID: tc.user}}).Find(&row)
		if result.Error != nil {
			t.Fatal(result.Error)
		}
		sql := result.Statement.SQL.String()
		if !tc.valid {
			if !strings.Contains(sql, "1 = 0") {
				t.Fatal("missing member scope did not fail closed")
			}
			continue
		}
		if !strings.Contains(sql, "core_task.organization_id = ?") || !strings.Contains(sql, "core_task.user_id = ?") || len(result.Statement.Vars) != 2 || result.Statement.Vars[0] != tc.org || result.Statement.Vars[1] != tc.user {
			t.Fatal("task query lost organization or user boundary")
		}
	}
}

func TestTaskDependencyQueriesKeepMemberBoundary(t *testing.T) {
	db, _, _ := callbackCASDB(t, 0)
	dry := db.Session(&gorm.Session{DryRun: true})
	var rows []*Task
	result := eligibleDependencyQuery(dry.Model(&Task{}), "member-dependent").Find(&rows)
	query := result.Statement.SQL.String()
	for _, predicate := range []string{
		"GROUP BY organization_id, user_id, subject_id, app_group",
		"ready.organization_id = core_task.organization_id",
		"ready.user_id = core_task.user_id",
	} {
		if !strings.Contains(query, predicate) {
			t.Errorf("candidate query lost member dependency boundary: %s", predicate)
		}
	}
	var wakeSQL string
	var wakeVars []any
	if err := dry.Callback().Query().After("gorm:query").Register("test:member-wake", func(tx *gorm.DB) {
		wakeSQL = tx.Statement.SQL.String()
		wakeVars = append([]any(nil), tx.Statement.Vars...)
	}); err != nil {
		t.Fatal(err)
	}
	_, err := nextStepTasks(context.Background(), dry, &Task{OrganizationID: "org-a", UserID: "user-a", SubjectID: 42, AppGroup: "group", TaskType: "member-dependent", Step: 0})
	if err != nil {
		t.Fatal(err)
	}
	for _, predicate := range []string{
		"organization_id = ? AND user_id = ?",
		"t2.organization_id = core_task.organization_id",
		"t2.user_id = core_task.user_id",
	} {
		if !strings.Contains(wakeSQL, predicate) {
			t.Errorf("wake query lost member dependency boundary: %s", predicate)
		}
	}
	if len(wakeVars) < 2 || wakeVars[0] != "org-a" || wakeVars[1] != "user-a" {
		t.Fatal("wake query has no member values")
	}
}

func TestTaskIdentitySchemaPreservesCompleteCaseSensitiveMember(t *testing.T) {
	model, err := schema.Parse(&Task{}, &sync.Map{}, schema.NamingStrategy{})
	if err != nil {
		t.Fatal(err)
	}
	for name, kind := range map[string]string{
		"OrganizationID": "varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin",
		"UserID":         "varchar(128) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin",
	} {
		field := model.LookUpField(name)
		if field == nil || field.TagSettings["TYPE"] != kind {
			t.Errorf("task %s must preserve complete case-sensitive identity", name)
		}
	}
}

func TestNextStepRejectsMissingMemberBeforeDatabase(t *testing.T) {
	for _, task := range []*Task{nil, {OrganizationID: "org-a"}, {UserID: "user-a"}} {
		if _, err := nextStepTasks(context.Background(), nil, task); err == nil {
			t.Fatal("invalid stored member reached dependency lookup")
		}
	}
}
