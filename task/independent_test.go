package task

import (
	"context"
	"strings"
	"testing"
)

func TestIndependentProtocolRequiresStepZero(t *testing.T) {
	const kind = "test.independent.validation"
	RegisterIndependentTaskType(kind)
	tsk := wellFormedTask()
	tsk.TaskType = kind
	for _, step := range []int{-1, 0, 1} {
		tsk.Step = step
		err := validateNewTask(tsk)
		if (err == nil) != (step == 0) {
			t.Fatalf("step=%d accepted=%v", step, err == nil)
		}
	}
	tsk.TaskType = "test.default.dag"
	tsk.Step = -1
	if err := validateNewTask(tsk); err != nil {
		t.Fatal("default DAG negative step rejected")
	}
}

func TestIndependentCompletionDoesNotQueryDatabase(t *testing.T) {
	const kind = "test.independent.completion"
	RegisterIndependentTaskType(kind)
	rows, err := nextStepTasks(context.Background(), nil, &Task{TaskType: kind})
	if err != nil || len(rows) != 0 {
		t.Fatalf("rows=%d err=%v", len(rows), err)
	}
}

func TestIndependentRegistrationRejectsEmptyType(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("empty type accepted")
		}
	}()
	RegisterIndependentTaskType(strings.TrimSpace(" "))
}
