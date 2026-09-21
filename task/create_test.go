package task

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/JUXON-AI/jxpkg/dbtools"
)

// wellFormedTask 返回一条能通过全部校验的任务。用例只改动它们要针对的那一个字段，
// 这样一条用例失败时能确定是哪个条件被破坏了。
func wellFormedTask() *Task {
	return &Task{
		AppGroup:          "wzwx",
		SubjectID:         7,
		TaskType:          "wzwx.identify",
		Payload:           `{"job_id":"j-1","image":"1.png"}`,
		TaskConfigTimeout: time.Minute,
		TaskConfigRedo:    2,
	}
}

func TestValidateNewTaskAcceptsAWellFormedTask(t *testing.T) {
	if err := validateNewTask(wellFormedTask()); err != nil {
		t.Fatalf("validateNewTask refused a well-formed task: %v", err)
	}
}

func TestValidateNewTaskRefusesNil(t *testing.T) {
	if err := validateNewTask(nil); err == nil {
		t.Fatal("validateNewTask accepted a nil task")
	}
}

// 每一个被拒绝的字段都要有独立的用例：漏掉一个，那条规则就只由 CreateTask 守着，
// 批量路径会静默放行。
func TestValidateNewTaskRefusesEachMissingField(t *testing.T) {
	cases := []struct {
		name    string
		corrupt func(*Task)
		want    string
	}{
		{"app_group 为空", func(tsk *Task) { tsk.AppGroup = "" }, "app_group cannot be empty"},
		{"subject_id 为零", func(tsk *Task) { tsk.SubjectID = 0 }, "subject_id cannot be zero"},
		{"task_type 为空", func(tsk *Task) { tsk.TaskType = "" }, "task_type cannot be empty"},
		{"payload 为空", func(tsk *Task) { tsk.Payload = "" }, "payload cannot be empty"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			tsk := wellFormedTask()
			testCase.corrupt(tsk)
			err := validateNewTask(tsk)
			if err == nil {
				t.Fatalf("validateNewTask accepted a task with %s", testCase.name)
			}
			if err.Error() != testCase.want {
				t.Fatalf("validateNewTask said %q, want %q", err.Error(), testCase.want)
			}
		})
	}
}

// 超时与重试是数量而不是标志位，边界必须按 >0 / >=0 而不是 !=0 判定：
// timeout 为 0 的任务永远不会被判定超时，redo 为 0 是合法的「不重试」。
func TestValidateNewTaskBoundaries(t *testing.T) {
	cases := []struct {
		name    string
		timeout time.Duration
		redo    int
		wantErr string
	}{
		{"timeout 为 0", 0, 0, "task_config_timeout must be greater than zero"},
		{"timeout 为负", -time.Second, 0, "task_config_timeout must be greater than zero"},
		{"timeout 为 1ns", time.Nanosecond, 0, ""},
		{"redo 为 0", time.Minute, 0, ""},
		{"redo 为负", time.Minute, -1, "task_config_redo cannot be negative"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			tsk := wellFormedTask()
			tsk.TaskConfigTimeout = testCase.timeout
			tsk.TaskConfigRedo = testCase.redo
			err := validateNewTask(tsk)
			if testCase.wantErr == "" {
				if err != nil {
					t.Fatalf("validateNewTask refused a legal boundary: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("validateNewTask accepted %s", testCase.name)
			}
			if err.Error() != testCase.wantErr {
				t.Fatalf("validateNewTask said %q, want %q", err.Error(), testCase.wantErr)
			}
		})
	}
}

// 两条创建路径必须对同一批输入给出同一套拒绝理由。这个性质是 validateNewTask 存在的
// 唯一原因，所以它自己要有用例：一旦有人把某条规则改回内联在单条路径上，这里就红。
func TestCreateTaskAndCreateTasksRefuseTheSameThings(t *testing.T) {
	corruptions := map[string]func(*Task){
		"nil":           nil,
		"app_group 为空":  func(tsk *Task) { tsk.AppGroup = "" },
		"subject_id 为零": func(tsk *Task) { tsk.SubjectID = 0 },
		"task_type 为空":  func(tsk *Task) { tsk.TaskType = "" },
		"payload 为空":    func(tsk *Task) { tsk.Payload = "" },
		"timeout 为零":    func(tsk *Task) { tsk.TaskConfigTimeout = 0 },
		"redo 为负":       func(tsk *Task) { tsk.TaskConfigRedo = -1 },
	}
	for name, corrupt := range corruptions {
		t.Run(name, func(t *testing.T) {
			single := wellFormedTask()
			batch := wellFormedTask()
			if corrupt != nil {
				corrupt(single)
				corrupt(batch)
			} else {
				single, batch = nil, nil
			}

			singleErr := CreateTask(context.Background(), single)
			if singleErr == nil {
				t.Fatalf("CreateTask accepted a task with %s", name)
			}
			batchErr := CreateTasks(context.Background(), []*Task{batch})
			if batchErr == nil {
				t.Fatalf("CreateTasks accepted a task with %s", name)
			}
			if !strings.Contains(batchErr.Error(), singleErr.Error()) {
				t.Fatalf("the two paths disagree on %s: CreateTask said %q, CreateTasks said %q",
					name, singleErr.Error(), batchErr.Error())
			}
		})
	}
}

func TestCreateTasksRefusesAnEmptyBatch(t *testing.T) {
	if err := CreateTasks(context.Background(), nil); err == nil {
		t.Fatal("CreateTasks accepted a nil batch")
	}
	if err := CreateTasks(context.Background(), []*Task{}); err == nil {
		t.Fatal("CreateTasks accepted an empty batch")
	}
}

// 全有全无是这条路径存在的理由，而这个用例是它唯一的证据：批次里第 4 条不合法，
// 期望拿到带下标的校验错误而不是一次数据库写入。
//
// 判据来自 dbtools.DB：连接未注册时它 panic，注册了才返回 *gorm.DB。本包没有任何
// init 去注册连接，所以未配置数据库时——也正是测试的默认状态——走到写库这一步必然
// panic。于是「返回了校验错误而没有 panic」就等价于「校验在写库之前跑完了、一条都没
// 写」。若数据库恰好被配置了，这个前提不成立，用例会跳过而不是给出假证据。
func TestCreateTasksValidatesTheWholeBatchBeforeWriting(t *testing.T) {
	if dbtools.DBExists("core") {
		t.Skip("core 数据库已注册，这个用例要的「写库必然 panic」前提不成立")
	}

	tasks := []*Task{wellFormedTask(), wellFormedTask(), wellFormedTask(), wellFormedTask()}
	tasks[1].TaskType = "wzwx.embed"
	tasks[3].Payload = ""

	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("CreateTasks reached the database despite tasks[3] being invalid "+
				"(panicked on %v); validation must finish for the whole batch before any write", recovered)
		}
	}()
	err := CreateTasks(context.Background(), tasks)
	if err == nil {
		t.Fatal("CreateTasks accepted a batch with an invalid element")
	}
	if !strings.Contains(err.Error(), "tasks[3]") {
		t.Fatalf("the error does not name the offending index: %v", err)
	}
	if !strings.Contains(err.Error(), "payload cannot be empty") {
		t.Fatalf("the error does not carry the rejection reason: %v", err)
	}
}

// 不合法的那条在最前面时，后面的合法条目也不得被写进去：校验要扫完整个批次，
// 而不是遇到第一个错误才停下之前先写一部分。
func TestCreateTasksReportsTheFirstInvalidElementInOrder(t *testing.T) {
	if dbtools.DBExists("core") {
		t.Skip("core 数据库已注册，这个用例要的「写库必然 panic」前提不成立")
	}

	tasks := []*Task{wellFormedTask(), wellFormedTask(), wellFormedTask()}
	tasks[0].AppGroup = ""
	tasks[2].TaskType = ""

	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("CreateTasks reached the database despite an invalid batch (panicked on %v)", recovered)
		}
	}()
	err := CreateTasks(context.Background(), tasks)
	if err == nil {
		t.Fatal("CreateTasks accepted an invalid batch")
	}
	if !strings.Contains(err.Error(), "tasks[0]") {
		t.Fatalf("the error names the wrong element, want the first one: %v", err)
	}
}

// 批量推送同样先校验：空批次不碰 Redis，所以这个用例不需要 Redis 也能跑。
func TestPushTaskQueuesRefusesAnEmptyBatch(t *testing.T) {
	if err := pushTaskQueues(context.Background(), nil); err == nil {
		t.Fatal("pushTaskQueues accepted a nil batch")
	}
	if err := pushTaskQueues(context.Background(), []string{}); err == nil {
		t.Fatal("pushTaskQueues accepted an empty batch")
	}
}
