package task

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/JUXON-AI/jxpkg/apis/runtime/server"
	"github.com/JUXON-AI/jxpkg/credits"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

func TestClaimRejectsOldAttemptOtherWorkerAndTerminalTasks(t *testing.T) {
	now := time.Now()
	start := now.Add(-time.Minute)
	base := Task{Model: gorm.Model{ID: 7}, CompanyID: 2, UIN: 3, Redo: 2, WorkerID: "worker-1", StartAt: &start, TaskStatus: TaskStatusRunning, TaskConfigTimeout: 2 * time.Minute}
	if !validClaim(&base, 7, "worker-1", 3, now) {
		t.Fatal("valid claim rejected")
	}
	for _, tc := range []struct {
		name    string
		mutate  func(*Task)
		id      uint
		worker  string
		attempt int64
	}{
		{"old_attempt", func(*Task) {}, 7, "worker-1", 2},
		{"other_worker", func(*Task) {}, 7, "worker-2", 3},
		{"other_task", func(*Task) {}, 8, "worker-1", 3},
		{"cancelled", func(t *Task) { t.TaskStatus = TaskStatusCancel }, 7, "worker-1", 3},
		{"expired", func(t *Task) { t.TaskConfigTimeout = time.Second }, 7, "worker-1", 3},
		{"no_employee", func(t *Task) { t.UIN = 0 }, 7, "worker-1", 3},
		{"new_claim", func(t *Task) { t.Redo++ }, 7, "worker-1", 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			row := base
			tc.mutate(&row)
			if validClaim(&row, tc.id, tc.worker, tc.attempt, now) {
				t.Fatal("invalid claim accepted")
			}
		})
	}
}

func TestWorkerRoutesValidateConfigAndGuardEveryAction(t *testing.T) {
	acquire := func(context.Context, credits.Subject) (credits.Connection, error) {
		t.Fatal("unexpected acquisition")
		return credits.Connection{}, nil
	}
	for _, token := range []string{"", "short", strings.Repeat("x", 31) + " ", strings.Repeat("x", 8193)} {
		router := server.NewRouter("/v1/")
		err := RegisterWorkerRoutes(router, "example", "queue", WorkerConfig{Token: token}, acquire)
		if err == nil || strings.Contains(err.Error(), token) && token != "" || len(router.GinEngine().Routes()) != 0 {
			t.Fatal("invalid configuration accepted, exposed, or partially registered")
		}
	}
	router := server.NewRouter("/v1/")
	if err := RegisterWorkerRoutes(router, "example", "queue", WorkerConfig{Token: strings.Repeat("x", 32)}, acquire); err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{"GetPendingTask", "TaskCallBack", "CheckInstance", "AcquireTaskModelConnection"} {
		w := httptest.NewRecorder()
		router.GinEngine().ServeHTTP(w, httptest.NewRequest("POST", "/v1/example."+action, strings.NewReader(`{"request":{}}`)))
		if w.Code != 401 {
			t.Fatalf("unguarded action %s: %d", action, w.Code)
		}
	}
}

func TestWorkerConnectionUsesAuthoritativeClaimAndRechecksAfterAcquisition(t *testing.T) {
	for _, name := range []string{"valid", "old_attempt", "cancelled_before", "cancelled_after", "new_claim", "changed_start", "changed_employee", "lookup_failure", "denied", "unavailable"} {
		t.Run(name, func(t *testing.T) {
			start := time.Now().Add(-time.Second)
			row := Task{Model: gorm.Model{ID: 7}, CompanyID: 2, UIN: 3, TaskType: "queue", Redo: 2, WorkerID: "worker-1", StartAt: &start, TaskStatus: TaskStatusRunning, TaskConfigTimeout: time.Minute}
			if name == "cancelled_before" {
				row.TaskStatus = TaskStatusCancel
			}
			acquisitions, lookups := 0, 0
			lookup := func(_ context.Context, id uint, workerID, queue string) (*Task, error) {
				lookups++
				if id != 7 || workerID != "worker-1" || queue != "queue" {
					t.Fatal("wrong task scope")
				}
				latest := row
				if lookups > 1 {
					switch name {
					case "cancelled_after":
						latest.TaskStatus = TaskStatusCancel
					case "new_claim":
						latest.Redo++
					case "changed_start":
						newer := start.Add(time.Second)
						latest.StartAt = &newer
					case "changed_employee":
						latest.UIN++
					case "lookup_failure":
						return nil, errors.New("database private failure")
					}
				}
				return &latest, nil
			}
			acquire := func(_ context.Context, subject credits.Subject) (credits.Connection, error) {
				acquisitions++
				if subject != (credits.Subject{CompanyID: 2, UIN: 3}) {
					t.Fatal("request overrode task employee")
				}
				if name == "denied" {
					return credits.Connection{}, credits.ErrDenied
				}
				if name == "unavailable" {
					return credits.Connection{}, errors.New("private upstream failure")
				}
				return credits.Connection{BaseURL: "https://models.example.com/v1", APIKey: "employee-default"}, nil
			}
			engine := gin.New()
			engine.POST("/task", authenticateWorker("queue", WorkerConfig{Token: strings.Repeat("x", 32)}, lookup), bindTaskExecution(acquire), server.API(acquireTaskModelConnection(lookup)))
			attempt := "3"
			if name == "old_attempt" {
				attempt = "2"
			}
			r := httptest.NewRequest("POST", "/task", strings.NewReader(`{"request":{"task_id":7,"worker_id":"worker-1","attempt":`+attempt+`,"company_id":999,"uin":999}}`))
			r.Header.Set("Authorization", "Bearer "+strings.Repeat("x", 32))
			w := httptest.NewRecorder()
			engine.ServeHTTP(w, r)
			var resp AcquireTaskModelConnectionResponse
			if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
				t.Fatal(err)
			}
			wantCode := uint32(403)
			if name == "valid" {
				wantCode = 0
			}
			if name == "unavailable" {
				wantCode = 503
			}
			if w.Code != 200 || resp.Code != wantCode || w.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("http=%d bodycode=%d", w.Code, resp.Code)
			}
			if name == "valid" {
				if resp.Response.APIKey != "employee-default" || acquisitions != 1 || lookups != 2 {
					t.Fatal("valid claim not acquired once and rechecked")
				}
			} else if resp.Response.APIKey != "" || strings.Contains(w.Body.String(), "private") {
				t.Fatal("failure exposed credential or internal error")
			}
			if (name == "old_attempt" || name == "cancelled_before") && acquisitions != 0 {
				t.Fatal("invalid claim reached acquisition")
			}
		})
	}
}

func TestTaskExecutionIsLazyAndSharesGinAndRequestContext(t *testing.T) {
	for _, use := range []bool{false, true} {
		calls := 0
		engine := gin.New()
		engine.POST("/callback", func(ctx *gin.Context) { ctx.Set(workerTaskContextKey, &Task{CompanyID: 2, UIN: 3}) }, bindTaskExecution(func(context.Context, credits.Subject) (credits.Connection, error) {
			calls++
			return credits.Connection{BaseURL: "https://models.example.com/v1", APIKey: "employee-default"}, nil
		}), func(ctx *gin.Context) {
			if use {
				for _, c := range []context.Context{ctx, ctx.Request.Context()} {
					if _, err := credits.ConnectionFromContext(c); err != nil {
						t.Fatal(err)
					}
				}
			}
			ctx.Status(204)
		})
		w := httptest.NewRecorder()
		engine.ServeHTTP(w, httptest.NewRequest("POST", "/callback", nil))
		want := 0
		if use {
			want = 1
		}
		if w.Code != 204 || calls != want {
			t.Fatalf("status=%d acquisition=%d", w.Code, calls)
		}
	}
}

func TestWorkerBoundaryRejectsBrowserMissingTokenAndWrongQueue(t *testing.T) {
	token := strings.Repeat("x", 32)
	for _, tc := range []struct {
		name, path, body, authorization, cookie string
		status                                  int
	}{
		{"valid", "GetPendingTask", `{"request":{"task_type":"attachment","worker_id":"worker"}}`, "Bearer " + token, "", 204},
		{"missing_token", "GetPendingTask", `{}`, "", "", 401},
		{"browser", "GetPendingTask", `{}`, "Bearer " + token, "session=browser", 401},
		{"wrong_queue", "CheckInstance", `{"request":{"task_type":"memory","worker_id":"worker","task_id":7}}`, "Bearer " + token, "", 403},
		{"missing_queue", "CheckInstance", `{"request":{"worker_id":"worker","task_id":7}}`, "Bearer " + token, "", 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			engine := gin.New()
			engine.POST("/v1/jxagent."+tc.path, authenticateWorker("attachment", WorkerConfig{Token: token}, nil), func(ctx *gin.Context) { ctx.Status(204) })
			r := httptest.NewRequest(http.MethodPost, "/v1/jxagent."+tc.path, strings.NewReader(tc.body))
			if tc.authorization != "" {
				r.Header.Set("Authorization", tc.authorization)
			}
			if tc.cookie != "" {
				r.Header.Set("Cookie", tc.cookie)
			}
			w := httptest.NewRecorder()
			engine.ServeHTTP(w, r)
			if w.Code != tc.status {
				t.Fatalf("status=%d want %d", w.Code, tc.status)
			}
		})
	}
}
