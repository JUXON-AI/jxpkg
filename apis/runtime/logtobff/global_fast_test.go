package logtobff

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
)

type observedGlobalAuthority struct {
	calls       atomic.Int64
	deny        atomic.Bool
	unavailable atomic.Bool
	removeRead  atomic.Bool
}

func (a *observedGlobalAuthority) Permissions(context.Context, string) (GlobalAccess, error) {
	a.calls.Add(1)
	if a.unavailable.Load() {
		return GlobalAccess{}, ErrUnavailable
	}
	decision := GlobalAccess{Allowed: !a.deny.Load()}
	if !a.removeRead.Load() {
		decision.Permissions = []string{"credits:read"}
	}
	return decision, nil
}

func TestGlobalFastReadsAcrossReplicasAndOnlineWrites(t *testing.T) {
	private := loadFixtureRedisConfig(t)
	a, value, _, _ := globalFixture(t)
	ctx := context.Background()
	cache := redis.NewClient(&redis.Options{Addr: private.Address, Password: private.Password})
	t.Cleanup(func() { _ = cache.Close() })
	cfg := Config{Namespace: "test-global-fast-" + testOpaque(t), SessionKey: testOpaque(t)}
	storeA, err := newStore(cfg, cache)
	if err != nil {
		t.Fatal(err)
	}
	storeB, err := newStore(cfg, cache)
	if err != nil {
		t.Fatal(err)
	}
	var clock atomic.Int64
	clock.Store(time.Now().UnixNano())
	storeA.now = func() time.Time { return time.Unix(0, clock.Load()) }
	storeB.now = storeA.now
	authority := &observedGlobalAuthority{}
	a.store, a.globalAuthority = storeA, authority
	a.config.GlobalReadFastPath, a.config.CookieName = true, "test-session"
	replica := *a
	replica.store = storeB
	id, err := storeA.create(ctx, value, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cache.Del(ctx, storeA.prefix+"s:"+id).Err() })
	epoch := globalEpoch(value.Subject, "credits:read")
	router := func(r *Runtime) *gin.Engine {
		mux := gin.New()
		mux.POST("/read", r.RequireGlobalRead("credits:read"), func(c *gin.Context) {
			if _, ok := GlobalFromContext(c.Request.Context()); !ok {
				c.Status(500)
				return
			}
			c.Status(204)
		})
		mux.POST("/write", r.Require("credits:read"), func(c *gin.Context) { c.Status(204) })
		return mux
	}
	servers := []*gin.Engine{router(a), router(&replica)}
	send := func(h http.Handler, method, path, csrf, requestEpoch string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, a.config.Origin+path, nil)
		r.AddCookie(&http.Cookie{Name: a.config.CookieName, Value: id})
		r.Header.Set("Origin", a.config.Origin)
		r.Header.Set("X-CSRF-Token", csrf)
		r.Header.Set("X-Authority-Epoch", requestEpoch)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	var wait sync.WaitGroup
	for i := range 12 {
		wait.Go(func() {
			w := send(servers[i%2], "POST", "/read", value.CSRF, epoch)
			if w.Code != 204 {
				t.Errorf("concurrent cold read: %d %s", w.Code, w.Body.String())
			}
		})
	}
	wait.Wait()
	if calls := authority.calls.Load(); calls != 1 {
		t.Fatalf("cold reads performed %d decisions", calls)
	}

	_, owner, err := storeB.acquire(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	warm := send(a.Handler(), "GET", "/auth/session", "", "")
	if warm.Code != 200 || !strings.Contains(warm.Body.String(), "credits:read") {
		t.Fatalf("session read while locked: %d", warm.Code)
	}
	warm = send(servers[0], "POST", "/read", value.CSRF, epoch)
	storeB.release(ctx, id, owner)
	if warm.Code != 204 || authority.calls.Load() != 1 {
		t.Fatal("warm path contacted authority or required lease")
	}
	if send(servers[0], "POST", "/read", "wrong", epoch).Code != 403 ||
		send(servers[1], "POST", "/read", value.CSRF, "wrong").Code != 409 {
		t.Fatal("fast read bypassed CSRF or authority epoch")
	}
	if r := send(a.Handler(), "POST", "/auth/session", value.CSRF, epoch); r.Code != 200 || authority.calls.Load() != 2 {
		t.Fatalf("renewal did not check current authority: %d", r.Code)
	}

	authority.removeRead.Store(true)
	if r := send(a.Handler(), "POST", "/auth/session", value.CSRF, epoch); r.Code != 409 {
		t.Fatalf("renewal accepted the old scope epoch: %d", r.Code)
	}
	if r := send(a.Handler(), "GET", "/auth/session", "", ""); r.Code != 200 || strings.Contains(r.Body.String(), "credits:read") {
		t.Fatalf("session reverted to the old permission snapshot: %d %s", r.Code, r.Body.String())
	}
	authority.deny.Store(true)
	if r := send(servers[1], "POST", "/write", value.CSRF, epoch); r.Code != 403 || authority.calls.Load() != 5 {
		t.Fatalf("write accepted revoked authority: %d", r.Code)
	}
	// Expire the shared marker while both app clocks still consider the local snapshot fresh.
	if err := cache.PExpireAt(ctx, storeA.prefix+"lock:read-valid:"+id, time.Now().Add(-time.Second)).Err(); err != nil {
		t.Fatal(err)
	}
	for i := range 12 {
		wait.Go(func() {
			if r := send(servers[i%2], "POST", "/read", value.CSRF, epoch); r.Code != 403 {
				t.Errorf("expired snapshot accepted revoked authority: %d", r.Code)
			}
		})
	}
	wait.Wait()
	if calls := authority.calls.Load(); calls != 6 {
		t.Fatalf("concurrent denied reads made %d total decisions", calls)
	}
	if r := send(a.Handler(), "POST", "/auth/session", value.CSRF, epoch); r.Code != 403 {
		t.Fatalf("revoked session renewed: %d", r.Code)
	}
	_ = cache.Del(ctx, storeA.prefix+"lock:read-backoff:"+id).Err()
	authority.unavailable.Store(true)
	if r := send(servers[1], "POST", "/read", value.CSRF, epoch); r.Code != 503 {
		t.Fatalf("expired snapshot accepted during outage: %d", r.Code)
	}
	before, err := storeA.readGlobal(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	newer, generationOwner, err := storeB.acquire(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	newer.GlobalGeneration = "new"
	if err := storeB.commit(ctx, id, generationOwner, id, newer, false); err != nil {
		t.Fatal(err)
	}
	if status := classify(a.dropInvalidGlobal(ctx, id, before)).status; status != 409 {
		t.Fatalf("late invalidation not fenced: %d", status)
	}
	if current, err := storeA.readGlobal(ctx, id); err != nil || current.GlobalGeneration != "new" {
		t.Fatalf("newer session deleted by late invalidation: %v", err)
	}
	if err := cache.Del(ctx, storeA.prefix+"s:"+id).Err(); err != nil {
		t.Fatal(err)
	}
	if r := send(a.Handler(), "GET", "/auth/session", "", ""); r.Code != 401 {
		t.Fatalf("removed session readable: %d", r.Code)
	} else if cookies := r.Result().Cookies(); len(cookies) != 1 || cookies[0].MaxAge >= 0 {
		t.Fatal("expired session did not clear its cookie")
	}
}
