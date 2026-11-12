package logtobff

import (
	"context"
	"maps"
	"time"
)

type resourceReadClaimsKey struct{}

// resourceReadClaims is a request-local credential capability. It is never
// serialized into Redis or forwarded into the authorized business context.
type resourceReadClaims struct {
	runtime       *Runtime
	id            string
	before, value *session
}

// issue preserves the online-check-then-fresh-token ordering. The latest SDK
// remains authoritative; a parallel logout or identity switch cannot be
// overwritten by the older online-read snapshot.
func (r *resourceReadClaims) issue(ctx context.Context, org string) (string, error) {
	var (
		started             = time.Now()
		current, owner, err = r.runtime.store.acquire(ctx, r.id)
	)
	recordIdentityPhase(ctx, "bff.resource.acquire", started)
	if err != nil {
		return "", err
	}
	committed := false
	defer func() {
		if !committed {
			r.runtime.store.release(ctx, r.id, owner)
		}
	}()
	if err := mergeIdentityUpdate(current, r.before, r.before, r.runtime.store.nowTime()); err != nil {
		return "", err
	}
	started = time.Now()
	raw, tokenErr := r.runtime.token(ctx, current, org)
	recordIdentityPhase(ctx, "bff.resource.token", started)
	// Persist any SDK rotation even when token issuance failed. The outer read
	// owns deterministic invalidation and applies it only to this SDK generation.
	save, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
	defer cancel()
	started = time.Now()
	if err := r.runtime.store.commit(save, r.id, owner, r.id, current, false /* remove */); err != nil {
		recordIdentityPhase(ctx, "bff.resource.commit", started)
		return "", err
	}
	recordIdentityPhase(ctx, "bff.resource.commit", started)
	committed = true
	r.value.SDK = current.SDK
	r.before.SDK = maps.Clone(current.SDK)
	return raw, tokenErr
}
