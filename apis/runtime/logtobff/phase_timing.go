package logtobff

import (
	"context"
	"time"

	"github.com/JUXON-AI/jxpkg/logs"
	"github.com/JUXON-AI/jxpkg/requestid"
)

const _phaseTimingThreshold = 100 * time.Millisecond

// recordIdentityPhase exposes slow dependency waits without logging identity, credentials or errors.
// Phase names are fixed internally; only lease acquisition supplies a busy count.
func recordIdentityPhase(ctx context.Context, phase string, started time.Time, busyCount ...int) {
	elapsed := time.Since(started)
	if elapsed < _phaseTimingThreshold {
		return
	}
	fields := make([]any, 0, 6)
	fields = append(fields, "phase", phase, "duration_ms", elapsed.Milliseconds())
	if len(busyCount) > 0 {
		fields = append(fields, "busy_count", busyCount[0])
	}
	safe := logs.WithContextFields(context.Background(), "request_id", requestid.FromContext(ctx))
	logs.InfoContextw(safe, "logtobff.phase_timing", fields...)
}
