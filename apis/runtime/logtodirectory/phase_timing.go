package logtodirectory

import (
	"context"
	"time"

	"github.com/JUXON-AI/jxpkg/logs"
	"github.com/JUXON-AI/jxpkg/requestid"
)

// recordDirectoryPhase exposes slow dependency waits without logging identity, credentials or errors.
// Phase names are fixed at internal call sites; errors keep their existing owner.
func recordDirectoryPhase(ctx context.Context, phase string, started time.Time) {
	const phaseTimingThreshold = 100 * time.Millisecond
	elapsed := time.Since(started)
	if elapsed < phaseTimingThreshold {
		return
	}
	safe := logs.WithContextFields(context.Background(), "request_id", requestid.FromContext(ctx))
	logs.InfoContextw(safe, "logtodirectory.phase_timing", "phase", phase, "duration_ms", elapsed.Milliseconds())
}
