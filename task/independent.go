package task

import "sync"

var independentTypes sync.Map

// RegisterIndependentTaskType declares a queue protocol with only step-zero work.
// Register at startup, before creating or claiming tasks. All tasks sharing a
// subject/app_group with this type must also be independent: dependency-driven
// workflows must retain the default policy. The claim lease, durable queue,
// callback, retry and cancellation protocols are unchanged.
//
// This belongs in task because only the scheduler can avoid dependency queries
// consistently at discovery, locked claim and completion. No business payload or
// service-specific type name is interpreted here.
func RegisterIndependentTaskType(taskType string) {
	if taskType == "" {
		panic("task: independent task type cannot be empty")
	}
	independentTypes.Store(taskType, true)
}

func independentTaskType(taskType string) bool {
	_, ok := independentTypes.Load(taskType)
	return ok
}
