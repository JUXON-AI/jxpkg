-- Explicit deployment migration. Never run from application startup.
-- Target: the configured core database, table core_task (MySQL 5.7+).
-- Preflight: SHOW INDEX FROM core_task; skip any already-existing identical index.
-- Both indexes contain scheduling metadata only, never payload or result.
-- Online InnoDB build permits concurrent DML. LOCK=NONE makes unsupported
-- online builds fail rather than silently take an exclusive table lock.
-- A brief metadata lock is still required; lock_wait_timeout bounds that wait.
-- Observed target: approximately 16k rows / 1.3 GB; build duration is workload
-- dependent and must be measured. Existing rows and columns are unchanged.
SET SESSION lock_wait_timeout = 10;
ALTER TABLE core_task
  ADD INDEX idx_core_task_claim (task_type, deleted_at, task_status, priority, updated_at),
  ADD INDEX idx_core_task_dependency (subject_id, app_group, step, deleted_at, task_status),
  ALGORITHM=INPLACE, LOCK=NONE;

-- Verify: SHOW INDEX FROM core_task, then EXPLAIN the claim and dependency SQL.
-- Code rollback does not require removing indexes. If removal is explicitly
-- approved later, the reverse is ALTER TABLE core_task DROP INDEX ... for only
-- the two indexes above; it does not remove task rows.
