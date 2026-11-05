# fileupload

`fileupload` 提供单文件与 S3-compatible multipart 上传的通用生命周期，并把成功文件登记到 Core `core_upload_files`。上传会话独立存储在 `core_file_upload_sessions`；Gin、业务 DTO、附件模型和下载权限不属于本包。

## 边界

- 仅新上传使用本 SDK。历史已完成附件继续按业务原有字段读取，不回填 `file_id`。
- 已完成会话不会被清理或中止；`Get` 和所有操作都用当前 `organization_id + user_id + id` 作用域查询。
- SDK 默认读取完整对象流并始终计算 SHA256，同时校验精确大小和对象的声明 MIME；`Request.SHA256` 可空，非空时必须与实际内容一致。对象 ETag 只作元数据，不能替代 SHA256。
- 业务 `Verifier` 可以执行图片变换例外、把 `text/markdown` 规范化为实际 `text/plain` 或格式校验，并返回可信去重后的规范路径。SDK 要求可信对象返回合法小写 SHA256、合法 MIME、正确大小和安全 shape，路径只需位于相同 `purpose`，不要求扩展名一致。可信 Attestation 可引用其他 owner 已验证的物理路径，因为既有 globalhash 秒传策略暂时保留；该风险另行讨论。
- `RegisterExisting` 只供可信服务调用，客户端 HTTP 接口不得直接传入 `StoragePath` 或可信 Attestation。共享物理路径不会改变 CoreFileInfo 的 `organization_id`/`user_id`，不同 owner 各自登记独立归属。
- 旧 `pending_upload` 草稿改为重新发起新上传，不保留旧 multipart 协议或状态回退。

## 生命周期

```go
service, err := fileupload.New(coreDB, objectStorage, fileupload.Options{})
started, err := service.Start(ctx, fileupload.Request{ /* server-validated member and metadata */ })
urls, err := service.PartURLs(ctx, member, started.Session.ID, []int32{1, 2})
file, err := service.Complete(ctx, member, started.Session.ID, parts, businessVerifier)
```

`member` 必须由调用方从已验证身份构造为 `identity.Member`，不能从请求体恢复或覆盖。

完成和终止使用有限 `completing`/`aborting` lease 与随机 fencing token。S3 合并、读取和删除均在数据库事务外；只有 Core 文件创建与 session `completed` CAS 使用同一 Core 事务。COS 已合并但 Core 事务失败时，session 可重试，`Head/Read` 会恢复对象并返回同一 `file_id`。

`CoreFileInfo.Hash` 使用 `sha256:<64hex>`。完成或可信登记后，重复调用返回同一文件 ID；`Complete` 对已完成 session 先返回文件，不受后来过期时间影响。

业务 Blob 去重选定 canonical 对象后，可对 owner 内 `completed` session 调用 `UseVerifiedObject`。SDK 比对已完成文件的 size、SHA256 和 MIME，校验新路径属于同一 `purpose`，再在单个 Core 事务中锁定 session 与文件，以旧路径 CAS 仅更新 `core_upload_files.storage_path`。session 的原始路径不变，SDK 不读写或删除对象；相同路径幂等，并发不同路径返回冲突。该入口用于 JXX 在 Core 完成后再登记 Blob，避免提前写 Blob 与清理竞态。

## 显式迁移

应用显式调用 `fileupload.InitDB()`，或审查后执行 [`migration.sql`](migration.sql)。普通启动不得隐式迁移。迁移同时把 Core 文件名称、扩展名和路径宽度扩展为 255、16 和 512；真实 DDL 必须由部署流程单独核验。

会话表只保留 `(state, expires_at)` 清理索引和 UUID 主键。当前按 UUID 加 owner 过滤读取，生产查询消费方没有 owner/file_id 列表需求，因此不保留对应冗余索引。清理查询会同时过滤未完成状态和可抢占 lease，避免 busy 会话占满单批 LIMIT。该索引设计尚未在真实 Core 库执行 `EXPLAIN`，状态为 UNVERIFIED。
