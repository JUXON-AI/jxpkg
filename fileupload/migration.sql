-- Core 通用文件上传显式迁移。发布前由 DBA 和应用负责人审查后执行。
-- 本文件不会由包导入或普通服务启动自动执行。

ALTER TABLE `core_upload_files`
    MODIFY COLUMN `filename` varchar(255) NULL COMMENT '原始文件名',
    MODIFY COLUMN `file_ext` varchar(16) NULL COMMENT '文件扩展名',
    MODIFY COLUMN `storage_path` varchar(512) NULL COMMENT '存储的相对路径';

CREATE TABLE IF NOT EXISTS `core_file_upload_sessions` (
    `id` char(36) NOT NULL COMMENT '上传会话ID',
    `organization_id` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL COMMENT '所属组织ID',
    `user_id` varchar(128) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL COMMENT '所属用户ID',
    `purpose` varchar(32) NOT NULL COMMENT '用途分类',
    `filename` varchar(255) NOT NULL COMMENT '原始文件名',
    `file_ext` varchar(16) NOT NULL COMMENT '文件扩展名',
    `mime_type` varchar(128) NOT NULL COMMENT 'MIME类型',
    `size_bytes` bigint NOT NULL COMMENT '文件字节数',
    `sha256` char(64) NOT NULL COMMENT '文件SHA256',
    `storage_path` varchar(512) NOT NULL COMMENT '对象存储路径',
    `multipart_id` varchar(255) NOT NULL DEFAULT '' COMMENT '分片上传ID',
    `mode` varchar(16) NOT NULL COMMENT '上传模式',
    `part_size` bigint NOT NULL DEFAULT 0 COMMENT '分片字节数',
    `part_count` int NOT NULL DEFAULT 0 COMMENT '分片总数',
    `expires_at` datetime(3) NOT NULL COMMENT '上传过期时间',
    `file_id` bigint unsigned NULL COMMENT 'Core文件ID',
    `state` varchar(16) NOT NULL COMMENT '会话状态',
    `lease_token` char(64) NOT NULL DEFAULT '' COMMENT '租约令牌',
    `lease_expires_at` datetime(3) NULL COMMENT '租约过期时间',
    `created_at` datetime(3) NOT NULL COMMENT '创建时间',
    `updated_at` datetime(3) NOT NULL COMMENT '更新时间',
    PRIMARY KEY (`id`),
    KEY `idx_core_file_upload_sessions_cleanup` (`state`, `expires_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
  COMMENT='Core通用文件上传会话';
