# jxpkg

Juxonone 后端服务基础包，提供 HTTP API、配置、数据库、Redis、日志、对象存储、任务、认证、邮件和模型客户端等能力。

## 安装

```bash
go get github.com/JUXON-AI/jxpkg@v0.0.5
```

要求 Go 1.25 或更高版本。

## 目录

```text
apis/          HTTP API、JWT、Gin middleware 和 server
config/        YAML 配置加载
dbtools/       GORM 数据库和 Redis 连接
lifecycle/     应用生命周期
llm/           OpenAI-compatible 客户端
logs/          Zap 和 GORM 日志
mail/          SMTP 邮件
mutex/         Redis 锁和集群选主
random/        随机数据生成
settings/      数据库配置项
storage/       S3-compatible 对象存储和文件模型
task/          异步任务、队列和 worker API
verification/  一次性验证码
```

数据库迁移由应用显式调用，不会因为导入本包自动执行。数据库连接、Redis、S3 和 SMTP 等配置由应用提供。

## 集成测试

默认测试不会连接外部资源。需要执行集成测试时设置对应环境变量：

```text
JXPKG_TEST_DB_CORE
JXPKG_TEST_DB_ACCOUNT
JXPKG_TEST_DB_JXONE
JXPKG_TEST_S3_ENDPOINT
JXPKG_TEST_S3_ACCESS_KEY
JXPKG_TEST_S3_SECRET_KEY
JXPKG_TEST_S3_BUCKET
JXPKG_TEST_S3_REGION
```
