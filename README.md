# jxpkg

通用 Go 后端服务基础库，提供 HTTP API 框架、配置管理、数据库操作、缓存、日志等基础设施的轻量封装。

## 目录结构

```
jxpkg/
├── apis/               HTTP API 框架层
│   ├── apiobj/         请求/响应数据结构定义（BaseRequest、分页查询等）
│   ├── constants/      Gin 上下文键常量
│   ├── errcode/        业务错误码注册与管理
│   └── runtime/
│       ├── auth/        JWT 认证（Claims 定义、令牌解析、登录态）
│       ├── middleware/   Gin 中间件（CORS、日志、鉴权、Recovery、语言）
│       ├── server/      路由注册、Handler 适配（反射转写）、认证注入
│       ├── context.go   请求上下文辅助函数（Uin、RequestID 等）
│       └── error.go     统一响应错误处理（Success、BadRequest、InternalError）
│
├── cache/              缓存抽象层
│   ├── cache.go        Cache 接口定义 + Marshal/Unmarshal 工具
│   ├── memory/         内存缓存实现
│   └── redis/          Redis 缓存实现
│
├── config/             配置定义与加载
│   ├── config.go       核心配置结构（MainConfig、JwtConfig、MysqlConfig、RedisConfig）+ YAML 加载
│   └── logger.go       日志配置结构（多 Writer、多 Encoder 支持）
│
├── dbtools/            数据源管理
│   ├── database.go     数据库表自动迁移与初始化工具
│   ├── datasource.go   多数据源连接管理（MySQL、SQLite）+ 连接池配置
│   └── redis.go        Redis 客户端初始化与单例管理
│
├── lifecycle/          应用生命周期管理（信号监听、优雅退出）
├── logs/               日志封装（基于 zap + lumberjack）
│   ├── logger.go       日志门面方法（Debug/Info/Warn/Error 及 Context 版本）
│   ├── logger_wrapper.go 日志初始化、配置重载、多 Writer 支持
│   └── gorm.go         GORM 日志适配器
└── settings/           配置项管理（DB 持久化 + Redis 缓存）
    ├── setting.go      Settings 表的 CRUD 操作
    └── secret.go       AES-GCM 加解密工具（敏感配置加密存储）
```
