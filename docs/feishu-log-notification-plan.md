# 飞书日志告警方案（Draft）

## 目标

建立 `JX｜生产告警` 飞书群，由各运行服务以独立机器人身份发送需要人工处理的日志告警。

## 方案

- 群内创建 `Juxonone`、`JXWorker`、`JXAccount` 三个自定义机器人，各自使用独立头像、Webhook 和签名密钥。
- `jxpkg` 只提供通用异步发送能力，不作为运行时机器人身份；公共包日志沿用宿主服务身份，并携带 `component: jxpkg/...`。
- Webhook 和签名密钥只通过环境变量或 Secret 注入，不写入 YAML、Git、镜像或日志；固定出口 IP 时同时启用 IP 白名单。
- 仅推送需人工处理的事件：`ERROR` 及以上立即发送，`WARN` 聚合发送，普通 `INFO`/`DEBUG` 不发送。
- 消息卡片至少包含 `service`、`component`、`env`、`event`、`request_id`、`trace_id`、时间和脱敏后的错误摘要；完整日志通过链接跳转到日志平台。

## 开发落点

1. 在 `jxpkg/logs` 增加异步、有限队列的飞书输出，支持签名、超时、限流退避、错误聚合和退出刷新。
2. 由 `juxonone`、`jxworker`、`jxaccount` 分别注入自己的 Webhook 和签名密钥；发送失败不得阻塞或中断业务请求。
3. 增加签名、脱敏、超时、非零响应、队列溢出、聚合和关闭刷新测试。
4. 先接测试群验证，再逐个服务启用生产机器人；上线后观察发送量、失败数和丢弃数。

## 验收

- 三个服务在群内显示正确的机器人名称和头像。
- 同一错误不会造成刷屏，敏感字段不会出现在卡片中。
- 飞书不可用、限流或队列满时，业务请求仍正常完成。
- Webhook、签名密钥及数据库、Token、Cookie 等敏感信息均未进入仓库或日志。

参考：[飞书自定义机器人指南](https://open.feishu.cn/document/client-docs/bot-v3/add-custom-bot)、[发送消息 API](https://open.feishu.cn/document/server-docs/im-v1/message/create)。
