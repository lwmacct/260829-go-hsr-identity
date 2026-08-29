# identity

`identity` 是一个面向 Go 1.27、PostgreSQL 18+ 应用的用户身份模块，直接使用宿主已经采用的 Bun 和 Huma。它提供用户、Argon2id 密码、不可逆 Session token、账户生命周期和基础 HTTP API；OAuth、SSH key、验证码、角色权限、审计及业务关系由宿主项目拥有。

## 分层

```text
pkg/identity                 对外 Module、领域类型、schema
        ↓
internal/identity/handler    Huma DTO、路由、cookie、鉴权中间件
        ↓
internal/identity/service   用户、密码、Session、账户事务
        ↓
internal/identity/repository Bun model、查询、事务、错误映射
```

模块内部依赖 Bun/Huma 是有意的：`260628-llm-relay-console` 和 `260606-sshrt` 使用相同技术栈，宿主若不满意某一层可以复制后独立维护。

## 最小装配

```go
mod, err := identity.New(identity.Options{
    DB: db,
    Session: identity.SessionOptions{TTL: 30 * 24 * time.Hour},
    HTTP: identity.HTTPOptions{
        RegistrationEnabled: true,
        SecureCookie: true,
    },
})
if err != nil { return err }

mod.Register(api) // 注册 /auth/*，以及配置开启时的 /admin/*
```

应用启动时由宿主统一执行 Bun schema：

```go
if err := identity.ApplySchema(ctx, db); err != nil { return err }
```

`ApplySchema` 适合测试和 Bun model 驱动的应用。生产环境的版本化升级仍由宿主 migration runner 管理；本包不提供 `migrations/`，也不会在 `identity.New` 中自动建表。

## 公共能力

```go
user, err := mod.RegisterUser(ctx, identity.UserCreateInput{Handle: "alice"}, password)
user, err = mod.Authenticate(ctx, "alice", password)
user, issued, err := mod.Login(ctx, "alice", password, identity.RequestMeta{ClientIP: "203.0.113.10"})
principal, err := mod.ResolveSession(ctx, issued.Token, identity.RequestMeta{ClientIP: "203.0.113.10"})

// OAuth/SSH 等宿主登录完成后，直接签发 identity Session：
issued, err = mod.CreateSession(ctx, user.ID, identity.RequestMeta{ClientIP: "203.0.113.10"})
```

`Authenticate` 只做凭据校验；需要建立登录态时使用 `Login`。`CreateSession`
用于宿主已经完成 OAuth/SSH 等外部凭据校验的场景，同样会记录
`last_login_at`。用户和 Session ID 固定为 UUIDv7，直接调用 Go 1.27 标准库
`uuid.NewV7()` 生成；不提供自定义 ID 生成器。

Session token 只在创建时返回，数据库只保存 SHA-256 hash。Session ID 是独立的非敏感标识。

## HTTP 路由

默认认证前缀为 `/auth`：

```text
POST  /auth/register
POST  /auth/login
POST  /auth/logout
GET   /auth/session
PATCH /auth/password
POST  /auth/sessions/revoke-all
```

开启 `EnableAdminRoutes` 后提供 `/admin/users` 的列表、创建、查询、更新、状态切换、密码重置和删除接口。管理员授权通过 `Options.Authorizer` 注入，identity 不保存角色或权限表。

认证中间件同时支持 Session cookie 和 `Authorization: Bearer <token>`。宿主可以通过 `HTTP.TokenExtractor` 完全替换 token 来源。
如果应用位于可信反向代理之后，可通过 `HTTP.RequestMetaResolver` 注入客户端 IP、User-Agent 和 Device ID 的解析；默认实现不信任转发头。

## 数据表

模块只拥有三张表：

```text
identity_users
identity_passwords
identity_sessions
```

不包含 `user_external_identities`，也不包含 OAuth、SSH、验证码、授权或审计表。

PostgreSQL 最低支持版本为 18；生产环境由宿主 migration runner 管理 schema
版本，本包不自动迁移或创建表。PostgreSQL schema 会使用
`uuid_extract_version(id) = 7` 检查，拒绝非 UUIDv7 的用户和 Session ID。

## 承包式接管

默认直接依赖 `pkg/identity`。宿主需要定制时，可以复制：

```text
internal/identity/handler       只接管 HTTP
internal/identity/service       接管业务编排
internal/identity/repository    接管 Bun 查询和模型
pkg/identity/domain             接管领域类型
```

复制后替换 module import path，删除外部 identity 依赖即可。详见 [docs/forking.md](docs/forking.md)。
