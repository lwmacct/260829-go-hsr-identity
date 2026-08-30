# identity

`identity` 是一个面向 Go 1.27、SQLite 或 PostgreSQL 18+ 应用的身份与访问控制模块，直接使用宿主已经采用的 Bun 和 Huma。它提供用户、Argon2id 密码、不可逆 Session token、账户生命周期、通用 RBAC、人机挑战契约和基础 HTTP API；OAuth、SSH key、审计及业务关系由宿主项目拥有。

## 分层

```text
pkg/identity                 对外 Module、领域类型、schema
pkg/identity/challenge      可复用的图片和远程 token provider
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
        // Use pkg/identity/challenge for the built-in image or remote token
        // providers, or supply a host-owned implementation. Set
        // RequireChallenge when login and registration must solve it.
        ChallengeProvider: challengeProvider,
        RequireChallenge: true,
        SecureCookie: true,
    },
})
if err != nil { return err }

mod.Register(api) // 注册 /auth/*，以及配置开启时的 /admin/*
```

测试或显式数据库初始化命令可由宿主执行 Bun schema：

```go
if err := identity.ApplySchema(ctx, db); err != nil { return err }
```

`ApplySchema` 仅是显式 schema helper，不会执行缺列补齐或历史迁移。生产启动流程不应把它当作自动迁移；生产数据库由部署阶段重建或执行宿主维护的 SQL。

宿主可通过 `Options.Events` 接收登录、账户、密码、Session 和 RBAC 的提交后事实事件，用于日志、审计或指标：

```go
Events: identity.EventSinkFunc(func(ctx context.Context, event identity.Event) {
    logger.InfoContext(ctx, string(event.Type), "user_id", event.UserID)
}),
```

事件 observer 不参与数据库事务，且其 panic 会被隔离；需要与 identity 写入强一致的宿主数据必须使用明确的事务参与边界，而不是依赖事件。

## 公共能力

```go
user, err := mod.RegisterUser(ctx, identity.UserCreateInput{Username: "alice"}, password)
user, err = mod.Authenticate(ctx, "alice", password)
user, issued, err := mod.Login(ctx, "alice", password, identity.RequestMeta{ClientIP: "203.0.113.10"})
principal, err := mod.ResolveSession(ctx, issued.Token, identity.RequestMeta{ClientIP: "203.0.113.10"})

// OAuth/SSH 等宿主登录完成后，直接签发 identity Session：
issued, err = mod.CreateSession(ctx, user.ID, identity.RequestMeta{ClientIP: "203.0.113.10"})

// 初始化通用角色和权限：
role, err := mod.EnsureRole(ctx, identity.RoleInput{Code: "admin", Name: "Administrator", System: true})
permission, err := mod.EnsurePermission(ctx, identity.PermissionInput{Code: "relay.api_key.manage", Name: "Manage API keys"})
err = mod.SetRolePermissions(ctx, role.ID, []string{permission.Code})
err = mod.SetUserRoles(ctx, user.ID, []string{role.Code})

// Bootstrap an initial privileged account from an explicit operator command:
user, err := mod.BootstrapUser(ctx, identity.BootstrapInput{
    User: identity.UserCreateInput{Username: "admin", DisplayName: "Administrator"},
    Password: password,
    RoleCodes: []string{"admin"},
})
```

`BootstrapUser` creates the account, password and requested role bindings in
one transaction. Every requested role must still be unassigned; a second
bootstrap attempt returns `identity.ErrBootstrapCompleted` and never changes
an existing account.

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
GET   /auth/config
POST  /auth/challenges
GET   /auth/session
PATCH /auth/password
POST  /auth/sessions/revoke-all
```

开启 `EnableAdminRoutes` 后提供 `/admin/users` 的列表、创建、查询、更新、状态切换、密码重置和删除接口。开启 `EnableRBACRoutes` 后还提供角色、权限及绑定管理接口。基础管理操作由 identity RBAC 权限控制；`Options.Authorizer` 仅用于叠加宿主的额外策略。

认证中间件同时支持 Session cookie 和 `Authorization: Bearer <token>`。宿主可以通过 `HTTP.TokenExtractor` 完全替换 token 来源。
如果应用位于可信反向代理之后，可通过 `HTTP.RequestMetaResolver` 注入客户端 IP 和 User-Agent 的解析；默认实现不信任转发头。

## 数据表

模块拥有七张表：

```text
identity_users
identity_passwords
identity_sessions
identity_roles
identity_permissions
identity_user_roles
identity_role_permissions
```

不包含 `user_external_identities`，也不包含 OAuth、SSH、验证码或审计表。通用的图片和远程 token
验证码 provider 位于 `pkg/identity/challenge`；宿主也可以分别实现 `HumanChallengeVerifier` 和可选的 `HumanChallengeCreator` 后注入。
identity 负责配置、挑战路由、登录/注册校验和业务侧复用的 `CreateChallenge`/`VerifyChallenge`。
宿主的业务权限编码写入 identity 的通用 permission 表，但权限语义仍由宿主定义。

SQLite 是默认数据库，也可用于生产；PostgreSQL 最低支持版本为 18。生产环境由宿主部署阶段管理 schema 版本，本包不自动迁移或创建表。PostgreSQL schema 会使用
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
