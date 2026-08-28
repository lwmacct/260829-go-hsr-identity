# identity

通用的用户身份模块，供 relay-console、sshrt 等宿主项目共同装配。

模块只拥有用户目录和可复用的登录能力，不携带业务授权、OAuth、SSH key、节点、钱包或资源字段。宿主项目通过 `identity.ClaimsResolver` 注入角色/权限，通过自己的表保存 OAuth、SSH 和业务关系。

## 包结构

- `pkg/identity`：`User`、`Principal`、repository/UnitOfWork 接口、handle policy 和 transport-neutral 请求元数据。
- `pkg/identity/account`：用户与凭据的原子注册、密码重置和跨 repository 事务编排。
- `pkg/identity/password`：Argon2id hasher、密码策略、认证、改密和重置。
- `pkg/identity/session`：不透明会话 token、独立 Session ID、SHA-256 token hash、绝对/空闲 TTL、touch、撤销和 IP/自定义绑定。
- `pkg/identity/sqlstore`：基于 `database/sql` 和 sqlc 生成代码的 SQLite/PostgreSQL repository 适配器。
- `pkg/identity/migrations`：宿主项目使用迁移工具执行的版本化 schema。
- `pkg/identity/testkit`：仅用于测试数据库初始化的辅助包。
- `pkg/identity/httpauth`：纯 `net/http` cookie、Bearer token、请求元数据转换和 optional/required middleware。
- `pkg/identity/internal/dbgen`：sqlc 生成代码，不作为宿主项目的稳定 API。

生产数据库方言以 PostgreSQL 为准；当前 SQL 使用可移植子集，因此测试可使用 SQLite。若宿主项目需要数据库专有能力，应在自己的 adapter 中扩展查询，不修改 identity 的领域接口。

## 最小装配

```go
store := sqlstore.New(db)
// 由宿主项目的 migration runner 执行 migrations.FS 中的 SQL 后再装配服务。
users, _ := identity.New(identity.Options{Users: store, Transactions: store})
passwords, _ := password.New(password.Options{
    Credentials: store, Users: store, UserUpdates: store,
})
accounts, _ := account.New(account.Options{
    Users: users, Passwords: passwords, Transactions: store,
})
sessions, _ := session.New(session.Options{Repository: store, Users: store})
auth := httpauth.New(sessions, httpauth.DefaultCookieConfig())
handler := auth.Required(appHandler)
```

注册后由宿主决定响应格式，并把 `sessions.Create` 返回的 token 写入 cookie：

```go
user, err := accounts.Register(ctx, identity.UserCreateInput{Handle: "alice"}, passwordValue)
token, sessionRecord, err := sessions.Create(ctx, user.ID, meta)
httpauth.SessionCookie(w, token, sessionRecord.ExpiresAt, cookieConfig)
```

密码和会话 token 均不会以明文写入数据库；`Principal.SessionID` 是独立的非敏感 session 标识，而不是可登录 token。审计事件由宿主项目在事务提交后发布。identity 不在生产启动时建表或删表，宿主项目通过 `migrations.FS` 和自己的 migration runner 管理 schema 版本。

SQL 由 [sqlc.yaml](sqlc.yaml)、[001_identity.sql](pkg/identity/migrations/001_identity.sql) 和 [queries.sql](pkg/identity/sqlstore/queries.sql) 定义。更新 SQL 后使用固定版本生成器重新生成：

```bash
go run github.com/sqlc-dev/sqlc/cmd/sqlc@v1.29.0 generate
```
