package identity

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/lwmacct/260829-go-hsr-identity/internal/identity/handler"
	"github.com/lwmacct/260829-go-hsr-identity/internal/identity/repository"
	"github.com/lwmacct/260829-go-hsr-identity/internal/identity/service"
	"github.com/uptrace/bun"
)

type Module struct {
	users    *service.UserService
	password *service.PasswordService
	session  *service.SessionService
	account  *service.AccountService
	handler  *handler.Endpoint
}

func New(options Options) (*Module, error) {
	if options.DB == nil {
		return nil, errors.New("identity: database is required")
	}
	now := options.Clock
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	handle := options.HandlePolicy
	if handle == nil {
		handle = HandlePolicyFunc(LowerASCIIHandlePolicy)
	}
	store := repository.NewStore(options.DB)
	users, err := service.NewUserService(store, store, handle, now)
	if err != nil {
		return nil, err
	}
	password, err := service.NewPasswordService(store, store, service.PasswordOptions{
		Policy: service.PasswordPolicy{
			MinLength:     options.Password.Policy.MinLength,
			MaxLength:     options.Password.Policy.MaxLength,
			RequireUpper:  options.Password.Policy.RequireUpper,
			RequireLower:  options.Password.Policy.RequireLower,
			RequireDigit:  options.Password.Policy.RequireDigit,
			RequireSymbol: options.Password.Policy.RequireSymbol,
			RejectHandle:  options.Password.Policy.RejectHandle,
			RejectCommon:  options.Password.Policy.RejectCommon,
		},
		Hasher: options.Password.Hasher,
		Argon2id: service.Argon2idParams{
			Memory:      options.Password.Argon2id.Memory,
			Iterations:  options.Password.Argon2id.Iterations,
			Parallelism: options.Password.Argon2id.Parallelism,
			SaltLength:  options.Password.Argon2id.SaltLength,
			KeyLength:   options.Password.Argon2id.KeyLength,
		},
	}, now, handle)
	if err != nil {
		return nil, err
	}
	session, err := service.NewSessionService(store, store, service.SessionOptions{
		TTL:           options.Session.TTL,
		IdleTimeout:   options.Session.IdleTimeout,
		TouchInterval: options.Session.TouchInterval,
		TokenBytes:    options.Session.TokenBytes,
		Binding:       options.Session.Binding,
		Claims:        options.Session.Claims,
	}, now)
	if err != nil {
		return nil, err
	}
	account, err := service.NewAccountService(users, password, session, store)
	if err != nil {
		return nil, err
	}
	endpoint := handler.NewEndpoint(handler.Config{
		AuthPrefix:          options.HTTP.AuthPrefix,
		AdminPrefix:         options.HTTP.AdminPrefix,
		RegistrationEnabled: options.HTTP.RegistrationEnabled,
		EnableAdminRoutes:   options.HTTP.EnableAdminRoutes,
		CookieName:          options.HTTP.CookieName,
		CookiePath:          options.HTTP.CookiePath,
		CookieDomain:        options.HTTP.CookieDomain,
		SecureCookie:        options.HTTP.SecureCookie,
		SameSite:            options.HTTP.SameSite,
		TokenExtractor:      options.HTTP.TokenExtractor,
		RequestMetaResolver: options.HTTP.RequestMetaResolver,
		Authorizer:          options.Authorizer,
	}, handler.Services{Users: users, Passwords: password, Sessions: session, Accounts: account})
	return &Module{users: users, password: password, session: session, account: account, handler: endpoint}, nil
}

func MustNew(options Options) *Module {
	m, err := New(options)
	if err != nil {
		panic(err)
	}
	return m
}

func (m *Module) Register(api huma.API) {
	if m != nil && m.handler != nil {
		m.handler.Register(api)
	}
}
func (m *Module) Handler() *Handler {
	if m == nil {
		return nil
	}
	return &Handler{endpoint: m.handler}
}
func (m *Module) UserByID(ctx context.Context, id UserID) (*User, error) {
	return m.users.UserByID(ctx, id)
}
func (m *Module) UserByHandle(ctx context.Context, handle string) (*User, error) {
	return m.users.UserByHandle(ctx, handle)
}
func (m *Module) CreateUser(ctx context.Context, input UserCreateInput) (*User, error) {
	return m.users.Create(ctx, input)
}
func (m *Module) UpdateUserProfile(ctx context.Context, id UserID, input UserUpdateProfileInput) (*User, error) {
	return m.users.UpdateProfile(ctx, id, input)
}
func (m *Module) MarkUserLogin(ctx context.Context, id UserID) error {
	return m.users.MarkLogin(ctx, id)
}

// SetPassword provisions or replaces a user's password and revokes existing
// sessions. It is useful for host-owned administrative account creation where
// the user row and credential are assembled as separate operations.
func (m *Module) SetPassword(ctx context.Context, userID UserID, password string) error {
	return m.account.ResetPassword(ctx, userID, password)
}
func (m *Module) ListUsers(ctx context.Context, filter UserFilter) ([]User, int, error) {
	return m.users.Users(ctx, filter)
}
func (m *Module) RegisterUser(ctx context.Context, input UserCreateInput, password string) (*User, error) {
	return m.account.Register(ctx, input, password)
}
func (m *Module) Authenticate(ctx context.Context, handle, password string) (*User, error) {
	return m.password.Authenticate(ctx, handle, password)
}
func (m *Module) Login(ctx context.Context, handle, password string, meta RequestMeta) (*User, *IssuedSession, error) {
	return m.account.Login(ctx, handle, password, meta)
}
func (m *Module) CreateSession(ctx context.Context, userID UserID, meta RequestMeta) (*IssuedSession, error) {
	return m.account.IssueSession(ctx, userID, meta)
}
func (m *Module) ResolveSession(ctx context.Context, token string, meta RequestMeta) (*Principal, error) {
	return m.session.Resolve(ctx, token, meta)
}
func (m *Module) CurrentPrincipal(ctx context.Context, token string, meta RequestMeta) (*Principal, error) {
	return m.ResolveSession(ctx, token, meta)
}
func (m *Module) CurrentUser(ctx context.Context, token string, meta RequestMeta) (*User, error) {
	p, err := m.ResolveSession(ctx, token, meta)
	if err != nil {
		return nil, err
	}
	return p.User, nil
}
func (m *Module) RevokeSession(ctx context.Context, token, reason string, meta RequestMeta) error {
	return m.session.Revoke(ctx, token, reason, meta)
}
func (m *Module) ChangePassword(ctx context.Context, userID UserID, current, next string) error {
	return m.account.ChangePassword(ctx, userID, current, next)
}
func (m *Module) ResetPassword(ctx context.Context, userID UserID, next string) error {
	return m.account.ResetPassword(ctx, userID, next)
}
func (m *Module) SetUserState(ctx context.Context, ids []UserID, state State) error {
	return m.users.SetState(ctx, ids, state)
}
func (m *Module) DeleteUsers(ctx context.Context, ids []UserID) error {
	return m.users.DeleteUsers(ctx, ids)
}

type Handler struct{ endpoint *handler.Endpoint }

func (h *Handler) Register(api huma.API) {
	if h != nil && h.endpoint != nil {
		h.endpoint.Register(api)
	}
}
func (h *Handler) OptionalMiddleware() func(huma.Context, func(huma.Context)) {
	if h == nil || h.endpoint == nil {
		return nil
	}
	return h.endpoint.OptionalMiddleware()
}
func (h *Handler) RequiredMiddleware(api huma.API) func(huma.Context, func(huma.Context)) {
	if h == nil || h.endpoint == nil {
		return nil
	}
	return h.endpoint.RequiredMiddleware(api)
}
func (h *Handler) HTTPHandler() http.Handler {
	if h == nil || h.endpoint == nil {
		return http.NotFoundHandler()
	}
	return h.endpoint.Handler()
}

type Schema struct {
	Models []any
	Tables []string
}

func (s Schema) Apply(ctx context.Context, db bun.IDB) error {
	return repository.Schema{Models: s.Models, Tables: s.Tables}.Apply(ctx, db)
}

func DatabaseSchema() Schema {
	s := repository.DatabaseSchema()
	return Schema{Models: s.Models, Tables: s.Tables}
}
func ApplySchema(ctx context.Context, db bun.IDB) error {
	return DatabaseSchema().Apply(ctx, db)
}
