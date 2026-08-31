package identity

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/lwmacct/260829-go-hsr-identity/internal/identity/handler"
	"github.com/lwmacct/260829-go-hsr-identity/internal/identity/repository"
	"github.com/lwmacct/260829-go-hsr-identity/internal/identity/service"
	"github.com/lwmacct/260829-go-hsr-identity/pkg/identity/domain"
	"github.com/uptrace/bun"
)

type Module struct {
	users            *service.UserService
	password         *service.PasswordService
	session          *service.SessionService
	authorization    *service.AuthorizationService
	account          *service.AccountService
	challenge        HumanChallengeVerifier
	challengeCreator HumanChallengeCreator
	handler          *handler.Endpoint
}

func New(options Options) (*Module, error) {
	if options.DB == nil {
		return nil, errors.New("identity: database is required")
	}
	if options.HTTP.SameSite == http.SameSiteNoneMode && !options.HTTP.SecureCookie {
		return nil, errors.New("identity: SameSite=None cookies require SecureCookie")
	}
	if options.HTTP.CookiePath != "" && !strings.HasPrefix(options.HTTP.CookiePath, "/") {
		return nil, errors.New("identity: cookie path must start with /")
	}
	if err := ValidateSchema(context.Background(), options.DB); err != nil {
		return nil, fmt.Errorf("identity: validate database schema: %w", err)
	}
	if (options.HTTP.Challenge.RequireOnLogin || options.HTTP.Challenge.RequireOnRegistration) && options.HTTP.Challenge.Verifier == nil {
		return nil, errors.New("identity: challenge verifier is required when challenge enforcement is enabled")
	}
	if verifier := options.HTTP.Challenge.Verifier; verifier != nil {
		name := strings.TrimSpace(verifier.Name())
		public := verifier.PublicConfig()
		if name == "" || strings.TrimSpace(public.Provider) == "" || strings.TrimSpace(public.Provider) != name {
			return nil, errors.New("identity: challenge verifier must expose a stable provider name")
		}
	}
	if options.HTTP.Challenge.Verifier != nil && options.HTTP.Challenge.Creator != nil {
		verifierName := strings.TrimSpace(options.HTTP.Challenge.Verifier.Name())
		creatorName := challengeCreatorName(options.HTTP.Challenge.Creator)
		if verifierName == "" || (creatorName != "" && verifierName != creatorName) {
			return nil, errors.New("identity: challenge verifier and creator providers must match")
		}
	}
	now := options.Clock
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	username := options.UsernamePolicy
	if username == nil {
		username = UsernamePolicyFunc(LowerASCIIUsernamePolicy)
	}
	store := repository.NewStore(options.DB)
	users, err := service.NewUserService(store, store, username, now)
	if err != nil {
		return nil, err
	}
	users.SetEventSink(options.Events)
	if options.DeleteParticipant != nil {
		users.SetDeleteParticipant(func(ctx context.Context, db bun.IDB, users []domain.User) error {
			return options.DeleteParticipant(ctx, db, users)
		})
	}
	authorization, err := service.NewAuthorizationService(store, store, store, now, options.Authorization.DefaultRoleCodes)
	if err != nil {
		return nil, err
	}
	authorization.SetEventSink(options.Events)
	claims := func(ctx context.Context, user *domain.User) (domain.Claims, error) {
		builtIn, err := authorization.Claims(ctx, user)
		if err != nil {
			return domain.Claims{}, err
		}
		if options.Session.Claims == nil {
			return builtIn, nil
		}
		extra, err := options.Session.Claims(ctx, user)
		if err != nil {
			return domain.Claims{}, err
		}
		return mergeClaims(builtIn, extra), nil
	}
	password, err := service.NewPasswordService(store, store, service.PasswordOptions{
		Policy: service.PasswordPolicy{
			MinLength:      options.Password.Policy.MinLength,
			MaxLength:      options.Password.Policy.MaxLength,
			RequireUpper:   options.Password.Policy.RequireUpper,
			RequireLower:   options.Password.Policy.RequireLower,
			RequireDigit:   options.Password.Policy.RequireDigit,
			RequireSymbol:  options.Password.Policy.RequireSymbol,
			RejectUsername: options.Password.Policy.RejectUsername,
			RejectCommon:   options.Password.Policy.RejectCommon,
		},
		Hasher: options.Password.Hasher,
		Argon2id: service.Argon2idParams{
			Memory:      options.Password.Argon2id.Memory,
			Iterations:  options.Password.Argon2id.Iterations,
			Parallelism: options.Password.Argon2id.Parallelism,
			SaltLength:  options.Password.Argon2id.SaltLength,
			KeyLength:   options.Password.Argon2id.KeyLength,
		},
	}, now, username)
	if err != nil {
		return nil, err
	}
	session, err := service.NewSessionService(store, store, service.SessionOptions{
		TTL:           options.Session.TTL,
		IdleTimeout:   options.Session.IdleTimeout,
		TouchInterval: options.Session.TouchInterval,
		TokenBytes:    options.Session.TokenBytes,
		Binding:       options.Session.Binding,
		Claims:        claims,
	}, now)
	if err != nil {
		return nil, err
	}
	session.SetEventSink(options.Events)
	account, err := service.NewAccountService(users, password, session, authorization, store)
	if err != nil {
		return nil, err
	}
	account.SetLoginGuard(options.LoginGuard)
	account.SetEventSink(options.Events)
	authorizer := func(ctx context.Context, principal *domain.Principal, action string) error {
		if err := authorization.Authorize(ctx, principal, action); err != nil {
			return err
		}
		if options.Authorizer != nil {
			return options.Authorizer(ctx, principal, action)
		}
		return nil
	}
	creator := options.HTTP.Challenge.Creator
	if creator == nil {
		creator, _ = options.HTTP.Challenge.Verifier.(HumanChallengeCreator)
	}
	endpoint := handler.NewEndpoint(handler.Config{
		AuthPrefix:                     options.HTTP.AuthPrefix,
		AdminPrefix:                    options.HTTP.AdminPrefix,
		LoginEnabled:                   options.HTTP.LoginEnabled,
		RegistrationEnabled:            options.HTTP.RegistrationEnabled,
		EnableAdminRoutes:              options.HTTP.EnableAdminRoutes,
		EnableRBACRoutes:               options.HTTP.EnableRBACRoutes,
		CookieName:                     options.HTTP.CookieName,
		CookiePath:                     options.HTTP.CookiePath,
		CookieDomain:                   options.HTTP.CookieDomain,
		SecureCookie:                   options.HTTP.SecureCookie,
		SameSite:                       options.HTTP.SameSite,
		TokenExtractor:                 options.HTTP.TokenExtractor,
		RequestMetaResolver:            options.HTTP.RequestMetaResolver,
		ChallengeVerifier:              options.HTTP.Challenge.Verifier,
		ChallengeCreator:               creator,
		RequireChallengeOnLogin:        options.HTTP.Challenge.RequireOnLogin,
		RequireChallengeOnRegistration: options.HTTP.Challenge.RequireOnRegistration,
		Authorizer:                     authorizer,
	}, handler.Services{Users: users, Passwords: password, Sessions: session, Accounts: account, Authorization: authorization})
	return &Module{users: users, password: password, session: session, authorization: authorization, account: account, challenge: options.HTTP.Challenge.Verifier, challengeCreator: creator, handler: endpoint}, nil
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
func (m *Module) UserByUsername(ctx context.Context, username string) (*User, error) {
	return m.users.UserByUsername(ctx, username)
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

func (m *Module) ListUsers(ctx context.Context, filter UserFilter) ([]User, int, error) {
	return m.users.Users(ctx, filter)
}
func (m *Module) RegisterUser(ctx context.Context, input UserCreateInput, password string) (*User, error) {
	return m.account.Register(ctx, input, password)
}

// ProvisionUser atomically creates a user, password and explicit role
// bindings. It is intended for trusted host-side administration.
func (m *Module) ProvisionUser(ctx context.Context, input UserProvisionInput) (*User, error) {
	return m.account.ProvisionUser(ctx, input)
}

func (m *Module) RegisterAndLogin(ctx context.Context, input UserCreateInput, password string, meta RequestMeta) (*User, *IssuedSession, error) {
	return m.account.RegisterAndLogin(ctx, input, password, meta)
}
func (m *Module) Authenticate(ctx context.Context, username, password string) (*User, error) {
	return m.password.Authenticate(ctx, username, password)
}
func (m *Module) Login(ctx context.Context, username, password string, meta RequestMeta) (*User, *IssuedSession, error) {
	return m.account.Login(ctx, username, password, meta)
}
func (m *Module) CreateSession(ctx context.Context, userID UserID, meta RequestMeta) (*IssuedSession, error) {
	return m.account.IssueSession(ctx, userID, meta)
}
func (m *Module) ResolveSession(ctx context.Context, token string, meta RequestMeta) (*Principal, error) {
	return m.session.Resolve(ctx, token, meta)
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
func (m *Module) ListUserSessions(ctx context.Context, userID UserID) ([]Session, error) {
	return m.session.ListForUser(ctx, userID)
}
func (m *Module) RevokeSessionByID(ctx context.Context, sessionID SessionID, reason string) error {
	return m.session.RevokeByID(ctx, sessionID, reason)
}
func (m *Module) DeleteExpiredSessions(ctx context.Context) (int64, error) {
	return m.session.DeleteExpired(ctx)
}
func (m *Module) ChangePassword(ctx context.Context, userID UserID, current, next string) error {
	return m.account.ChangePassword(ctx, userID, current, next)
}

// ChallengeConfig returns the provider configuration exposed to clients.
func (m *Module) ChallengeConfig() HumanChallengeConfig {
	if m == nil || m.challenge == nil {
		return HumanChallengeConfig{}
	}
	return m.challenge.PublicConfig()
}

// CreateChallenge creates a provider-specific challenge for a client.
func (m *Module) CreateChallenge(ctx context.Context, meta RequestMeta) (*HumanChallenge, error) {
	if m == nil || m.challengeCreator == nil {
		return nil, ErrHumanChallengeUnsupported
	}
	challenge, err := m.challengeCreator.Create(ctx, meta)
	if err != nil {
		return nil, err
	}
	if challenge == nil {
		return nil, ErrHumanChallengeUnsupported
	}
	if strings.TrimSpace(challenge.Provider) == "" {
		return nil, ErrHumanChallengeUnsupported
	}
	if m.challenge != nil && strings.TrimSpace(challenge.Provider) != strings.TrimSpace(m.challenge.Name()) {
		return nil, ErrHumanChallengeUnsupported
	}
	return challenge, nil
}

// VerifyChallenge validates a provider response. Hosts can use this for
// protected actions such as resource trials in addition to login flows.
func (m *Module) VerifyChallenge(ctx context.Context, response HumanChallengeResponse, meta RequestMeta) error {
	if m == nil || m.challenge == nil {
		return ErrHumanChallengeUnsupported
	}
	if strings.TrimSpace(response.Provider) == "" || strings.TrimSpace(response.Provider) != strings.TrimSpace(m.challenge.Name()) {
		return ErrHumanChallengeInvalid
	}
	if err := m.challenge.Verify(ctx, response, meta); err != nil {
		if errors.Is(err, ErrHumanChallengeUnavailable) {
			return ErrHumanChallengeUnavailable
		}
		if errors.Is(err, ErrHumanChallengeUnsupported) {
			return ErrHumanChallengeUnsupported
		}
		return ErrHumanChallengeInvalid
	}
	return nil
}

func challengeCreatorName(creator HumanChallengeCreator) string {
	if named, ok := creator.(interface{ Name() string }); ok {
		return strings.TrimSpace(named.Name())
	}
	return ""
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

func (m *Module) Authorize(ctx context.Context, principal *Principal, permission string) error {
	if m == nil || m.authorization == nil {
		return ErrForbidden
	}
	return m.authorization.Authorize(ctx, principal, permission)
}

func (m *Module) HasPermission(principal *Principal, permission string) bool {
	return m != nil && m.authorization != nil && service.HasPermission(principal, permission)
}

func (m *Module) CreateRole(ctx context.Context, input RoleInput) (*Role, error) {
	return m.authorization.CreateRole(ctx, input)
}
func (m *Module) EnsureRole(ctx context.Context, input RoleInput) (*Role, error) {
	return m.authorization.EnsureRole(ctx, input)
}
func (m *Module) ListRoles(ctx context.Context, filter RoleFilter) ([]Role, int, error) {
	return m.authorization.ListRoles(ctx, filter)
}
func (m *Module) RoleByID(ctx context.Context, id RoleID) (*Role, error) {
	return m.authorization.RoleByID(ctx, id)
}
func (m *Module) RoleByCode(ctx context.Context, code string) (*Role, error) {
	return m.authorization.RoleByCode(ctx, code)
}
func (m *Module) UpdateRole(ctx context.Context, id RoleID, input RoleInput) (*Role, error) {
	return m.authorization.UpdateRole(ctx, id, input)
}
func (m *Module) DeleteRole(ctx context.Context, id RoleID) error {
	return m.authorization.DeleteRole(ctx, id)
}
func (m *Module) CreatePermission(ctx context.Context, input PermissionInput) (*Permission, error) {
	return m.authorization.CreatePermission(ctx, input)
}
func (m *Module) EnsurePermission(ctx context.Context, input PermissionInput) (*Permission, error) {
	return m.authorization.EnsurePermission(ctx, input)
}
func (m *Module) ListPermissions(ctx context.Context, filter PermissionFilter) ([]Permission, int, error) {
	return m.authorization.ListPermissions(ctx, filter)
}
func (m *Module) PermissionByID(ctx context.Context, id PermissionID) (*Permission, error) {
	return m.authorization.PermissionByID(ctx, id)
}
func (m *Module) PermissionByCode(ctx context.Context, code string) (*Permission, error) {
	return m.authorization.PermissionByCode(ctx, code)
}
func (m *Module) UpdatePermission(ctx context.Context, id PermissionID, input PermissionInput) (*Permission, error) {
	return m.authorization.UpdatePermission(ctx, id, input)
}
func (m *Module) DeletePermission(ctx context.Context, id PermissionID) error {
	return m.authorization.DeletePermission(ctx, id)
}
func (m *Module) UserRoles(ctx context.Context, userID UserID) ([]Role, error) {
	return m.authorization.UserRoles(ctx, userID)
}
func (m *Module) SetUserRoles(ctx context.Context, userID UserID, roleCodes []string) error {
	return m.authorization.SetUserRoles(ctx, userID, roleCodes)
}
func (m *Module) RolePermissions(ctx context.Context, roleID RoleID) ([]Permission, error) {
	return m.authorization.RolePermissions(ctx, roleID)
}
func (m *Module) SetRolePermissions(ctx context.Context, roleID RoleID, permissionCodes []string) error {
	return m.authorization.SetRolePermissions(ctx, roleID, permissionCodes)
}

func mergeClaims(base, extra Claims) Claims {
	roles := append([]string(nil), base.Roles...)
	permissions := append([]string(nil), base.Permissions...)
	roles = append(roles, extra.Roles...)
	permissions = append(permissions, extra.Permissions...)
	roleSet := make(map[string]struct{}, len(roles))
	permissionSet := make(map[string]struct{}, len(permissions))
	uniqueRoles := roles[:0]
	for _, role := range roles {
		if role == "" {
			continue
		}
		if _, ok := roleSet[role]; ok {
			continue
		}
		roleSet[role] = struct{}{}
		uniqueRoles = append(uniqueRoles, role)
	}
	uniquePermissions := permissions[:0]
	for _, permission := range permissions {
		if permission == "" {
			continue
		}
		if _, ok := permissionSet[permission]; ok {
			continue
		}
		permissionSet[permission] = struct{}{}
		uniquePermissions = append(uniquePermissions, permission)
	}
	attributes := make(map[string]string, len(base.Attributes)+len(extra.Attributes))
	for key, value := range base.Attributes {
		attributes[key] = value
	}
	for key, value := range extra.Attributes {
		attributes[key] = value
	}
	return Claims{Roles: uniqueRoles, Permissions: uniquePermissions, Attributes: attributes}
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

func ValidateSchema(ctx context.Context, db *bun.DB) error {
	return repository.ValidateSchema(ctx, db)
}
