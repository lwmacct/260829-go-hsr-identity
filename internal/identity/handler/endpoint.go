package handler

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"github.com/lwmacct/260829-go-hsr-identity/internal/identity/service"
	"github.com/lwmacct/260829-go-hsr-identity/pkg/identity/domain"
)

type Config struct {
	AuthPrefix          string
	AdminPrefix         string
	RegistrationEnabled bool
	EnableAdminRoutes   bool
	EnableRBACRoutes    bool
	CookieName          string
	CookiePath          string
	CookieDomain        string
	SecureCookie        bool
	SameSite            http.SameSite
	TokenExtractor      func(*http.Request) string
	RequestMetaResolver func(*http.Request) (domain.RequestMeta, error)
	Authorizer          func(context.Context, *domain.Principal, string) error
	ChallengeProvider   domain.HumanChallengeProvider
	RequireChallenge    bool
}

type Services struct {
	Users         *service.UserService
	Passwords     *service.PasswordService
	Sessions      *service.SessionService
	Accounts      *service.AccountService
	Authorization *service.AuthorizationService
}

type Endpoint struct {
	config   Config
	services Services
}

func NewEndpoint(config Config, services Services) *Endpoint {
	if config.AuthPrefix == "" {
		config.AuthPrefix = "/auth"
	}
	if config.AdminPrefix == "" {
		config.AdminPrefix = "/admin"
	}
	if config.CookieName == "" {
		config.CookieName = "identity_session"
	}
	if config.CookiePath == "" {
		config.CookiePath = "/"
	}
	if config.SameSite == 0 {
		config.SameSite = http.SameSiteLaxMode
	}
	return &Endpoint{config: config, services: services}
}

func (e *Endpoint) Handler() http.Handler {
	mux := http.NewServeMux()
	api := humago.New(mux, huma.DefaultConfig("Identity API", "1.0.0"))
	e.Register(api)
	return mux
}

func (e *Endpoint) Register(api huma.API) {
	if e == nil || api == nil {
		return
	}
	auth := huma.NewGroup(api, e.config.AuthPrefix)
	auth.UseMiddleware(e.OptionalMiddleware())
	huma.Register(auth, huma.Operation{OperationID: "identity-register", Method: http.MethodPost, Path: "/register", DefaultStatus: http.StatusCreated, Tags: []string{"Identity"}}, e.register)
	huma.Register(auth, huma.Operation{OperationID: "identity-login", Method: http.MethodPost, Path: "/login", Tags: []string{"Identity"}}, e.login)
	huma.Register(auth, huma.Operation{OperationID: "identity-logout", Method: http.MethodPost, Path: "/logout", Tags: []string{"Identity"}}, e.logout)
	huma.Register(auth, huma.Operation{OperationID: "identity-config", Method: http.MethodGet, Path: "/config", Tags: []string{"Identity"}}, e.configOutput)
	huma.Register(auth, huma.Operation{OperationID: "identity-create-challenge", Method: http.MethodPost, Path: "/challenges", Tags: []string{"Identity"}}, e.createChallenge)
	protected := huma.NewGroup(auth)
	protected.UseMiddleware(e.RequiredMiddleware(api))
	huma.Register(protected, huma.Operation{OperationID: "identity-current-session", Method: http.MethodGet, Path: "/session", Tags: []string{"Identity"}}, e.currentSession)
	huma.Register(protected, huma.Operation{OperationID: "identity-change-password", Method: http.MethodPatch, Path: "/password", Tags: []string{"Identity"}}, e.changePassword)
	huma.Register(protected, huma.Operation{OperationID: "identity-revoke-sessions", Method: http.MethodPost, Path: "/sessions/revoke-all", Tags: []string{"Identity"}}, e.revokeAll)
	if e.config.EnableAdminRoutes {
		e.registerAdmin(api)
		if e.config.EnableRBACRoutes {
			e.registerAuthorization(api)
		}
	}
}

func (e *Endpoint) verifyChallenge(ctx context.Context, response *challengeBody) error {
	if !e.config.RequireChallenge {
		return nil
	}
	if e.config.ChallengeProvider == nil || response == nil {
		return domain.ErrHumanChallengeInvalid
	}
	if strings.TrimSpace(response.Provider) == "" || strings.TrimSpace(response.Provider) != strings.TrimSpace(e.config.ChallengeProvider.Name()) {
		return domain.ErrHumanChallengeInvalid
	}
	if err := requestMetaErrorFromContext(ctx); err != nil {
		return err
	}
	if err := e.config.ChallengeProvider.Verify(ctx, response.domain(), requestMetaFromContext(ctx)); err != nil {
		return domain.ErrHumanChallengeInvalid
	}
	return nil
}

func (e *Endpoint) configOutput(_ context.Context, _ *struct{}) (*struct{ Body configView }, error) {
	body := configView{RegistrationEnabled: e.config.RegistrationEnabled}
	if e.config.ChallengeProvider != nil {
		public := e.config.ChallengeProvider.PublicConfig()
		body.Challenge = &humanChallengeConfigView{Provider: public.Provider, SiteKey: public.SiteKey, Required: e.config.RequireChallenge}
	}
	return &struct{ Body configView }{Body: body}, nil
}

func (e *Endpoint) createChallenge(ctx context.Context, _ *struct{}) (*struct{ Body challengeView }, error) {
	if e.config.ChallengeProvider == nil {
		return nil, huma.Error400BadRequest("challenge provider unsupported")
	}
	if err := requestMetaErrorFromContext(ctx); err != nil {
		return nil, mapError(err, false)
	}
	challenge, err := e.config.ChallengeProvider.Create(ctx, requestMetaFromContext(ctx))
	if err != nil {
		if errors.Is(err, domain.ErrHumanChallengeLimitExceeded) {
			return nil, huma.Error429TooManyRequests("too many challenges")
		}
		if errors.Is(err, domain.ErrHumanChallengeUnsupported) {
			return nil, huma.Error400BadRequest("challenge creation unsupported")
		}
		return nil, huma.Error500InternalServerError("challenge creation failed")
	}
	return &struct{ Body challengeView }{Body: challengeViewFromDomain(challenge)}, nil
}

func (e *Endpoint) OptionalMiddleware() func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		if e == nil {
			next(ctx)
			return
		}
		r := requestFromContext(ctx)
		meta, metaErr := e.requestMeta(r)
		base := withRequestData(ctx.Context(), r, meta, metaErr)
		token := e.token(r)
		if token != "" {
			base = context.WithValue(base, tokenKey{}, token)
		}
		if token != "" && e.services.Sessions != nil && metaErr == nil {
			if principal, err := e.services.Sessions.Resolve(base, token, meta); err == nil {
				base = domain.ContextWithPrincipal(base, principal)
			}
		}
		next(huma.WithContext(ctx, base))
	}
}

func (e *Endpoint) RequiredMiddleware(api huma.API) func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		e.OptionalMiddleware()(ctx, func(nextCtx huma.Context) {
			if _, ok := domain.PrincipalFromContext(nextCtx.Context()); !ok {
				_ = huma.WriteErr(api, nextCtx, http.StatusUnauthorized, "unauthorized")
				return
			}
			next(nextCtx)
		})
	}
}

type requestDataKey struct{}
type tokenKey struct{}
type requestData struct {
	request *http.Request
	meta    domain.RequestMeta
	err     error
}

func withRequestData(ctx context.Context, r *http.Request, meta domain.RequestMeta, err error) context.Context {
	return context.WithValue(ctx, requestDataKey{}, requestData{request: r, meta: meta, err: err})
}
func requestDataFromContext(ctx context.Context) (requestData, bool) {
	d, ok := ctx.Value(requestDataKey{}).(requestData)
	return d, ok
}
func tokenFromContext(ctx context.Context) string { v, _ := ctx.Value(tokenKey{}).(string); return v }
func requestMetaFromContext(ctx context.Context) domain.RequestMeta {
	if d, ok := requestDataFromContext(ctx); ok {
		return d.meta
	}
	return domain.RequestMeta{}
}
func requestMetaErrorFromContext(ctx context.Context) error {
	if d, ok := requestDataFromContext(ctx); ok {
		return d.err
	}
	return nil
}

func requestFromContext(ctx huma.Context) *http.Request {
	if r := unwrapHTTPContext(ctx); r != nil {
		return r
	}
	r := &http.Request{Method: ctx.Method(), RemoteAddr: ctx.RemoteAddr(), Header: make(http.Header)}
	ctx.EachHeader(func(name, value string) { r.Header.Add(name, value) })
	return r
}

func unwrapHTTPContext(ctx huma.Context) (request *http.Request) {
	defer func() { _ = recover() }()
	request, _ = humago.Unwrap(ctx)
	return request
}
func (e *Endpoint) token(r *http.Request) string {
	if r == nil {
		return ""
	}
	if e.config.TokenExtractor != nil {
		return strings.TrimSpace(e.config.TokenExtractor(r))
	}
	if c, err := r.Cookie(e.config.CookieName); err == nil && c.Value != "" {
		return c.Value
	}
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	if len(auth) > 7 && strings.EqualFold(auth[:7], "bearer ") {
		return strings.TrimSpace(auth[7:])
	}
	return ""
}
func (e *Endpoint) requestMeta(r *http.Request) (domain.RequestMeta, error) {
	if e != nil && e.config.RequestMetaResolver != nil {
		meta, err := e.config.RequestMetaResolver(r)
		if err != nil {
			return domain.RequestMeta{}, err
		}
		return domain.NormalizeRequestMeta(meta)
	}
	if r == nil {
		return domain.RequestMeta{}, domain.ErrInvalidRequestMeta
	}
	ip := strings.TrimSpace(r.RemoteAddr)
	if host, _, err := net.SplitHostPort(ip); err == nil {
		ip = host
	}
	return domain.NormalizeRequestMeta(domain.RequestMeta{ClientIP: ip, UserAgent: r.UserAgent(), DeviceID: r.Header.Get("X-Device-ID")})
}

func (e *Endpoint) cookie(token string, expires time.Time, clear bool) string {
	maxAge := 0
	if clear {
		maxAge = -1
		expires = time.Unix(1, 0)
	}
	return (&http.Cookie{Name: e.config.CookieName, Value: token, Path: e.config.CookiePath, Domain: e.config.CookieDomain, Secure: e.config.SecureCookie, HttpOnly: true, SameSite: e.config.SameSite, Expires: expires, MaxAge: maxAge}).String()
}
func (e *Endpoint) authorize(ctx context.Context, action string) error {
	p, ok := domain.PrincipalFromContext(ctx)
	if !ok {
		return domain.ErrUnauthenticated
	}
	if e.config.Authorizer == nil {
		return domain.ErrForbidden
	}
	if err := e.config.Authorizer(ctx, p, action); err != nil {
		return err
	}
	return nil
}

func mapError(err error, login bool) error {
	if err == nil {
		return nil
	}
	if login && (errors.Is(err, domain.ErrNotFound) || errors.Is(err, domain.ErrDisabled) || errors.Is(err, domain.ErrUnauthenticated)) {
		return huma.Error401Unauthorized("invalid credentials")
	}
	switch {
	case errors.Is(err, domain.ErrUnauthenticated), errors.Is(err, domain.ErrExpired), errors.Is(err, domain.ErrRevoked), errors.Is(err, domain.ErrBindingMismatch):
		return huma.Error401Unauthorized("unauthorized")
	case errors.Is(err, domain.ErrForbidden):
		return huma.Error403Forbidden("forbidden")
	case errors.Is(err, domain.ErrDisabled):
		return huma.Error403Forbidden("user is disabled")
	case errors.Is(err, domain.ErrNotFound):
		return huma.Error404NotFound("not found")
	case errors.Is(err, domain.ErrConflict), errors.Is(err, domain.ErrHandleTaken):
		return huma.Error409Conflict("identity conflict")
	case errors.Is(err, domain.ErrInvalid), errors.Is(err, domain.ErrWeakPassword), errors.Is(err, domain.ErrInvalidState), errors.Is(err, domain.ErrInvalidRequestMeta):
		return huma.Error422UnprocessableEntity("invalid identity request")
	case errors.Is(err, domain.ErrHumanChallengeInvalid):
		if login {
			return huma.Error401Unauthorized("invalid challenge")
		}
		return huma.Error422UnprocessableEntity("invalid challenge")
	case errors.Is(err, domain.ErrHumanChallengeUnsupported):
		return huma.Error400BadRequest("challenge provider unsupported")
	default:
		return huma.Error500InternalServerError("internal server error")
	}
}
