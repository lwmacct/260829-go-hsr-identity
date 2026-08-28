// Package httpauth contains transport-neutral net/http authentication helpers.
package httpauth

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/lwmacct/260829-go-hsr-identity/pkg/identity"
)

type CookieConfig struct {
	Name     string
	Path     string
	Domain   string
	Secure   bool
	HTTPOnly bool
	SameSite http.SameSite
	MaxAge   time.Duration
}

func DefaultCookieConfig() CookieConfig {
	return CookieConfig{Name: "identity_session", Path: "/", HTTPOnly: true, SameSite: http.SameSiteLaxMode}
}

func (c CookieConfig) normalized() CookieConfig {
	if c.Name == "" {
		c.Name = "identity_session"
	}
	if c.Path == "" {
		c.Path = "/"
	}
	if c.SameSite == 0 {
		c.SameSite = http.SameSiteLaxMode
	}
	return c
}

func SessionCookie(w http.ResponseWriter, token string, expiresAt time.Time, config CookieConfig) {
	config = config.normalized()
	maxAge := 0
	if config.MaxAge != 0 {
		maxAge = int(config.MaxAge.Seconds())
	} else if !expiresAt.IsZero() {
		maxAge = max(0, int(time.Until(expiresAt).Seconds()))
	}
	http.SetCookie(w, &http.Cookie{Name: config.Name, Value: token, Path: config.Path, Domain: config.Domain, Secure: config.Secure, HttpOnly: config.HTTPOnly, SameSite: config.SameSite, Expires: expiresAt, MaxAge: maxAge})
}

func SetSessionCookie(w http.ResponseWriter, token string, expiresAt time.Time, config CookieConfig) {
	SessionCookie(w, token, expiresAt, config)
}

func ClearSessionCookie(w http.ResponseWriter, config CookieConfig) {
	config = config.normalized()
	http.SetCookie(w, &http.Cookie{Name: config.Name, Value: "", Path: config.Path, Domain: config.Domain, Secure: config.Secure, HttpOnly: config.HTTPOnly, SameSite: config.SameSite, Expires: time.Unix(1, 0), MaxAge: -1})
}

func TokenFromRequest(r *http.Request, config CookieConfig) string {
	if r == nil {
		return ""
	}
	if cookie, err := r.Cookie(config.normalized().Name); err == nil && cookie.Value != "" {
		return cookie.Value
	}
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	if len(auth) > 7 && strings.EqualFold(auth[:7], "bearer ") {
		return strings.TrimSpace(auth[7:])
	}
	return ""
}

type TokenSource interface{ Token(*http.Request) string }
type TokenSourceFunc func(*http.Request) string

func (f TokenSourceFunc) Token(r *http.Request) string {
	if f == nil {
		return ""
	}
	return f(r)
}

type cookieTokenSource struct{ config CookieConfig }

func (s cookieTokenSource) Token(r *http.Request) string { return TokenFromRequest(r, s.config) }

type Middleware struct {
	Resolver identity.SessionResolver
	Cookie   CookieConfig
	Source   TokenSource
	OnError  func(http.ResponseWriter, *http.Request, error)
	Meta     func(*http.Request) (identity.RequestMeta, error)
}

func New(resolver identity.SessionResolver, config CookieConfig) *Middleware {
	config = config.normalized()
	return &Middleware{Resolver: resolver, Cookie: config, Source: cookieTokenSource{config}, Meta: defaultRequestMeta}
}

func (m *Middleware) Optional(next http.Handler) http.Handler   { return m.wrap(next, false) }
func (m *Middleware) Required(next http.Handler) http.Handler   { return m.wrap(next, true) }
func (m *Middleware) Require(next http.Handler) http.Handler    { return m.Required(next) }
func (m *Middleware) Middleware(next http.Handler) http.Handler { return m.Optional(next) }

func (m *Middleware) wrap(next http.Handler, required bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if m == nil || m.Resolver == nil {
			if required {
				m.error(w, r, errors.New("identity/httpauth: resolver is not configured"))
				return
			}
			next.ServeHTTP(w, r)
			return
		}
		source := m.Source
		if source == nil {
			source = cookieTokenSource{m.Cookie}
		}
		token := source.Token(r)
		if token == "" {
			if required {
				m.error(w, r, identity.ErrUnauthenticated)
				return
			}
			next.ServeHTTP(w, r)
			return
		}
		meta, err := m.requestMeta(r)
		if err != nil {
			if required {
				m.error(w, r, err)
				return
			}
			next.ServeHTTP(w, r)
			return
		}
		principal, err := m.Resolver.ResolveSession(r.Context(), token, meta)
		if err != nil {
			if required {
				m.error(w, r, err)
				return
			}
			next.ServeHTTP(w, r)
			return
		}
		ctx := identity.ContextWithPrincipal(r.Context(), principal)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (m *Middleware) requestMeta(r *http.Request) (identity.RequestMeta, error) {
	resolver := m.Meta
	if resolver == nil {
		resolver = defaultRequestMeta
	}
	return resolver(r)
}

func defaultRequestMeta(r *http.Request) (identity.RequestMeta, error) {
	meta, ok := identity.RequestMetaFromHTTP(r)
	if !ok {
		return identity.RequestMeta{}, identity.ErrInvalidRequestMeta
	}
	return meta, nil
}

func (m *Middleware) error(w http.ResponseWriter, r *http.Request, err error) {
	if m != nil && m.OnError != nil {
		m.OnError(w, r, err)
		return
	}
	status := http.StatusUnauthorized
	if errors.Is(err, identity.ErrBindingMismatch) || errors.Is(err, identity.ErrRevoked) || errors.Is(err, identity.ErrExpired) {
		status = http.StatusUnauthorized
	}
	http.Error(w, http.StatusText(status), status)
}

func Principal(ctx context.Context) (*identity.Principal, bool) {
	return identity.PrincipalFromContext(ctx)
}
func RequirePrincipal(ctx context.Context) (*identity.Principal, error) {
	p, ok := Principal(ctx)
	if !ok || !p.Active() {
		return nil, identity.ErrUnauthenticated
	}
	return p, nil
}
