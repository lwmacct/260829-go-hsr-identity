package handler

import (
	"context"
	"errors"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/lwmacct/260829-go-hsr-identity/pkg/identity/domain"
)

type credentialsBody struct {
	Handle   string `json:"handle" minLength:"1"`
	Password string `json:"password" minLength:"1"`
}
type credentialsInput struct{ Body credentialsBody }
type passwordBody struct {
	CurrentPassword string `json:"currentPassword" minLength:"1"`
	NewPassword     string `json:"newPassword" minLength:"1"`
}
type passwordInput struct{ Body passwordBody }
type sessionResponse struct {
	SetCookie string `header:"Set-Cookie"`
	Body      sessionView
}
type basicResponse struct{ Body operationView }
type operationView struct {
	OK bool `json:"ok"`
}
type sessionView struct {
	Authenticated   bool      `json:"authenticated"`
	User            userView  `json:"user,omitzero"`
	SessionID       string    `json:"sessionId,omitempty"`
	AuthenticatedAt timeValue `json:"authenticatedAt,omitzero"`
	ExpiresAt       timeValue `json:"expiresAt,omitzero"`
}

// timeValue keeps the public response schema stable while allowing zero times
// to be omitted by Huma's JSON encoder.
type timeValue = time.Time

func (e *Endpoint) register(ctx context.Context, input *credentialsInput) (*sessionResponse, error) {
	if !e.config.RegistrationEnabled {
		return nil, huma.Error403Forbidden("registration is disabled")
	}
	if err := requestMetaErrorFromContext(ctx); err != nil {
		return nil, mapError(err, false)
	}
	user, issued, err := e.services.Accounts.RegisterAndLogin(ctx, domain.UserCreateInput{Handle: input.Body.Handle}, input.Body.Password, requestMetaFromContext(ctx))
	if err != nil {
		return nil, mapError(err, false)
	}
	return &sessionResponse{SetCookie: e.cookie(issued.Token, issued.Session.ExpiresAt, false), Body: sessionViewFromPrincipal(&domain.Principal{Subject: user.ID, User: user, SessionID: issued.Session.ID, AuthenticatedAt: issued.Session.CreatedAt, ExpiresAt: issued.Session.ExpiresAt})}, nil
}

func (e *Endpoint) login(ctx context.Context, input *credentialsInput) (*sessionResponse, error) {
	if err := requestMetaErrorFromContext(ctx); err != nil {
		return nil, mapError(err, false)
	}
	user, issued, err := e.services.Accounts.Login(ctx, input.Body.Handle, input.Body.Password, requestMetaFromContext(ctx))
	if err != nil {
		return nil, mapError(err, true)
	}
	return &sessionResponse{SetCookie: e.cookie(issued.Token, issued.Session.ExpiresAt, false), Body: sessionViewFromPrincipal(&domain.Principal{Subject: user.ID, User: user, SessionID: issued.Session.ID, AuthenticatedAt: issued.Session.CreatedAt, ExpiresAt: issued.Session.ExpiresAt})}, nil
}

func (e *Endpoint) logout(ctx context.Context, _ *struct{}) (*sessionResponse, error) {
	if e.services.Sessions != nil && requestMetaErrorFromContext(ctx) == nil {
		if err := e.services.Sessions.Revoke(ctx, tokenFromContext(ctx), "logout", requestMetaFromContext(ctx)); err != nil && !errors.Is(err, domain.ErrNotFound) && !errors.Is(err, domain.ErrUnauthenticated) && !errors.Is(err, domain.ErrRevoked) && !errors.Is(err, domain.ErrExpired) && !errors.Is(err, domain.ErrBindingMismatch) {
			return nil, mapError(err, false)
		}
	}
	return &sessionResponse{SetCookie: e.cookie("", time.Time{}, true), Body: sessionView{Authenticated: false}}, nil
}

func (e *Endpoint) currentSession(ctx context.Context, _ *struct{}) (*struct{ Body sessionView }, error) {
	p, ok := domain.PrincipalFromContext(ctx)
	if !ok || !p.Active() {
		return nil, huma.Error401Unauthorized("unauthorized")
	}
	return &struct{ Body sessionView }{Body: sessionViewFromPrincipal(p)}, nil
}

func (e *Endpoint) changePassword(ctx context.Context, input *passwordInput) (*sessionResponse, error) {
	p, ok := domain.PrincipalFromContext(ctx)
	if !ok || !p.Active() {
		return nil, huma.Error401Unauthorized("unauthorized")
	}
	if err := e.services.Accounts.ChangePassword(ctx, p.Subject, input.Body.CurrentPassword, input.Body.NewPassword); err != nil {
		return nil, mapError(err, false)
	}
	return &sessionResponse{SetCookie: e.cookie("", time.Time{}, true), Body: sessionView{Authenticated: false}}, nil
}

func (e *Endpoint) revokeAll(ctx context.Context, _ *struct{}) (*basicResponse, error) {
	p, ok := domain.PrincipalFromContext(ctx)
	if !ok || !p.Active() {
		return nil, huma.Error401Unauthorized("unauthorized")
	}
	if err := e.services.Sessions.RevokeForUsers(ctx, []domain.UserID{p.Subject}, "logout_all"); err != nil {
		return nil, mapError(err, false)
	}
	return &basicResponse{Body: operationView{OK: true}}, nil
}
