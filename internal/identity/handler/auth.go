package handler

import (
	"context"
	"errors"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/lwmacct/260829-go-hsr-identity/pkg/identity/domain"
)

type registrationBody struct {
	Challenge *challengeBody `json:"challenge,omitempty"`
	Username  string         `json:"username" minLength:"1" maxLength:"64"`
	Phone     string         `json:"phone,omitempty" maxLength:"16"`
	Email     string         `json:"email,omitempty" maxLength:"254"`
	Password  string         `json:"password" minLength:"1"`
}
type registrationInput struct{ Body registrationBody }
type loginBody struct {
	Challenge  *challengeBody `json:"challenge,omitempty"`
	Identifier string         `json:"identifier" minLength:"1" maxLength:"254"`
	Password   string         `json:"password" minLength:"1"`
}
type loginInput struct{ Body loginBody }
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
	Roles           []string  `json:"roles,omitempty"`
	Permissions     []string  `json:"permissions,omitempty"`
	SessionID       string    `json:"sessionId,omitempty"`
	AuthenticatedAt timeValue `json:"authenticatedAt,omitzero"`
	ExpiresAt       timeValue `json:"expiresAt,omitzero"`
}

type sessionItemView struct {
	ID            string     `json:"id" format:"uuid"`
	UserID        string     `json:"userId" format:"uuid"`
	LoginIP       string     `json:"loginIp,omitempty"`
	LastIP        string     `json:"lastIp,omitempty"`
	ExpiresAt     time.Time  `json:"expiresAt"`
	CreatedAt     time.Time  `json:"createdAt"`
	LastSeenAt    time.Time  `json:"lastSeenAt"`
	RevokedAt     *time.Time `json:"revokedAt,omitempty"`
	RevokedReason string     `json:"revokedReason,omitempty"`
	Current       bool       `json:"current"`
}

type sessionListResponse struct {
	Body struct {
		Items []sessionItemView `json:"items"`
	}
}

type sessionPathInput struct {
	SessionID string `path:"sessionID" format:"uuid"`
}

// timeValue keeps the public response schema stable while allowing zero times
// to be omitted by Huma's JSON encoder.
type timeValue = time.Time

func (e *Endpoint) register(ctx context.Context, input *registrationInput) (*sessionResponse, error) {
	if !e.config.RegistrationEnabled {
		return nil, huma.Error403Forbidden("registration is disabled")
	}
	if err := requestMetaErrorFromContext(ctx); err != nil {
		return nil, mapError(err, false)
	}
	if err := e.verifyChallenge(ctx, input.Body.Challenge, e.config.RequireChallengeOnRegistration); err != nil {
		return nil, mapError(err, false)
	}
	_, issued, err := e.services.Accounts.RegisterAndLogin(ctx, domain.UserCreateInput{
		Username: input.Body.Username,
		Phone:    input.Body.Phone,
		Email:    input.Body.Email,
	}, input.Body.Password, requestMetaFromContext(ctx))
	if err != nil {
		return nil, mapError(err, false)
	}
	principal, err := e.resolveIssuedSession(ctx, issued, requestMetaFromContext(ctx))
	if err != nil {
		return nil, mapError(err, false)
	}
	return &sessionResponse{SetCookie: e.cookie(issued.Token, issued.Session.ExpiresAt, false), Body: sessionViewFromPrincipal(principal)}, nil
}

func (e *Endpoint) login(ctx context.Context, input *loginInput) (*sessionResponse, error) {
	if !e.config.LoginEnabled {
		return nil, huma.Error403Forbidden("login is disabled")
	}
	if err := requestMetaErrorFromContext(ctx); err != nil {
		return nil, mapError(err, false)
	}
	if err := e.verifyChallenge(ctx, input.Body.Challenge, e.config.RequireChallengeOnLogin); err != nil {
		return nil, mapError(err, true)
	}
	_, issued, err := e.services.Accounts.Login(ctx, input.Body.Identifier, input.Body.Password, requestMetaFromContext(ctx))
	if err != nil {
		return nil, mapError(err, true)
	}
	principal, err := e.resolveIssuedSession(ctx, issued, requestMetaFromContext(ctx))
	if err != nil {
		return nil, mapError(err, true)
	}
	return &sessionResponse{SetCookie: e.cookie(issued.Token, issued.Session.ExpiresAt, false), Body: sessionViewFromPrincipal(principal)}, nil
}

func (e *Endpoint) resolveIssuedSession(ctx context.Context, issued *domain.IssuedSession, meta domain.RequestMeta) (*domain.Principal, error) {
	if issued == nil || issued.Session == nil || e.services.Sessions == nil {
		return nil, domain.ErrUnauthenticated
	}
	return e.services.Sessions.Resolve(ctx, issued.Token, meta)
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

func (e *Endpoint) listSessions(ctx context.Context, _ *struct{}) (*sessionListResponse, error) {
	p, ok := domain.PrincipalFromContext(ctx)
	if !ok || !p.Active() {
		return nil, huma.Error401Unauthorized("unauthorized")
	}
	sessions, err := e.services.Sessions.ListForUser(ctx, p.Subject)
	if err != nil {
		return nil, mapError(err, false)
	}
	response := &sessionListResponse{}
	response.Body.Items = make([]sessionItemView, len(sessions))
	for i := range sessions {
		session := sessions[i]
		response.Body.Items[i] = sessionItemView{
			ID:            session.ID.String(),
			UserID:        session.UserID.String(),
			LoginIP:       session.LoginIP,
			LastIP:        session.LastIP,
			ExpiresAt:     session.ExpiresAt,
			CreatedAt:     session.CreatedAt,
			LastSeenAt:    session.LastSeenAt,
			RevokedAt:     session.RevokedAt,
			RevokedReason: session.RevokedReason,
			Current:       session.ID == p.SessionID,
		}
	}
	return response, nil
}

func (e *Endpoint) revokeSession(ctx context.Context, input *sessionPathInput) (*noContent, error) {
	p, ok := domain.PrincipalFromContext(ctx)
	if !ok || !p.Active() {
		return nil, huma.Error401Unauthorized("unauthorized")
	}
	id, err := domain.ParseSessionID(input.SessionID)
	if err != nil {
		return nil, mapError(err, false)
	}
	sessions, err := e.services.Sessions.ListForUser(ctx, p.Subject)
	if err != nil {
		return nil, mapError(err, false)
	}
	for _, session := range sessions {
		if session.ID == id {
			if err := e.services.Sessions.RevokeByID(ctx, id, "self_revoked"); err != nil {
				return nil, mapError(err, false)
			}
			return &noContent{}, nil
		}
	}
	return nil, huma.Error404NotFound("session not found")
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
