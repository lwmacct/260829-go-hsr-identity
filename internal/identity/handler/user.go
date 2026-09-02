package handler

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/lwmacct/260829-go-hsr-identity/pkg/identity/domain"
)

type userView struct {
	ID          string     `json:"id" format:"uuid"`
	Username    string     `json:"username"`
	DisplayName string     `json:"displayName"`
	AvatarURL   string     `json:"avatarUrl,omitempty"`
	State       string     `json:"state"`
	DisabledAt  *time.Time `json:"disabledAt,omitempty"`
	LastLoginAt *time.Time `json:"lastLoginAt,omitempty"`
	CreatedAt   time.Time  `json:"createdAt"`
	UpdatedAt   time.Time  `json:"updatedAt"`
}

type userListBody struct {
	Items    []userView `json:"items"`
	Total    int        `json:"total"`
	Page     int        `json:"page"`
	PageSize int        `json:"pageSize"`
}
type userListResponse struct{ Body userListBody }
type userResponse struct{ Body userView }
type profileResponse struct{ Body profileView }
type profileView struct {
	ID          string              `json:"id" format:"uuid"`
	Username    string              `json:"username"`
	DisplayName string              `json:"displayName"`
	AvatarURL   string              `json:"avatarUrl,omitempty"`
	Contacts    profileContactsView `json:"contacts"`
}
type profileContactsView struct {
	Phone *contactView `json:"phone,omitempty"`
	Email *contactView `json:"email,omitempty"`
}
type contactView struct {
	MaskedValue string    `json:"maskedValue"`
	VerifiedAt  time.Time `json:"verifiedAt"`
}
type profilePatchBody struct {
	DisplayName *string `json:"displayName,omitempty"`
	AvatarURL   *string `json:"avatarUrl,omitempty"`
}
type profilePatchInput struct{ Body profilePatchBody }
type contactKindPathInput struct {
	Kind string `path:"kind" enum:"phone,email"`
}
type contactVerificationStartBody struct {
	Value string `json:"value" minLength:"1" maxLength:"254"`
}
type contactVerificationStartInput struct {
	Kind string `path:"kind" enum:"phone,email"`
	Body contactVerificationStartBody
}
type contactVerificationConfirmBody struct {
	VerificationID string `json:"verificationId" format:"uuid"`
	Code           string `json:"code" minLength:"1" maxLength:"32"`
}
type contactVerificationConfirmInput struct {
	Kind string `path:"kind" enum:"phone,email"`
	Body contactVerificationConfirmBody
}
type contactVerificationResponse struct {
	Body contactVerificationView
}
type contactVerificationView struct {
	VerificationID    string    `json:"verificationId" format:"uuid"`
	ExpiresAt         time.Time `json:"expiresAt"`
	RetryAfterSeconds int       `json:"retryAfterSeconds"`
}
type userPathInput struct {
	UserID string `path:"userID" format:"uuid"`
}
type userListInput struct {
	Keyword  string `query:"keyword"`
	State    string `query:"state"`
	Page     int    `query:"page" minimum:"1"`
	PageSize int    `query:"pageSize" minimum:"1" maximum:"100"`
}
type userProfileBody struct {
	DisplayName string  `json:"displayName" minLength:"1"`
	AvatarURL   *string `json:"avatarUrl,omitempty"`
}
type userProfileInput struct {
	UserID string `path:"userID" format:"uuid"`
	Body   userProfileBody
}
type adminCreateBody struct {
	Username    string `json:"username" minLength:"1" maxLength:"64"`
	DisplayName string `json:"displayName,omitempty"`
	AvatarURL   string `json:"avatarUrl,omitempty"`
	Password    string `json:"password" minLength:"1"`
}
type adminCreateInput struct{ Body adminCreateBody }
type userStateBody struct {
	State string `json:"state"`
}
type userStateInput struct {
	UserID string `path:"userID" format:"uuid"`
	Body   userStateBody
}
type resetPasswordBody struct {
	NewPassword string `json:"newPassword" minLength:"1"`
}
type resetPasswordInput struct {
	UserID string `path:"userID" format:"uuid"`
	Body   resetPasswordBody
}
type noContent struct{}

func (e *Endpoint) registerAdmin(api huma.API) {
	admin := huma.NewGroup(api, e.config.AdminPrefix)
	admin.UseMiddleware(e.RequiredMiddleware(api))
	huma.Register(admin, huma.Operation{OperationID: "identity-admin-list-users", Method: http.MethodGet, Path: "/users", Tags: []string{"Identity Admin"}}, e.adminList)
	huma.Register(admin, huma.Operation{OperationID: "identity-admin-create-user", Method: http.MethodPost, Path: "/users", DefaultStatus: http.StatusCreated, Tags: []string{"Identity Admin"}}, e.adminCreate)
	huma.Register(admin, huma.Operation{OperationID: "identity-admin-get-user", Method: http.MethodGet, Path: "/users/{userID}", Tags: []string{"Identity Admin"}}, e.adminGet)
	huma.Register(admin, huma.Operation{OperationID: "identity-admin-update-user", Method: http.MethodPatch, Path: "/users/{userID}", Tags: []string{"Identity Admin"}}, e.adminUpdate)
	huma.Register(admin, huma.Operation{OperationID: "identity-admin-set-user-state", Method: http.MethodPatch, Path: "/users/{userID}/state", Tags: []string{"Identity Admin"}}, e.adminState)
	huma.Register(admin, huma.Operation{OperationID: "identity-admin-reset-password", Method: http.MethodPost, Path: "/users/{userID}/password/reset", Tags: []string{"Identity Admin"}}, e.adminResetPassword)
	huma.Register(admin, huma.Operation{OperationID: "identity-admin-delete-user", Method: http.MethodDelete, Path: "/users/{userID}", DefaultStatus: http.StatusNoContent, Tags: []string{"Identity Admin"}}, e.adminDelete)
}

func (e *Endpoint) adminList(ctx context.Context, input *userListInput) (*userListResponse, error) {
	if err := e.authorize(ctx, domain.ActionUserList); err != nil {
		return nil, mapError(err, false)
	}
	users, total, err := e.services.Users.Users(ctx, domain.UserFilter{Keyword: input.Keyword, State: domain.State(input.State), Page: input.Page, PageSize: input.PageSize})
	if err != nil {
		return nil, mapError(err, false)
	}
	items := make([]userView, len(users))
	for i := range users {
		items[i] = userViewFrom(&users[i])
	}
	page, size := normalizePage(input.Page, input.PageSize)
	return &userListResponse{Body: userListBody{Items: items, Total: total, Page: page, PageSize: size}}, nil
}

func (e *Endpoint) adminCreate(ctx context.Context, input *adminCreateInput) (*userResponse, error) {
	if err := e.authorize(ctx, domain.ActionUserCreate); err != nil {
		return nil, mapError(err, false)
	}
	b := input.Body
	u, err := e.services.Accounts.Register(ctx, domain.UserCreateInput{Username: b.Username, DisplayName: b.DisplayName, AvatarURL: b.AvatarURL}, b.Password)
	if err != nil {
		return nil, mapError(err, false)
	}
	return &userResponse{Body: userViewFrom(u)}, nil
}
func (e *Endpoint) adminGet(ctx context.Context, input *userPathInput) (*userResponse, error) {
	if err := e.authorize(ctx, domain.ActionUserRead); err != nil {
		return nil, mapError(err, false)
	}
	id, err := domain.ParseUserID(input.UserID)
	if err != nil {
		return nil, mapError(err, false)
	}
	u, err := e.services.Users.UserByID(ctx, id)
	if err != nil {
		return nil, mapError(err, false)
	}
	return &userResponse{Body: userViewFrom(u)}, nil
}
func (e *Endpoint) adminUpdate(ctx context.Context, input *userProfileInput) (*userResponse, error) {
	if err := e.authorize(ctx, domain.ActionUserUpdate); err != nil {
		return nil, mapError(err, false)
	}
	id, err := domain.ParseUserID(input.UserID)
	if err != nil {
		return nil, mapError(err, false)
	}
	u, err := e.services.Users.UpdateProfile(ctx, id, domain.UserUpdateProfileInput{DisplayName: input.Body.DisplayName, AvatarURL: input.Body.AvatarURL})
	if err != nil {
		return nil, mapError(err, false)
	}
	return &userResponse{Body: userViewFrom(u)}, nil
}
func (e *Endpoint) adminState(ctx context.Context, input *userStateInput) (*userResponse, error) {
	if err := e.authorize(ctx, domain.ActionUserUpdate); err != nil {
		return nil, mapError(err, false)
	}
	id, err := domain.ParseUserID(input.UserID)
	if err != nil {
		return nil, mapError(err, false)
	}
	if err := e.services.Users.SetState(ctx, []domain.UserID{id}, domain.State(input.Body.State)); err != nil {
		return nil, mapError(err, false)
	}
	u, err := e.services.Users.UserByID(ctx, id)
	if err != nil {
		return nil, mapError(err, false)
	}
	return &userResponse{Body: userViewFrom(u)}, nil
}
func (e *Endpoint) adminResetPassword(ctx context.Context, input *resetPasswordInput) (*basicResponse, error) {
	if err := e.authorize(ctx, domain.ActionUserResetPassword); err != nil {
		return nil, mapError(err, false)
	}
	id, err := domain.ParseUserID(input.UserID)
	if err != nil {
		return nil, mapError(err, false)
	}
	if err := e.services.Accounts.ResetPassword(ctx, id, input.Body.NewPassword); err != nil {
		return nil, mapError(err, false)
	}
	return &basicResponse{Body: operationView{OK: true}}, nil
}
func (e *Endpoint) adminDelete(ctx context.Context, input *userPathInput) (*noContent, error) {
	if err := e.authorize(ctx, domain.ActionUserDelete); err != nil {
		return nil, mapError(err, false)
	}
	id, err := domain.ParseUserID(input.UserID)
	if err != nil {
		return nil, mapError(err, false)
	}
	if err := e.services.Users.DeleteUsers(ctx, []domain.UserID{id}); err != nil {
		return nil, mapError(err, false)
	}
	return &noContent{}, nil
}

func (e *Endpoint) currentProfile(ctx context.Context, _ *struct{}) (*profileResponse, error) {
	principal, ok := domain.PrincipalFromContext(ctx)
	if !ok || !principal.Active() {
		return nil, huma.Error401Unauthorized("unauthorized")
	}
	user, err := e.services.Users.UserByID(ctx, principal.Subject)
	if err != nil {
		return nil, mapError(err, false)
	}
	return e.profileResponse(ctx, user)
}

func (e *Endpoint) updateCurrentProfile(ctx context.Context, input *profilePatchInput) (*profileResponse, error) {
	principal, ok := domain.PrincipalFromContext(ctx)
	if !ok || !principal.Active() {
		return nil, huma.Error401Unauthorized("unauthorized")
	}
	displayName := principal.User.DisplayName
	if input.Body.DisplayName != nil {
		displayName = *input.Body.DisplayName
	}
	user, err := e.services.Users.UpdateProfile(ctx, principal.Subject, domain.UserUpdateProfileInput{
		DisplayName: displayName,
		AvatarURL:   input.Body.AvatarURL,
	})
	if err != nil {
		return nil, mapError(err, false)
	}
	return e.profileResponse(ctx, user)
}

func (e *Endpoint) startContactVerification(ctx context.Context, input *contactVerificationStartInput) (*contactVerificationResponse, error) {
	principal, ok := domain.PrincipalFromContext(ctx)
	if !ok || !principal.Active() {
		return nil, huma.Error401Unauthorized("unauthorized")
	}
	if e.services.Contacts == nil {
		return nil, mapError(domain.ErrVerificationUnsupported, false)
	}
	if err := requestMetaErrorFromContext(ctx); err != nil {
		return nil, mapError(err, false)
	}
	record, err := e.services.Contacts.StartVerification(ctx, principal.Subject, domain.ContactKind(input.Kind), input.Body.Value, requestMetaFromContext(ctx))
	if err != nil {
		return nil, mapError(err, false)
	}
	return &contactVerificationResponse{Body: contactVerificationView{
		VerificationID:    record.ID.String(),
		ExpiresAt:         record.ExpiresAt,
		RetryAfterSeconds: int(e.services.Contacts.ResendInterval().Seconds()),
	}}, nil
}

func (e *Endpoint) confirmContactVerification(ctx context.Context, input *contactVerificationConfirmInput) (*profileResponse, error) {
	principal, ok := domain.PrincipalFromContext(ctx)
	if !ok || !principal.Active() {
		return nil, huma.Error401Unauthorized("unauthorized")
	}
	if e.services.Contacts == nil {
		return nil, mapError(domain.ErrVerificationUnsupported, false)
	}
	if err := requestMetaErrorFromContext(ctx); err != nil {
		return nil, mapError(err, false)
	}
	verificationID, err := domain.ParseContactVerificationID(input.Body.VerificationID)
	if err != nil {
		return nil, mapError(err, false)
	}
	_, err = e.services.Contacts.ConfirmVerification(ctx, principal.Subject, domain.ContactKind(input.Kind), verificationID, input.Body.Code, requestMetaFromContext(ctx))
	if err != nil {
		return nil, mapError(err, false)
	}
	user, err := e.services.Users.UserByID(ctx, principal.Subject)
	if err != nil {
		return nil, mapError(err, false)
	}
	return e.profileResponse(ctx, user)
}

func (e *Endpoint) unbindContact(ctx context.Context, input *contactKindPathInput) (*noContent, error) {
	principal, ok := domain.PrincipalFromContext(ctx)
	if !ok || !principal.Active() {
		return nil, huma.Error401Unauthorized("unauthorized")
	}
	if e.services.Contacts == nil {
		return nil, mapError(domain.ErrVerificationUnsupported, false)
	}
	if err := e.services.Contacts.Unbind(ctx, principal.Subject, domain.ContactKind(input.Kind)); err != nil {
		return nil, mapError(err, false)
	}
	return &noContent{}, nil
}

func (e *Endpoint) profileResponse(ctx context.Context, user *domain.User) (*profileResponse, error) {
	if user == nil || e.services.Contacts == nil {
		return nil, mapError(domain.ErrNotFound, false)
	}
	contacts, err := e.services.Contacts.ListUserContacts(ctx, user.ID)
	if err != nil {
		return nil, mapError(err, false)
	}
	return &profileResponse{Body: profileViewFrom(user, contacts)}, nil
}

func profileViewFrom(user *domain.User, contacts []domain.UserContact) profileView {
	view := profileView{
		ID: user.ID.String(), Username: user.Username, DisplayName: user.DisplayName,
		AvatarURL: user.AvatarURL,
	}
	for i := range contacts {
		contact := contacts[i]
		item := &contactView{MaskedValue: maskContact(contact.Kind, contact.Value), VerifiedAt: contact.VerifiedAt}
		switch contact.Kind {
		case domain.ContactKindPhone:
			view.Contacts.Phone = item
		case domain.ContactKindEmail:
			view.Contacts.Email = item
		}
	}
	return view
}

func maskContact(kind domain.ContactKind, value string) string {
	switch kind {
	case domain.ContactKindPhone:
		if len(value) <= 4 {
			return "****"
		}
		return value[:len(value)-4] + "****"
	case domain.ContactKindEmail:
		at := strings.IndexByte(value, '@')
		if at <= 0 {
			return "***"
		}
		return value[:1] + "***" + value[at:]
	default:
		return "***"
	}
}

func userViewFrom(u *domain.User) userView {
	if u == nil {
		return userView{}
	}
	return userView{ID: u.ID.String(), Username: u.Username, DisplayName: u.DisplayName, AvatarURL: u.AvatarURL, State: string(u.State), DisabledAt: u.DisabledAt, LastLoginAt: u.LastLoginAt, CreatedAt: u.CreatedAt, UpdatedAt: u.UpdatedAt}
}
func sessionViewFromPrincipal(p *domain.Principal) sessionView {
	if p == nil {
		return sessionView{}
	}
	return sessionView{Authenticated: true, User: userViewFrom(p.User), Roles: append([]string(nil), p.Claims.Roles...), Permissions: append([]string(nil), p.Claims.Permissions...), SessionID: p.SessionID.String(), AuthenticatedAt: p.AuthenticatedAt, ExpiresAt: p.ExpiresAt}
}
func normalizePage(page, size int) (int, int) {
	if page < 1 {
		page = 1
	}
	if size < 1 {
		size = 20
	}
	if size > 100 {
		size = 100
	}
	return page, size
}
