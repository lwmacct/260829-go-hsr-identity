package handler

import (
	"context"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/lwmacct/260829-go-hsr-identity/pkg/identity/domain"
)

type userView struct {
	ID          string     `json:"id" format:"uuid"`
	Username    string     `json:"username"`
	Phone       string     `json:"phone,omitempty"`
	DisplayName string     `json:"displayName"`
	Email       string     `json:"email,omitempty"`
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
	Phone       *string `json:"phone,omitempty"`
	Email       *string `json:"email,omitempty"`
	AvatarURL   *string `json:"avatarUrl,omitempty"`
}
type userProfileInput struct {
	UserID string `path:"userID" format:"uuid"`
	Body   userProfileBody
}
type adminCreateBody struct {
	Username    string `json:"username" minLength:"1" maxLength:"64"`
	Phone       string `json:"phone,omitempty" maxLength:"16"`
	DisplayName string `json:"displayName,omitempty"`
	Email       string `json:"email,omitempty" maxLength:"254"`
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
	u, err := e.services.Accounts.Register(ctx, domain.UserCreateInput{Username: b.Username, Phone: b.Phone, DisplayName: b.DisplayName, Email: b.Email, AvatarURL: b.AvatarURL}, b.Password)
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
	u, err := e.services.Users.UpdateProfile(ctx, id, domain.UserUpdateProfileInput{DisplayName: input.Body.DisplayName, Phone: input.Body.Phone, Email: input.Body.Email, AvatarURL: input.Body.AvatarURL})
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

func userViewFrom(u *domain.User) userView {
	if u == nil {
		return userView{}
	}
	return userView{ID: u.ID.String(), Username: u.Username, Phone: u.Phone, DisplayName: u.DisplayName, Email: u.Email, AvatarURL: u.AvatarURL, State: string(u.State), DisabledAt: u.DisabledAt, LastLoginAt: u.LastLoginAt, CreatedAt: u.CreatedAt, UpdatedAt: u.UpdatedAt}
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
