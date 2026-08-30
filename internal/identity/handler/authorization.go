package handler

import (
	"context"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"github.com/lwmacct/260829-go-hsr-identity/pkg/identity/domain"
)

type roleView struct {
	ID          string    `json:"id" format:"uuid"`
	Code        string    `json:"code"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	System      bool      `json:"system"`
	CreatedAt   timeValue `json:"createdAt"`
	UpdatedAt   timeValue `json:"updatedAt"`
}

type permissionView struct {
	ID          string    `json:"id" format:"uuid"`
	Code        string    `json:"code"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	System      bool      `json:"system"`
	CreatedAt   timeValue `json:"createdAt"`
	UpdatedAt   timeValue `json:"updatedAt"`
}

type roleListBody struct {
	Items    []roleView `json:"items"`
	Total    int        `json:"total"`
	Page     int        `json:"page"`
	PageSize int        `json:"pageSize"`
}
type permissionListBody struct {
	Items    []permissionView `json:"items"`
	Total    int              `json:"total"`
	Page     int              `json:"page"`
	PageSize int              `json:"pageSize"`
}
type roleListResponse struct{ Body roleListBody }
type permissionListResponse struct{ Body permissionListBody }
type roleResponse struct{ Body roleView }
type permissionResponse struct{ Body permissionView }

type roleListInput struct {
	Keyword  string `query:"keyword"`
	Page     int    `query:"page" minimum:"1"`
	PageSize int    `query:"pageSize" minimum:"1" maximum:"100"`
}
type permissionListInput struct {
	Keyword  string `query:"keyword"`
	Page     int    `query:"page" minimum:"1"`
	PageSize int    `query:"pageSize" minimum:"1" maximum:"100"`
}
type rolePathInput struct {
	RoleID string `path:"roleID" format:"uuid"`
}
type permissionPathInput struct {
	PermissionID string `path:"permissionID" format:"uuid"`
}
type roleBody struct {
	Code        string `json:"code" minLength:"1"`
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
	System      bool   `json:"system,omitempty"`
}
type permissionBody struct {
	Code        string `json:"code" minLength:"1"`
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
	System      bool   `json:"system,omitempty"`
}
type roleInput struct {
	RoleID string `path:"roleID" format:"uuid"`
	Body   roleBody
}
type permissionInput struct {
	PermissionID string `path:"permissionID" format:"uuid"`
	Body         permissionBody
}
type userRolesInput struct {
	UserID string `path:"userID" format:"uuid"`
	Body   roleCodesBody
}
type rolePermissionsInput struct {
	RoleID string `path:"roleID" format:"uuid"`
	Body   permissionCodesBody
}
type roleCodesBody struct {
	RoleCodes []string `json:"roleCodes"`
}
type permissionCodesBody struct {
	PermissionCodes []string `json:"permissionCodes"`
}
type userRoleListResponse struct {
	Body struct {
		Items []roleView `json:"items"`
	}
}
type rolePermissionListResponse struct {
	Body struct {
		Items []permissionView `json:"items"`
	}
}
type roleAssignmentInput struct {
	UserID string `path:"userID" format:"uuid"`
}
type rolePermissionAssignmentInput struct {
	RoleID string `path:"roleID" format:"uuid"`
}

func (e *Endpoint) registerAuthorization(api huma.API) {
	admin := huma.NewGroup(api, e.config.AdminPrefix)
	admin.UseMiddleware(e.RequiredMiddleware(api))

	huma.Register(admin, huma.Operation{OperationID: "identity-list-roles", Method: http.MethodGet, Path: "/roles", Tags: []string{"Identity Authorization"}}, e.listRoles)
	huma.Register(admin, huma.Operation{OperationID: "identity-create-role", Method: http.MethodPost, Path: "/roles", DefaultStatus: http.StatusCreated, Tags: []string{"Identity Authorization"}}, e.createRole)
	huma.Register(admin, huma.Operation{OperationID: "identity-update-role", Method: http.MethodPatch, Path: "/roles/{roleID}", Tags: []string{"Identity Authorization"}}, e.updateRole)
	huma.Register(admin, huma.Operation{OperationID: "identity-delete-role", Method: http.MethodDelete, Path: "/roles/{roleID}", DefaultStatus: http.StatusNoContent, Tags: []string{"Identity Authorization"}}, e.deleteRole)
	huma.Register(admin, huma.Operation{OperationID: "identity-list-permissions", Method: http.MethodGet, Path: "/permissions", Tags: []string{"Identity Authorization"}}, e.listPermissions)
	huma.Register(admin, huma.Operation{OperationID: "identity-create-permission", Method: http.MethodPost, Path: "/permissions", DefaultStatus: http.StatusCreated, Tags: []string{"Identity Authorization"}}, e.createPermission)
	huma.Register(admin, huma.Operation{OperationID: "identity-update-permission", Method: http.MethodPatch, Path: "/permissions/{permissionID}", Tags: []string{"Identity Authorization"}}, e.updatePermission)
	huma.Register(admin, huma.Operation{OperationID: "identity-delete-permission", Method: http.MethodDelete, Path: "/permissions/{permissionID}", DefaultStatus: http.StatusNoContent, Tags: []string{"Identity Authorization"}}, e.deletePermission)
	huma.Register(admin, huma.Operation{OperationID: "identity-list-user-roles", Method: http.MethodGet, Path: "/users/{userID}/roles", Tags: []string{"Identity Authorization"}}, e.listUserRoles)
	huma.Register(admin, huma.Operation{OperationID: "identity-set-user-roles", Method: http.MethodPut, Path: "/users/{userID}/roles", Tags: []string{"Identity Authorization"}}, e.setUserRoles)
	huma.Register(admin, huma.Operation{OperationID: "identity-list-role-permissions", Method: http.MethodGet, Path: "/roles/{roleID}/permissions", Tags: []string{"Identity Authorization"}}, e.listRolePermissions)
	huma.Register(admin, huma.Operation{OperationID: "identity-set-role-permissions", Method: http.MethodPut, Path: "/roles/{roleID}/permissions", Tags: []string{"Identity Authorization"}}, e.setRolePermissions)
}

func (e *Endpoint) listRoles(ctx context.Context, input *roleListInput) (*roleListResponse, error) {
	if err := e.authorize(ctx, domain.ActionRoleList); err != nil {
		return nil, mapError(err, false)
	}
	if e.services.Authorization == nil {
		return nil, huma.Error500InternalServerError("authorization unavailable")
	}
	items, total, err := e.services.Authorization.ListRoles(ctx, domain.RoleFilter{Keyword: input.Keyword, Page: input.Page, PageSize: input.PageSize})
	if err != nil {
		return nil, mapError(err, false)
	}
	page, size := normalizePage(input.Page, input.PageSize)
	out := roleListResponse{Body: roleListBody{Items: make([]roleView, len(items)), Total: total, Page: page, PageSize: size}}
	for i := range items {
		out.Body.Items[i] = roleViewFrom(&items[i])
	}
	return &out, nil
}

func (e *Endpoint) createRole(ctx context.Context, input *struct{ Body roleBody }) (*roleResponse, error) {
	if err := e.authorize(ctx, domain.ActionRoleCreate); err != nil {
		return nil, mapError(err, false)
	}
	role, err := e.services.Authorization.CreateRole(ctx, domain.RoleInput{Code: input.Body.Code, Name: input.Body.Name, Description: input.Body.Description, System: input.Body.System})
	if err != nil {
		return nil, mapError(err, false)
	}
	return &roleResponse{Body: roleViewFrom(role)}, nil
}

func (e *Endpoint) updateRole(ctx context.Context, input *roleInput) (*roleResponse, error) {
	if err := e.authorize(ctx, domain.ActionRoleUpdate); err != nil {
		return nil, mapError(err, false)
	}
	id, err := parseUUID7(input.RoleID)
	if err != nil {
		return nil, mapError(err, false)
	}
	role, err := e.services.Authorization.UpdateRole(ctx, id, domain.RoleInput{Code: input.Body.Code, Name: input.Body.Name, Description: input.Body.Description})
	if err != nil {
		return nil, mapError(err, false)
	}
	return &roleResponse{Body: roleViewFrom(role)}, nil
}

func (e *Endpoint) deleteRole(ctx context.Context, input *rolePathInput) (*struct{}, error) {
	if err := e.authorize(ctx, domain.ActionRoleDelete); err != nil {
		return nil, mapError(err, false)
	}
	id, err := parseUUID7(input.RoleID)
	if err != nil {
		return nil, mapError(err, false)
	}
	if err := e.services.Authorization.DeleteRole(ctx, id); err != nil {
		return nil, mapError(err, false)
	}
	return &struct{}{}, nil
}

func (e *Endpoint) listPermissions(ctx context.Context, input *permissionListInput) (*permissionListResponse, error) {
	if err := e.authorize(ctx, domain.ActionPermissionList); err != nil {
		return nil, mapError(err, false)
	}
	items, total, err := e.services.Authorization.ListPermissions(ctx, domain.PermissionFilter{Keyword: input.Keyword, Page: input.Page, PageSize: input.PageSize})
	if err != nil {
		return nil, mapError(err, false)
	}
	page, size := normalizePage(input.Page, input.PageSize)
	out := permissionListResponse{Body: permissionListBody{Items: make([]permissionView, len(items)), Total: total, Page: page, PageSize: size}}
	for i := range items {
		out.Body.Items[i] = permissionViewFrom(&items[i])
	}
	return &out, nil
}

func (e *Endpoint) createPermission(ctx context.Context, input *struct{ Body permissionBody }) (*permissionResponse, error) {
	if err := e.authorize(ctx, domain.ActionPermissionCreate); err != nil {
		return nil, mapError(err, false)
	}
	permission, err := e.services.Authorization.CreatePermission(ctx, domain.PermissionInput{Code: input.Body.Code, Name: input.Body.Name, Description: input.Body.Description, System: input.Body.System})
	if err != nil {
		return nil, mapError(err, false)
	}
	return &permissionResponse{Body: permissionViewFrom(permission)}, nil
}

func (e *Endpoint) updatePermission(ctx context.Context, input *permissionInput) (*permissionResponse, error) {
	if err := e.authorize(ctx, domain.ActionPermissionUpdate); err != nil {
		return nil, mapError(err, false)
	}
	id, err := parseUUID7(input.PermissionID)
	if err != nil {
		return nil, mapError(err, false)
	}
	permission, err := e.services.Authorization.UpdatePermission(ctx, id, domain.PermissionInput{Code: input.Body.Code, Name: input.Body.Name, Description: input.Body.Description})
	if err != nil {
		return nil, mapError(err, false)
	}
	return &permissionResponse{Body: permissionViewFrom(permission)}, nil
}

func (e *Endpoint) deletePermission(ctx context.Context, input *permissionPathInput) (*struct{}, error) {
	if err := e.authorize(ctx, domain.ActionPermissionDelete); err != nil {
		return nil, mapError(err, false)
	}
	id, err := parseUUID7(input.PermissionID)
	if err != nil {
		return nil, mapError(err, false)
	}
	if err := e.services.Authorization.DeletePermission(ctx, id); err != nil {
		return nil, mapError(err, false)
	}
	return &struct{}{}, nil
}

func (e *Endpoint) listUserRoles(ctx context.Context, input *roleAssignmentInput) (*userRoleListResponse, error) {
	if err := e.authorize(ctx, domain.ActionUserRoleManage); err != nil {
		return nil, mapError(err, false)
	}
	id, err := parseUUID7(input.UserID)
	if err != nil {
		return nil, mapError(err, false)
	}
	roles, err := e.services.Authorization.UserRoles(ctx, id)
	if err != nil {
		return nil, mapError(err, false)
	}
	out := &userRoleListResponse{}
	out.Body.Items = make([]roleView, len(roles))
	for i := range roles {
		out.Body.Items[i] = roleViewFrom(&roles[i])
	}
	return out, nil
}

func (e *Endpoint) setUserRoles(ctx context.Context, input *userRolesInput) (*struct{ Body operationView }, error) {
	if err := e.authorize(ctx, domain.ActionUserRoleManage); err != nil {
		return nil, mapError(err, false)
	}
	id, err := parseUUID7(input.UserID)
	if err != nil {
		return nil, mapError(err, false)
	}
	if err := e.services.Authorization.SetUserRoles(ctx, id, input.Body.RoleCodes); err != nil {
		return nil, mapError(err, false)
	}
	return &struct{ Body operationView }{Body: operationView{OK: true}}, nil
}

func (e *Endpoint) listRolePermissions(ctx context.Context, input *rolePermissionAssignmentInput) (*rolePermissionListResponse, error) {
	if err := e.authorize(ctx, domain.ActionRolePermissionManage); err != nil {
		return nil, mapError(err, false)
	}
	id, err := parseUUID7(input.RoleID)
	if err != nil {
		return nil, mapError(err, false)
	}
	permissions, err := e.services.Authorization.RolePermissions(ctx, id)
	if err != nil {
		return nil, mapError(err, false)
	}
	out := &rolePermissionListResponse{}
	out.Body.Items = make([]permissionView, len(permissions))
	for i := range permissions {
		out.Body.Items[i] = permissionViewFrom(&permissions[i])
	}
	return out, nil
}

func (e *Endpoint) setRolePermissions(ctx context.Context, input *rolePermissionsInput) (*struct{ Body operationView }, error) {
	if err := e.authorize(ctx, domain.ActionRolePermissionManage); err != nil {
		return nil, mapError(err, false)
	}
	id, err := parseUUID7(input.RoleID)
	if err != nil {
		return nil, mapError(err, false)
	}
	if err := e.services.Authorization.SetRolePermissions(ctx, id, input.Body.PermissionCodes); err != nil {
		return nil, mapError(err, false)
	}
	return &struct{ Body operationView }{Body: operationView{OK: true}}, nil
}

func roleViewFrom(role *domain.Role) roleView {
	if role == nil {
		return roleView{}
	}
	return roleView{ID: role.ID.String(), Code: role.Code, Name: role.Name, Description: role.Description, System: role.System, CreatedAt: role.CreatedAt, UpdatedAt: role.UpdatedAt}
}

func permissionViewFrom(permission *domain.Permission) permissionView {
	if permission == nil {
		return permissionView{}
	}
	return permissionView{ID: permission.ID.String(), Code: permission.Code, Name: permission.Name, Description: permission.Description, System: permission.System, CreatedAt: permission.CreatedAt, UpdatedAt: permission.UpdatedAt}
}
