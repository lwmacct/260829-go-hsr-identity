package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"uuid"

	"github.com/lwmacct/260829-go-hsr-identity/pkg/identity/domain"
)

type AuthorizationService struct {
	repo         domain.AuthorizationRepository
	users        domain.UserDirectory
	tx           domain.TxManager
	now          domain.Clock
	defaultRoles []string
}

func NewAuthorizationService(repo domain.AuthorizationRepository, users domain.UserDirectory, tx domain.TxManager, now domain.Clock, defaultRoles []string) (*AuthorizationService, error) {
	if repo == nil {
		return nil, errors.New("identity: authorization repository is required")
	}
	if users == nil {
		return nil, errors.New("identity: authorization user directory is required")
	}
	if tx == nil {
		return nil, errors.New("identity: authorization transaction manager is required")
	}
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	roles := make([]string, 0, len(defaultRoles))
	seen := make(map[string]struct{}, len(defaultRoles))
	for _, code := range defaultRoles {
		code, err := normalizeCode(code, "role")
		if err != nil {
			return nil, err
		}
		if _, ok := seen[code]; ok {
			continue
		}
		seen[code] = struct{}{}
		roles = append(roles, code)
	}
	return &AuthorizationService{repo: repo, users: users, tx: tx, now: now, defaultRoles: roles}, nil
}

func (s *AuthorizationService) Claims(ctx context.Context, user *domain.User) (domain.Claims, error) {
	if s == nil || s.repo == nil || user == nil {
		return domain.Claims{}, nil
	}
	return s.repo.ListUserClaims(ctx, user.ID)
}

func (s *AuthorizationService) Authorize(_ context.Context, principal *domain.Principal, permission string) error {
	if principal == nil || !principal.Active() {
		return domain.ErrUnauthenticated
	}
	if !HasPermission(principal, permission) {
		return domain.ErrForbidden
	}
	return nil
}

func HasPermission(principal *domain.Principal, permission string) bool {
	permission = strings.TrimSpace(permission)
	if principal == nil || permission == "" {
		return false
	}
	for _, granted := range principal.Claims.Permissions {
		if granted == permission {
			return true
		}
	}
	return false
}

func (s *AuthorizationService) CreateRole(ctx context.Context, input domain.RoleInput) (*domain.Role, error) {
	normalized, err := normalizeRoleInput(input)
	if err != nil {
		return nil, err
	}
	now := s.now().UTC()
	return s.repo.CreateRole(ctx, domain.Role{ID: domain.RoleID(uuid.NewV7().String()), Code: normalized.Code, Name: normalized.Name, Description: normalized.Description, System: normalized.System, CreatedAt: now, UpdatedAt: now})
}

func (s *AuthorizationService) EnsureRole(ctx context.Context, input domain.RoleInput) (*domain.Role, error) {
	normalized, err := normalizeRoleInput(input)
	if err != nil {
		return nil, err
	}
	role, err := s.repo.GetRoleByCode(ctx, normalized.Code)
	if err == nil {
		if role.Name != normalized.Name || role.Description != normalized.Description || role.System != normalized.System {
			return s.repo.UpdateRole(ctx, role.ID, normalized, s.now().UTC())
		}
		return role, nil
	}
	if !errors.Is(err, domain.ErrNotFound) {
		return nil, err
	}
	return s.CreateRole(ctx, normalized)
}

func (s *AuthorizationService) ListRoles(ctx context.Context, filter domain.RoleFilter) ([]domain.Role, int, error) {
	return s.repo.ListRoles(ctx, filter)
}

func (s *AuthorizationService) RoleByID(ctx context.Context, id domain.RoleID) (*domain.Role, error) {
	id, err := domain.NormalizeRoleID(id)
	if err != nil {
		return nil, err
	}
	return s.repo.GetRole(ctx, id)
}

func (s *AuthorizationService) RoleByCode(ctx context.Context, code string) (*domain.Role, error) {
	code, err := normalizeCode(code, "role")
	if err != nil {
		return nil, err
	}
	return s.repo.GetRoleByCode(ctx, code)
}

func (s *AuthorizationService) UpdateRole(ctx context.Context, id domain.RoleID, input domain.RoleInput) (*domain.Role, error) {
	id, err := domain.NormalizeRoleID(id)
	if err != nil {
		return nil, err
	}
	normalized, err := normalizeRoleInput(input)
	if err != nil {
		return nil, err
	}
	return s.repo.UpdateRole(ctx, id, normalized, s.now().UTC())
}

func (s *AuthorizationService) DeleteRole(ctx context.Context, id domain.RoleID) error {
	id, err := domain.NormalizeRoleID(id)
	if err != nil {
		return err
	}
	return s.repo.DeleteRole(ctx, id)
}

func (s *AuthorizationService) CreatePermission(ctx context.Context, input domain.PermissionInput) (*domain.Permission, error) {
	normalized, err := normalizePermissionInput(input)
	if err != nil {
		return nil, err
	}
	now := s.now().UTC()
	return s.repo.CreatePermission(ctx, domain.Permission{ID: domain.PermissionID(uuid.NewV7().String()), Code: normalized.Code, Name: normalized.Name, Description: normalized.Description, System: normalized.System, CreatedAt: now, UpdatedAt: now})
}

func (s *AuthorizationService) EnsurePermission(ctx context.Context, input domain.PermissionInput) (*domain.Permission, error) {
	normalized, err := normalizePermissionInput(input)
	if err != nil {
		return nil, err
	}
	permission, err := s.repo.GetPermissionByCode(ctx, normalized.Code)
	if err == nil {
		if permission.Name != normalized.Name || permission.Description != normalized.Description || permission.System != normalized.System {
			return s.repo.UpdatePermission(ctx, permission.ID, normalized, s.now().UTC())
		}
		return permission, nil
	}
	if !errors.Is(err, domain.ErrNotFound) {
		return nil, err
	}
	return s.CreatePermission(ctx, normalized)
}

func (s *AuthorizationService) ListPermissions(ctx context.Context, filter domain.PermissionFilter) ([]domain.Permission, int, error) {
	return s.repo.ListPermissions(ctx, filter)
}

func (s *AuthorizationService) PermissionByID(ctx context.Context, id domain.PermissionID) (*domain.Permission, error) {
	id, err := domain.NormalizePermissionID(id)
	if err != nil {
		return nil, err
	}
	return s.repo.GetPermission(ctx, id)
}

func (s *AuthorizationService) PermissionByCode(ctx context.Context, code string) (*domain.Permission, error) {
	code, err := normalizeCode(code, "permission")
	if err != nil {
		return nil, err
	}
	return s.repo.GetPermissionByCode(ctx, code)
}

func (s *AuthorizationService) UpdatePermission(ctx context.Context, id domain.PermissionID, input domain.PermissionInput) (*domain.Permission, error) {
	id, err := domain.NormalizePermissionID(id)
	if err != nil {
		return nil, err
	}
	normalized, err := normalizePermissionInput(input)
	if err != nil {
		return nil, err
	}
	return s.repo.UpdatePermission(ctx, id, normalized, s.now().UTC())
}

func (s *AuthorizationService) DeletePermission(ctx context.Context, id domain.PermissionID) error {
	id, err := domain.NormalizePermissionID(id)
	if err != nil {
		return err
	}
	return s.repo.DeletePermission(ctx, id)
}

func (s *AuthorizationService) UserRoles(ctx context.Context, userID domain.UserID) ([]domain.Role, error) {
	userID, err := domain.NormalizeUserID(userID)
	if err != nil {
		return nil, err
	}
	return s.repo.ListUserRoles(ctx, userID)
}

func (s *AuthorizationService) SetUserRoles(ctx context.Context, userID domain.UserID, roleCodes []string) error {
	userID, err := domain.NormalizeUserID(userID)
	if err != nil {
		return err
	}
	return s.tx.WithinTx(ctx, func(c context.Context, uow domain.UnitOfWork) error {
		return s.replaceUserRoles(c, uow, userID, roleCodes)
	})
}

func (s *AuthorizationService) RolePermissions(ctx context.Context, roleID domain.RoleID) ([]domain.Permission, error) {
	roleID, err := domain.NormalizeRoleID(roleID)
	if err != nil {
		return nil, err
	}
	return s.repo.ListRolePermissions(ctx, roleID)
}

func (s *AuthorizationService) SetRolePermissions(ctx context.Context, roleID domain.RoleID, permissionCodes []string) error {
	roleID, err := domain.NormalizeRoleID(roleID)
	if err != nil {
		return err
	}
	return s.tx.WithinTx(ctx, func(c context.Context, uow domain.UnitOfWork) error {
		return s.replaceRolePermissions(c, uow, roleID, permissionCodes)
	})
}

func (s *AuthorizationService) assignDefaultRoles(ctx context.Context, uow domain.UnitOfWork, userID domain.UserID) error {
	if len(s.defaultRoles) == 0 {
		return nil
	}
	return s.replaceUserRoles(ctx, uow, userID, s.defaultRoles)
}

func (s *AuthorizationService) replaceUserRoles(ctx context.Context, uow domain.UnitOfWork, userID domain.UserID, roleCodes []string) error {
	if _, err := uow.Users().GetUser(ctx, userID); err != nil {
		return err
	}
	ids := make([]domain.RoleID, 0, len(roleCodes))
	seen := make(map[domain.RoleID]struct{}, len(roleCodes))
	for _, code := range roleCodes {
		code, err := normalizeCode(code, "role")
		if err != nil {
			return err
		}
		role, err := uow.Authorization().GetRoleByCode(ctx, code)
		if err != nil {
			return err
		}
		if _, ok := seen[role.ID]; ok {
			continue
		}
		seen[role.ID] = struct{}{}
		ids = append(ids, role.ID)
	}
	return uow.Authorization().ReplaceUserRoles(ctx, userID, ids)
}

func (s *AuthorizationService) replaceRolePermissions(ctx context.Context, uow domain.UnitOfWork, roleID domain.RoleID, permissionCodes []string) error {
	if _, err := uow.Authorization().GetRole(ctx, roleID); err != nil {
		return err
	}
	ids := make([]domain.PermissionID, 0, len(permissionCodes))
	seen := make(map[domain.PermissionID]struct{}, len(permissionCodes))
	for _, code := range permissionCodes {
		code, err := normalizeCode(code, "permission")
		if err != nil {
			return err
		}
		permission, err := uow.Authorization().GetPermissionByCode(ctx, code)
		if err != nil {
			return err
		}
		if _, ok := seen[permission.ID]; ok {
			continue
		}
		seen[permission.ID] = struct{}{}
		ids = append(ids, permission.ID)
	}
	return uow.Authorization().ReplaceRolePermissions(ctx, roleID, ids)
}

func normalizeRoleInput(input domain.RoleInput) (domain.RoleInput, error) {
	code, err := normalizeCode(input.Code, "role")
	if err != nil {
		return domain.RoleInput{}, err
	}
	name := strings.TrimSpace(input.Name)
	if name == "" {
		name = code
	}
	if len(name) > 256 || len(input.Description) > 4096 {
		return domain.RoleInput{}, fmt.Errorf("%w: role metadata is too long", domain.ErrInvalid)
	}
	return domain.RoleInput{Code: code, Name: name, Description: strings.TrimSpace(input.Description), System: input.System}, nil
}

func normalizePermissionInput(input domain.PermissionInput) (domain.PermissionInput, error) {
	code, err := normalizeCode(input.Code, "permission")
	if err != nil {
		return domain.PermissionInput{}, err
	}
	name := strings.TrimSpace(input.Name)
	if name == "" {
		name = code
	}
	if len(name) > 256 || len(input.Description) > 4096 {
		return domain.PermissionInput{}, fmt.Errorf("%w: permission metadata is too long", domain.ErrInvalid)
	}
	return domain.PermissionInput{Code: code, Name: name, Description: strings.TrimSpace(input.Description), System: input.System}, nil
}

func normalizeCode(value, kind string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" || len(value) > 128 {
		return "", fmt.Errorf("%w: invalid %s code", domain.ErrInvalid, kind)
	}
	for i, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-' || r == ':' {
			if i == 0 && (r == '.' || r == '_' || r == '-' || r == ':') {
				return "", fmt.Errorf("%w: invalid %s code", domain.ErrInvalid, kind)
			}
			continue
		}
		return "", fmt.Errorf("%w: invalid %s code", domain.ErrInvalid, kind)
	}
	return value, nil
}
