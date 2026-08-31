package repository

import (
	"context"
	"sort"
	"strings"
	"time"
	"uuid"

	"github.com/lwmacct/260829-go-hsr-identity/pkg/identity/domain"
	"github.com/uptrace/bun"
)

func (s *Store) ListRoles(ctx context.Context, filter domain.RoleFilter) ([]domain.Role, int, error) {
	page, size := normalizePage(filter.Page, filter.PageSize)
	count := s.db.NewSelect().Model((*RoleModel)(nil))
	count = applyRoleFilter(count, filter.Keyword)
	var total int
	if err := count.ColumnExpr("count(*)").Scan(ctx, &total); err != nil {
		return nil, 0, err
	}
	rows := make([]RoleModel, 0, size)
	q := s.db.NewSelect().Model(&rows)
	q = applyRoleFilter(q, filter.Keyword)
	if err := q.OrderExpr("r.created_at DESC, r.id DESC").Limit(size).Offset((page - 1) * size).Scan(ctx); err != nil {
		return nil, 0, err
	}
	out := make([]domain.Role, len(rows))
	for i := range rows {
		out[i] = roleFrom(&rows[i])
	}
	return out, total, nil
}

func applyRoleFilter(q *bun.SelectQuery, keyword string) *bun.SelectQuery {
	if keyword = strings.TrimSpace(keyword); keyword != "" {
		like := "%" + keyword + "%"
		q = q.Where("(r.code LIKE ? OR r.name LIKE ? OR r.description LIKE ?)", like, like, like)
	}
	return q
}

func (s *Store) GetRole(ctx context.Context, id domain.RoleID) (*domain.Role, error) {
	m := new(RoleModel)
	if err := s.db.NewSelect().Model(m).Where("r.id = ?", id.String()).Scan(ctx); err != nil {
		return nil, mapReadError(err)
	}
	r := roleFrom(m)
	return &r, nil
}

func (s *Store) GetRoleByCode(ctx context.Context, code string) (*domain.Role, error) {
	m := new(RoleModel)
	if err := s.db.NewSelect().Model(m).Where("r.code = ?", strings.TrimSpace(code)).Scan(ctx); err != nil {
		return nil, mapReadError(err)
	}
	r := roleFrom(m)
	return &r, nil
}

func (s *Store) CreateRole(ctx context.Context, in domain.Role) (*domain.Role, error) {
	m := &RoleModel{ID: in.ID.String(), Code: in.Code, Name: in.Name, Description: in.Description, System: in.System, CreatedAt: in.CreatedAt, UpdatedAt: in.UpdatedAt}
	if _, err := s.db.NewInsert().Model(m).Exec(ctx); err != nil {
		return nil, mapWriteError(err, false)
	}
	r := roleFrom(m)
	return &r, nil
}

func (s *Store) UpsertRole(ctx context.Context, in domain.Role) (*domain.Role, error) {
	m := &RoleModel{ID: in.ID.String(), Code: in.Code, Name: in.Name, Description: in.Description, System: in.System, CreatedAt: in.CreatedAt, UpdatedAt: in.UpdatedAt}
	if _, err := s.db.NewInsert().Model(m).On("CONFLICT (code) DO UPDATE").Set("name = EXCLUDED.name").Set("description = EXCLUDED.description").Set("system = EXCLUDED.system").Set("updated_at = EXCLUDED.updated_at").Exec(ctx); err != nil {
		return nil, mapWriteError(err, false)
	}
	return s.GetRoleByCode(ctx, in.Code)
}

func (s *Store) UpdateRole(ctx context.Context, id domain.RoleID, in domain.RoleInput, now time.Time) (*domain.Role, error) {
	res, err := s.db.NewUpdate().Model((*RoleModel)(nil)).
		Set("code = ?", in.Code).
		Set("name = ?", in.Name).
		Set("description = ?", in.Description).
		Set("updated_at = ?", now).
		Where("id = ?", id.String()).Exec(ctx)
	if err != nil {
		return nil, mapWriteError(err, false)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return nil, domain.ErrNotFound
	}
	return s.GetRole(ctx, id)
}

func (s *Store) DeleteRole(ctx context.Context, id domain.RoleID) error {
	var system bool
	if err := s.db.NewSelect().Model((*RoleModel)(nil)).Column("system").Where("id = ?", id.String()).Scan(ctx, &system); err != nil {
		return mapReadError(err)
	}
	if system {
		return domain.ErrConflict
	}
	if _, err := s.db.NewDelete().Model((*RolePermissionModel)(nil)).Where("role_id = ?", id.String()).Exec(ctx); err != nil {
		return err
	}
	if _, err := s.db.NewDelete().Model((*UserRoleModel)(nil)).Where("role_id = ?", id.String()).Exec(ctx); err != nil {
		return err
	}
	res, err := s.db.NewDelete().Model((*RoleModel)(nil)).Where("id = ?", id.String()).Exec(ctx)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return domain.ErrNotFound
	}
	return nil
}

func (s *Store) ListPermissions(ctx context.Context, filter domain.PermissionFilter) ([]domain.Permission, int, error) {
	page, size := normalizePage(filter.Page, filter.PageSize)
	count := s.db.NewSelect().Model((*PermissionModel)(nil))
	count = applyPermissionFilter(count, filter.Keyword)
	var total int
	if err := count.ColumnExpr("count(*)").Scan(ctx, &total); err != nil {
		return nil, 0, err
	}
	rows := make([]PermissionModel, 0, size)
	q := s.db.NewSelect().Model(&rows)
	q = applyPermissionFilter(q, filter.Keyword)
	if err := q.OrderExpr("p.created_at DESC, p.id DESC").Limit(size).Offset((page - 1) * size).Scan(ctx); err != nil {
		return nil, 0, err
	}
	out := make([]domain.Permission, len(rows))
	for i := range rows {
		out[i] = permissionFrom(&rows[i])
	}
	return out, total, nil
}

func applyPermissionFilter(q *bun.SelectQuery, keyword string) *bun.SelectQuery {
	if keyword = strings.TrimSpace(keyword); keyword != "" {
		like := "%" + keyword + "%"
		q = q.Where("(p.code LIKE ? OR p.name LIKE ? OR p.description LIKE ?)", like, like, like)
	}
	return q
}

func (s *Store) GetPermission(ctx context.Context, id domain.PermissionID) (*domain.Permission, error) {
	m := new(PermissionModel)
	if err := s.db.NewSelect().Model(m).Where("p.id = ?", id.String()).Scan(ctx); err != nil {
		return nil, mapReadError(err)
	}
	p := permissionFrom(m)
	return &p, nil
}

func (s *Store) GetPermissionByCode(ctx context.Context, code string) (*domain.Permission, error) {
	m := new(PermissionModel)
	if err := s.db.NewSelect().Model(m).Where("p.code = ?", strings.TrimSpace(code)).Scan(ctx); err != nil {
		return nil, mapReadError(err)
	}
	p := permissionFrom(m)
	return &p, nil
}

func (s *Store) CreatePermission(ctx context.Context, in domain.Permission) (*domain.Permission, error) {
	m := &PermissionModel{ID: in.ID.String(), Code: in.Code, Name: in.Name, Description: in.Description, System: in.System, CreatedAt: in.CreatedAt, UpdatedAt: in.UpdatedAt}
	if _, err := s.db.NewInsert().Model(m).Exec(ctx); err != nil {
		return nil, mapWriteError(err, false)
	}
	p := permissionFrom(m)
	return &p, nil
}

func (s *Store) UpsertPermission(ctx context.Context, in domain.Permission) (*domain.Permission, error) {
	m := &PermissionModel{ID: in.ID.String(), Code: in.Code, Name: in.Name, Description: in.Description, System: in.System, CreatedAt: in.CreatedAt, UpdatedAt: in.UpdatedAt}
	if _, err := s.db.NewInsert().Model(m).On("CONFLICT (code) DO UPDATE").Set("name = EXCLUDED.name").Set("description = EXCLUDED.description").Set("system = EXCLUDED.system").Set("updated_at = EXCLUDED.updated_at").Exec(ctx); err != nil {
		return nil, mapWriteError(err, false)
	}
	return s.GetPermissionByCode(ctx, in.Code)
}

func (s *Store) UpdatePermission(ctx context.Context, id domain.PermissionID, in domain.PermissionInput, now time.Time) (*domain.Permission, error) {
	res, err := s.db.NewUpdate().Model((*PermissionModel)(nil)).
		Set("code = ?", in.Code).
		Set("name = ?", in.Name).
		Set("description = ?", in.Description).
		Set("updated_at = ?", now).
		Where("id = ?", id.String()).Exec(ctx)
	if err != nil {
		return nil, mapWriteError(err, false)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return nil, domain.ErrNotFound
	}
	return s.GetPermission(ctx, id)
}

func (s *Store) DeletePermission(ctx context.Context, id domain.PermissionID) error {
	var system bool
	if err := s.db.NewSelect().Model((*PermissionModel)(nil)).Column("system").Where("id = ?", id.String()).Scan(ctx, &system); err != nil {
		return mapReadError(err)
	}
	if system {
		return domain.ErrConflict
	}
	if _, err := s.db.NewDelete().Model((*RolePermissionModel)(nil)).Where("permission_id = ?", id.String()).Exec(ctx); err != nil {
		return err
	}
	res, err := s.db.NewDelete().Model((*PermissionModel)(nil)).Where("id = ?", id.String()).Exec(ctx)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return domain.ErrNotFound
	}
	return nil
}

func (s *Store) ListUserRoles(ctx context.Context, userID domain.UserID) ([]domain.Role, error) {
	rows := make([]RoleModel, 0)
	err := s.db.NewSelect().Model(&rows).
		Join("JOIN identity_user_roles AS ur ON ur.role_id = r.id").
		Where("ur.user_id = ?", userID.String()).
		OrderExpr("r.code ASC").Scan(ctx)
	if err != nil {
		return nil, mapReadError(err)
	}
	out := make([]domain.Role, len(rows))
	for i := range rows {
		out[i] = roleFrom(&rows[i])
	}
	return out, nil
}

func (s *Store) ReplaceUserRoles(ctx context.Context, userID domain.UserID, roleIDs []domain.RoleID, now time.Time) error {
	if _, err := s.db.NewDelete().Model((*UserRoleModel)(nil)).Where("user_id = ?", userID.String()).Exec(ctx); err != nil {
		return err
	}
	if len(roleIDs) == 0 {
		return nil
	}
	rows := make([]UserRoleModel, 0, len(roleIDs))
	seen := make(map[domain.RoleID]struct{}, len(roleIDs))
	for _, id := range roleIDs {
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		rows = append(rows, UserRoleModel{UserID: userID.String(), RoleID: id.String(), CreatedAt: now})
	}
	if len(rows) == 0 {
		return nil
	}
	if _, err := s.db.NewInsert().Model(&rows).Exec(ctx); err != nil {
		return mapWriteError(err, false)
	}
	return nil
}

func (s *Store) ListRolePermissions(ctx context.Context, roleID domain.RoleID) ([]domain.Permission, error) {
	rows := make([]PermissionModel, 0)
	err := s.db.NewSelect().Model(&rows).
		Join("JOIN identity_role_permissions AS rp ON rp.permission_id = p.id").
		Where("rp.role_id = ?", roleID.String()).
		OrderExpr("p.code ASC").Scan(ctx)
	if err != nil {
		return nil, mapReadError(err)
	}
	out := make([]domain.Permission, len(rows))
	for i := range rows {
		out[i] = permissionFrom(&rows[i])
	}
	return out, nil
}

func (s *Store) ReplaceRolePermissions(ctx context.Context, roleID domain.RoleID, permissionIDs []domain.PermissionID, now time.Time) error {
	if _, err := s.db.NewDelete().Model((*RolePermissionModel)(nil)).Where("role_id = ?", roleID.String()).Exec(ctx); err != nil {
		return err
	}
	if len(permissionIDs) == 0 {
		return nil
	}
	rows := make([]RolePermissionModel, 0, len(permissionIDs))
	seen := make(map[domain.PermissionID]struct{}, len(permissionIDs))
	for _, id := range permissionIDs {
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		rows = append(rows, RolePermissionModel{RoleID: roleID.String(), PermissionID: id.String(), CreatedAt: now})
	}
	if len(rows) == 0 {
		return nil
	}
	if _, err := s.db.NewInsert().Model(&rows).Exec(ctx); err != nil {
		return mapWriteError(err, false)
	}
	return nil
}

func (s *Store) ListUserClaims(ctx context.Context, userID domain.UserID) (domain.Claims, error) {
	type claimRow struct {
		RoleCode       string `bun:"role_code"`
		PermissionCode string `bun:"permission_code"`
	}
	rows := make([]claimRow, 0)
	err := s.db.NewSelect().TableExpr("identity_user_roles AS ur").
		Join("JOIN identity_roles AS r ON r.id = ur.role_id").
		Join("LEFT JOIN identity_role_permissions AS rp ON rp.role_id = r.id").
		Join("LEFT JOIN identity_permissions AS p ON p.id = rp.permission_id").
		ColumnExpr("r.code AS role_code, p.code AS permission_code").
		Where("ur.user_id = ?", userID.String()).
		Scan(ctx, &rows)
	if err != nil {
		return domain.Claims{}, err
	}
	roles := make(map[string]struct{}, len(rows))
	permissions := make(map[string]struct{}, len(rows))
	for _, row := range rows {
		if row.RoleCode != "" {
			roles[row.RoleCode] = struct{}{}
		}
		if row.PermissionCode != "" {
			permissions[row.PermissionCode] = struct{}{}
		}
	}
	roleCodes := make([]string, 0, len(roles))
	for code := range roles {
		roleCodes = append(roleCodes, code)
	}
	permissionCodes := make([]string, 0, len(permissions))
	for code := range permissions {
		permissionCodes = append(permissionCodes, code)
	}
	sort.Strings(roleCodes)
	sort.Strings(permissionCodes)
	return domain.Claims{Roles: roleCodes, Permissions: permissionCodes}, nil
}

func roleFrom(m *RoleModel) domain.Role {
	idRaw, _ := uuid.Parse(m.ID)
	return domain.Role{ID: domain.RoleID(idRaw), Code: m.Code, Name: m.Name, Description: m.Description, System: m.System, CreatedAt: m.CreatedAt, UpdatedAt: m.UpdatedAt}
}

func permissionFrom(m *PermissionModel) domain.Permission {
	idRaw, _ := uuid.Parse(m.ID)
	return domain.Permission{ID: domain.PermissionID(idRaw), Code: m.Code, Name: m.Name, Description: m.Description, System: m.System, CreatedAt: m.CreatedAt, UpdatedAt: m.UpdatedAt}
}

var _ domain.AuthorizationRepository = (*Store)(nil)
