package repository

import (
	"context"
	"time"

	"github.com/uptrace/bun"
)

type UserModel struct {
	bun.BaseModel `bun:"table:identity_users,alias:u"`
	ID            UserID     `bun:"id,pk,type:uuid"`
	Handle        string     `bun:"handle,notnull,unique"`
	DisplayName   string     `bun:"display_name,notnull"`
	Email         string     `bun:"email,notnull"`
	AvatarURL     string     `bun:"avatar_url,notnull"`
	State         string     `bun:"state,notnull"`
	DisabledAt    *time.Time `bun:"disabled_at,nullzero"`
	LastLoginAt   *time.Time `bun:"last_login_at,nullzero"`
	CreatedAt     time.Time  `bun:"created_at,notnull"`
	UpdatedAt     time.Time  `bun:"updated_at,notnull"`
}

func (*UserModel) BeforeCreateTable(_ context.Context, query *bun.CreateTableQuery) error {
	query.ColumnExpr("CHECK (state IN ('active', 'disabled'))")
	if query.Dialect().Name().String() == "pg" {
		query.ColumnExpr("CHECK (uuid_extract_version(id) = 7)")
	}
	return nil
}

type PasswordModel struct {
	bun.BaseModel     `bun:"table:identity_passwords,alias:ip"`
	UserID            UserID    `bun:"user_id,pk,type:uuid"`
	Scheme            string    `bun:"scheme,notnull"`
	Hash              string    `bun:"hash,notnull"`
	PasswordChangedAt time.Time `bun:"password_changed_at,notnull"`
	CreatedAt         time.Time `bun:"created_at,notnull"`
	UpdatedAt         time.Time `bun:"updated_at,notnull"`
}

func (*PasswordModel) BeforeCreateTable(_ context.Context, query *bun.CreateTableQuery) error {
	query.ForeignKey("(user_id) REFERENCES identity_users (id) ON DELETE CASCADE")
	return nil
}

type SessionModel struct {
	bun.BaseModel `bun:"table:identity_sessions,alias:sess"`
	ID            SessionID  `bun:"id,pk,type:uuid"`
	TokenHash     []byte     `bun:"token_hash,notnull,unique"`
	UserID        UserID     `bun:"user_id,notnull,type:uuid"`
	LoginIP       string     `bun:"login_ip,notnull"`
	LastIP        string     `bun:"last_ip,notnull"`
	BindingHash   []byte     `bun:"binding_hash,nullzero"`
	UserAgentHash []byte     `bun:"user_agent_hash,notnull"`
	ExpiresAt     time.Time  `bun:"expires_at,notnull"`
	CreatedAt     time.Time  `bun:"created_at,notnull"`
	LastSeenAt    time.Time  `bun:"last_seen_at,notnull"`
	RevokedAt     *time.Time `bun:"revoked_at,nullzero"`
	RevokedReason string     `bun:"revoked_reason,notnull"`
}

func (*SessionModel) BeforeCreateTable(_ context.Context, query *bun.CreateTableQuery) error {
	query.ForeignKey("(user_id) REFERENCES identity_users (id) ON DELETE CASCADE")
	if query.Dialect().Name().String() == "pg" {
		query.ColumnExpr("CHECK (uuid_extract_version(id) = 7)")
	}
	return nil
}

type RoleModel struct {
	bun.BaseModel `bun:"table:identity_roles,alias:r"`
	ID            RoleID    `bun:"id,pk,type:uuid"`
	Code          string    `bun:"code,notnull,unique"`
	Name          string    `bun:"name,notnull"`
	Description   string    `bun:"description,notnull"`
	System        bool      `bun:"system,notnull"`
	CreatedAt     time.Time `bun:"created_at,notnull"`
	UpdatedAt     time.Time `bun:"updated_at,notnull"`
}

func (*RoleModel) BeforeCreateTable(_ context.Context, query *bun.CreateTableQuery) error {
	if query.Dialect().Name().String() == "pg" {
		query.ColumnExpr("CHECK (uuid_extract_version(id) = 7)")
	}
	query.ColumnExpr("CHECK (code <> '')")
	return nil
}

type PermissionModel struct {
	bun.BaseModel `bun:"table:identity_permissions,alias:p"`
	ID            PermissionID `bun:"id,pk,type:uuid"`
	Code          string       `bun:"code,notnull,unique"`
	Name          string       `bun:"name,notnull"`
	Description   string       `bun:"description,notnull"`
	System        bool         `bun:"system,notnull"`
	CreatedAt     time.Time    `bun:"created_at,notnull"`
	UpdatedAt     time.Time    `bun:"updated_at,notnull"`
}

func (*PermissionModel) BeforeCreateTable(_ context.Context, query *bun.CreateTableQuery) error {
	if query.Dialect().Name().String() == "pg" {
		query.ColumnExpr("CHECK (uuid_extract_version(id) = 7)")
	}
	query.ColumnExpr("CHECK (code <> '')")
	return nil
}

type UserRoleModel struct {
	bun.BaseModel `bun:"table:identity_user_roles,alias:ur"`
	UserID        UserID    `bun:"user_id,type:uuid,pk"`
	RoleID        RoleID    `bun:"role_id,type:uuid,pk"`
	CreatedAt     time.Time `bun:"created_at,notnull"`
}

func (*UserRoleModel) BeforeCreateTable(_ context.Context, query *bun.CreateTableQuery) error {
	query.ForeignKey("(user_id) REFERENCES identity_users (id) ON DELETE CASCADE")
	query.ForeignKey("(role_id) REFERENCES identity_roles (id) ON DELETE CASCADE")
	return nil
}

type RolePermissionModel struct {
	bun.BaseModel `bun:"table:identity_role_permissions,alias:rp"`
	RoleID        RoleID       `bun:"role_id,type:uuid,pk"`
	PermissionID  PermissionID `bun:"permission_id,type:uuid,pk"`
	CreatedAt     time.Time    `bun:"created_at,notnull"`
}

func (*RolePermissionModel) BeforeCreateTable(_ context.Context, query *bun.CreateTableQuery) error {
	query.ForeignKey("(role_id) REFERENCES identity_roles (id) ON DELETE CASCADE")
	query.ForeignKey("(permission_id) REFERENCES identity_permissions (id) ON DELETE CASCADE")
	return nil
}

type UserID = string
type SessionID = string
type RoleID = string
type PermissionID = string
