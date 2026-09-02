package repository

import (
	"context"
	"fmt"
	"time"

	"github.com/uptrace/bun"
)

type UserModel struct {
	bun.BaseModel `bun:"table:identity_users,alias:u"`
	ID            string     `bun:"id,pk,type:uuid"`
	Username      string     `bun:"username,notnull"`
	DisplayName   string     `bun:"display_name,notnull"`
	AvatarURL     string     `bun:"avatar_url,notnull"`
	State         string     `bun:"state,notnull"`
	DisabledAt    *time.Time `bun:"disabled_at,nullzero"`
	LastLoginAt   *time.Time `bun:"last_login_at,nullzero"`
	CreatedAt     time.Time  `bun:"created_at,notnull"`
	UpdatedAt     time.Time  `bun:"updated_at,notnull"`
}

func (*UserModel) BeforeCreateTable(_ context.Context, query *bun.CreateTableQuery) error {
	query.ColumnExpr("CONSTRAINT identity_users_state_chk CHECK (state IN ('active', 'disabled'))")
	if query.Dialect().Name().String() == "pg" {
		query.ColumnExpr("CONSTRAINT identity_users_username_chk CHECK (username ~ '^[a-z]([a-z0-9_-]*[a-z0-9])?$' AND length(username) BETWEEN 1 AND 64)")
	} else {
		query.ColumnExpr("CONSTRAINT identity_users_username_chk CHECK (length(username) BETWEEN 1 AND 64 AND substr(username, 1, 1) GLOB '[a-z]' AND substr(username, length(username), 1) GLOB '[a-z0-9]' AND username NOT GLOB '*[^a-z0-9_-]*')")
	}
	addUUIDv7Check(query, "id")
	return nil
}

type UserContactModel struct {
	bun.BaseModel `bun:"table:identity_user_contacts,alias:uc"`
	ID            string    `bun:"id,pk,type:uuid"`
	UserID        string    `bun:"user_id,type:uuid,notnull"`
	Kind          string    `bun:"kind,notnull"`
	Value         string    `bun:"normalized_value,notnull"`
	VerifiedAt    time.Time `bun:"verified_at,notnull"`
	CreatedAt     time.Time `bun:"created_at,notnull"`
	UpdatedAt     time.Time `bun:"updated_at,notnull"`
}

func (*UserContactModel) BeforeCreateTable(_ context.Context, query *bun.CreateTableQuery) error {
	query.ForeignKey("(user_id) REFERENCES identity_users (id) ON DELETE CASCADE")
	query.ColumnExpr("CONSTRAINT identity_user_contacts_kind_chk CHECK (kind IN ('phone', 'email'))")
	query.ColumnExpr("CONSTRAINT identity_user_contacts_value_chk CHECK (normalized_value <> '')")
	addUUIDv7Check(query, "id")
	return nil
}

type ContactVerificationModel struct {
	bun.BaseModel       `bun:"table:identity_contact_verifications,alias:cv"`
	ID                  string     `bun:"id,pk,type:uuid"`
	UserID              string     `bun:"user_id,type:uuid,notnull"`
	Kind                string     `bun:"kind,notnull"`
	Value               string     `bun:"normalized_value,notnull"`
	Provider            string     `bun:"provider,notnull"`
	ProviderChallengeID string     `bun:"provider_challenge_id,notnull"`
	Status              string     `bun:"status,notnull"`
	AttemptCount        int        `bun:"attempt_count,notnull"`
	ExpiresAt           time.Time  `bun:"expires_at,notnull"`
	CreatedAt           time.Time  `bun:"created_at,notnull"`
	ConsumedAt          *time.Time `bun:"consumed_at,nullzero"`
}

func (*ContactVerificationModel) BeforeCreateTable(_ context.Context, query *bun.CreateTableQuery) error {
	query.ForeignKey("(user_id) REFERENCES identity_users (id) ON DELETE CASCADE")
	query.ColumnExpr("CONSTRAINT identity_contact_verifications_kind_chk CHECK (kind IN ('phone', 'email'))")
	query.ColumnExpr("CONSTRAINT identity_contact_verifications_status_chk CHECK (status IN ('pending', 'consumed', 'expired', 'cancelled', 'failed'))")
	query.ColumnExpr("CONSTRAINT identity_contact_verifications_value_chk CHECK (normalized_value <> '')")
	addUUIDv7Check(query, "id")
	return nil
}

type PasswordModel struct {
	bun.BaseModel     `bun:"table:identity_passwords,alias:ip"`
	UserID            string    `bun:"user_id,pk,type:uuid"`
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
	ID            string     `bun:"id,pk,type:uuid"`
	TokenHash     []byte     `bun:"token_hash,notnull,unique"`
	UserID        string     `bun:"user_id,notnull,type:uuid"`
	LoginIP       string     `bun:"login_ip,notnull"`
	LastIP        string     `bun:"last_ip,notnull"`
	BindingHash   []byte     `bun:"binding_hash,nullzero"`
	ExpiresAt     time.Time  `bun:"expires_at,notnull"`
	CreatedAt     time.Time  `bun:"created_at,notnull"`
	LastSeenAt    time.Time  `bun:"last_seen_at,notnull"`
	RevokedAt     *time.Time `bun:"revoked_at,nullzero"`
	RevokedReason string     `bun:"revoked_reason,notnull"`
}

func (*SessionModel) BeforeCreateTable(_ context.Context, query *bun.CreateTableQuery) error {
	query.ForeignKey("(user_id) REFERENCES identity_users (id) ON DELETE CASCADE")
	addUUIDv7Check(query, "id")
	return nil
}

type RoleModel struct {
	bun.BaseModel `bun:"table:identity_roles,alias:r"`
	ID            string    `bun:"id,pk,type:uuid"`
	Code          string    `bun:"code,notnull,unique"`
	Name          string    `bun:"name,notnull"`
	Description   string    `bun:"description,notnull"`
	System        bool      `bun:"system,notnull"`
	CreatedAt     time.Time `bun:"created_at,notnull"`
	UpdatedAt     time.Time `bun:"updated_at,notnull"`
}

func (*RoleModel) BeforeCreateTable(_ context.Context, query *bun.CreateTableQuery) error {
	addUUIDv7Check(query, "id")
	query.ColumnExpr("CHECK (code <> '')")
	return nil
}

type PermissionModel struct {
	bun.BaseModel `bun:"table:identity_permissions,alias:p"`
	ID            string    `bun:"id,pk,type:uuid"`
	Code          string    `bun:"code,notnull,unique"`
	Name          string    `bun:"name,notnull"`
	Description   string    `bun:"description,notnull"`
	System        bool      `bun:"system,notnull"`
	CreatedAt     time.Time `bun:"created_at,notnull"`
	UpdatedAt     time.Time `bun:"updated_at,notnull"`
}

func (*PermissionModel) BeforeCreateTable(_ context.Context, query *bun.CreateTableQuery) error {
	addUUIDv7Check(query, "id")
	query.ColumnExpr("CHECK (code <> '')")
	return nil
}

type UserRoleModel struct {
	bun.BaseModel `bun:"table:identity_user_roles,alias:ur"`
	UserID        string    `bun:"user_id,type:uuid,pk"`
	RoleID        string    `bun:"role_id,type:uuid,pk"`
	CreatedAt     time.Time `bun:"created_at,notnull"`
}

func (*UserRoleModel) BeforeCreateTable(_ context.Context, query *bun.CreateTableQuery) error {
	query.ForeignKey("(user_id) REFERENCES identity_users (id) ON DELETE CASCADE")
	query.ForeignKey("(role_id) REFERENCES identity_roles (id) ON DELETE CASCADE")
	return nil
}

type RolePermissionModel struct {
	bun.BaseModel `bun:"table:identity_role_permissions,alias:rp"`
	RoleID        string    `bun:"role_id,type:uuid,pk"`
	PermissionID  string    `bun:"permission_id,type:uuid,pk"`
	CreatedAt     time.Time `bun:"created_at,notnull"`
}

func (*RolePermissionModel) BeforeCreateTable(_ context.Context, query *bun.CreateTableQuery) error {
	query.ForeignKey("(role_id) REFERENCES identity_roles (id) ON DELETE CASCADE")
	query.ForeignKey("(permission_id) REFERENCES identity_permissions (id) ON DELETE CASCADE")
	return nil
}

func addUUIDv7Check(query *bun.CreateTableQuery, column string) {
	if query.Dialect().Name().String() == "pg" {
		query.ColumnExpr(fmt.Sprintf("CHECK (uuid_extract_version(%s) = 7)", column))
		return
	}
	query.ColumnExpr(fmt.Sprintf(
		"CHECK (length(%[1]s) = 36 AND substr(%[1]s, 9, 1) = '-' AND substr(%[1]s, 14, 1) = '-' AND substr(%[1]s, 19, 1) = '-' AND substr(%[1]s, 24, 1) = '-' AND substr(%[1]s, 15, 1) = '7' AND lower(substr(%[1]s, 20, 1)) IN ('8', '9', 'a', 'b') AND lower(replace(%[1]s, '-', '')) NOT GLOB '*[^0-9a-f]*')",
		column,
	))
}
