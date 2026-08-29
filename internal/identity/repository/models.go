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

type UserID = string
type SessionID = string
