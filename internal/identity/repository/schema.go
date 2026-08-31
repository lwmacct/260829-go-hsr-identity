package repository

import (
	"context"
	"fmt"

	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect"
)

type Schema struct {
	Models []any
	Tables []string
}

var requiredSchema = []struct {
	table   string
	columns []string
}{
	{"identity_users", []string{"id", "username", "phone_e164", "display_name", "email", "avatar_url", "state", "disabled_at", "last_login_at", "created_at", "updated_at"}},
	{"identity_passwords", []string{"user_id", "scheme", "hash", "password_changed_at", "created_at", "updated_at"}},
	{"identity_sessions", []string{"id", "token_hash", "user_id", "login_ip", "last_ip", "binding_hash", "expires_at", "created_at", "last_seen_at", "revoked_at", "revoked_reason"}},
	{"identity_roles", []string{"id", "code", "name", "description", "system", "created_at", "updated_at"}},
	{"identity_permissions", []string{"id", "code", "name", "description", "system", "created_at", "updated_at"}},
	{"identity_user_roles", []string{"user_id", "role_id", "created_at"}},
	{"identity_role_permissions", []string{"role_id", "permission_id", "created_at"}},
}

func DatabaseSchema() Schema {
	return Schema{
		Models: []any{
			(*UserModel)(nil),
			(*PasswordModel)(nil),
			(*SessionModel)(nil),
			(*RoleModel)(nil),
			(*PermissionModel)(nil),
			(*UserRoleModel)(nil),
			(*RolePermissionModel)(nil),
		},
		Tables: []string{
			"identity_role_permissions",
			"identity_user_roles",
			"identity_sessions",
			"identity_passwords",
			"identity_permissions",
			"identity_roles",
			"identity_users",
		},
	}
}

// Apply creates the identity tables and indexes. It is intended for tests and
// hosts that use Bun's model-driven schema setup; production migrations remain
// owned by the host application.
func (s Schema) Apply(ctx context.Context, db bun.IDB) error {
	if db == nil {
		return fmt.Errorf("identity schema: database is required")
	}
	if db.Dialect().Name() == dialect.SQLite {
		if _, err := db.NewRaw("PRAGMA foreign_keys = ON").Exec(ctx); err != nil {
			return fmt.Errorf("enable SQLite foreign keys: %w", err)
		}
	}
	for _, model := range s.Models {
		if _, err := db.NewCreateTable().Model(model).IfNotExists().WithForeignKeys().Exec(ctx); err != nil {
			return fmt.Errorf("create identity table: %w", err)
		}
	}
	indexes := []struct {
		name, table string
		columns     []string
		unique      bool
	}{
		{"identity_users_username_uq", "identity_users", []string{"username"}, true},
		{"identity_users_phone_uq", "identity_users", []string{"phone_e164"}, true},
		{"identity_users_email_uq", "identity_users", []string{"email"}, true},
		{"identity_sessions_user_expiry_idx", "identity_sessions", []string{"user_id", "expires_at"}, false},
		{"identity_sessions_expiry_idx", "identity_sessions", []string{"expires_at"}, false},
		{"identity_user_roles_role_idx", "identity_user_roles", []string{"role_id"}, false},
		{"identity_role_permissions_permission_idx", "identity_role_permissions", []string{"permission_id"}, false},
	}
	for _, index := range indexes {
		// The index target is supplied explicitly. Do not bind a model here:
		// Bun keeps a model's table as the primary target even when Table is
		// called afterwards, which would make every index use identity_sessions.
		create := db.NewCreateIndex().Index(index.name).Table(index.table).Column(index.columns...).IfNotExists()
		if index.unique {
			create = create.Unique()
		}
		if _, err := create.Exec(ctx); err != nil {
			return fmt.Errorf("create identity index: %w", err)
		}
	}
	return nil
}

func ValidateSchema(ctx context.Context, db *bun.DB) error {
	if db == nil {
		return fmt.Errorf("identity schema: database is required")
	}
	for _, required := range requiredSchema {
		for _, column := range required.columns {
			exists, err := schemaColumnExists(ctx, db, required.table, column)
			if err != nil {
				return fmt.Errorf("inspect identity schema %s.%s: %w", required.table, column, err)
			}
			if !exists {
				return fmt.Errorf("identity schema is incomplete: missing %s.%s", required.table, column)
			}
		}
	}
	switch db.Dialect().Name() {
	case dialect.SQLite:
		// SQLite foreign-key enforcement is connection-local. Identity deletes
		// dependent rows explicitly, so schema validity does not depend on a
		// pool-wide PRAGMA setting.
	case dialect.PG:
		var versionNum int
		if err := db.NewRaw("SHOW server_version_num").Scan(ctx, &versionNum); err != nil {
			return fmt.Errorf("inspect PostgreSQL version: %w", err)
		}
		if versionNum < 180000 {
			return fmt.Errorf("identity requires PostgreSQL 18 or newer, got %d", versionNum)
		}
	default:
		return fmt.Errorf("unsupported database dialect %s", db.Dialect().Name())
	}
	for _, index := range []struct {
		table string
		name  string
	}{
		{"identity_users", "identity_users_username_uq"},
		{"identity_users", "identity_users_phone_uq"},
		{"identity_users", "identity_users_email_uq"},
		{"identity_sessions", "identity_sessions_user_expiry_idx"},
		{"identity_sessions", "identity_sessions_expiry_idx"},
		{"identity_user_roles", "identity_user_roles_role_idx"},
		{"identity_role_permissions", "identity_role_permissions_permission_idx"},
	} {
		exists, err := schemaIndexExists(ctx, db, index.table, index.name)
		if err != nil {
			return fmt.Errorf("inspect identity schema index %s: %w", index.name, err)
		}
		if !exists {
			return fmt.Errorf("identity schema is incomplete: missing index %s", index.name)
		}
	}
	return nil
}

func schemaColumnExists(ctx context.Context, db *bun.DB, table, column string) (bool, error) {
	var count int
	switch db.Dialect().Name() {
	case dialect.SQLite:
		err := db.NewRaw("SELECT COUNT(*) FROM pragma_table_info(?) WHERE name = ?", table, column).Scan(ctx, &count)
		return count > 0, err
	case dialect.PG:
		err := db.NewRaw("SELECT COUNT(*) FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = ? AND column_name = ?", table, column).Scan(ctx, &count)
		return count > 0, err
	default:
		return false, fmt.Errorf("unsupported database dialect %s", db.Dialect().Name())
	}
}

func schemaIndexExists(ctx context.Context, db *bun.DB, table, index string) (bool, error) {
	var count int
	switch db.Dialect().Name() {
	case dialect.SQLite:
		err := db.NewRaw("SELECT COUNT(*) FROM pragma_index_list(?) WHERE name = ?", table, index).Scan(ctx, &count)
		return count > 0, err
	case dialect.PG:
		err := db.NewRaw("SELECT COUNT(*) FROM pg_indexes WHERE schemaname = current_schema() AND tablename = ? AND indexname = ?", table, index).Scan(ctx, &count)
		return count > 0, err
	default:
		return false, fmt.Errorf("unsupported database dialect %s", db.Dialect().Name())
	}
}
