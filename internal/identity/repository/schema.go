package repository

import (
	"context"
	"fmt"
	"strings"

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
	{"identity_users", []string{"id", "username", "display_name", "avatar_url", "state", "disabled_at", "last_login_at", "created_at", "updated_at"}},
	{"identity_user_contacts", []string{"id", "user_id", "kind", "normalized_value", "verified_at", "created_at", "updated_at"}},
	{"identity_contact_verifications", []string{"id", "user_id", "kind", "normalized_value", "provider", "provider_challenge_id", "status", "attempt_count", "expires_at", "created_at", "consumed_at"}},
	{"identity_passwords", []string{"user_id", "scheme", "hash", "password_changed_at", "created_at", "updated_at"}},
	{"identity_sessions", []string{"id", "token_hash", "user_id", "login_ip", "last_ip", "binding_hash", "expires_at", "created_at", "last_seen_at", "revoked_at", "revoked_reason"}},
	{"identity_roles", []string{"id", "code", "name", "description", "system", "created_at", "updated_at"}},
	{"identity_permissions", []string{"id", "code", "name", "description", "system", "created_at", "updated_at"}},
	{"identity_user_roles", []string{"user_id", "role_id", "created_at"}},
	{"identity_role_permissions", []string{"role_id", "permission_id", "created_at"}},
}

type schemaIndexRequirement struct {
	name, table string
	columns     []string
	unique      bool
}

var requiredIndexes = []schemaIndexRequirement{
	{name: "identity_users_username_uq", table: "identity_users", columns: []string{"username"}, unique: true},
	{name: "identity_user_contacts_user_kind_uq", table: "identity_user_contacts", columns: []string{"user_id", "kind"}, unique: true},
	{name: "identity_user_contacts_kind_value_uq", table: "identity_user_contacts", columns: []string{"kind", "normalized_value"}, unique: true},
	{name: "identity_user_contacts_user_idx", table: "identity_user_contacts", columns: []string{"user_id"}, unique: false},
	{name: "identity_contact_verifications_user_kind_idx", table: "identity_contact_verifications", columns: []string{"user_id", "kind", "created_at"}, unique: false},
	{name: "identity_contact_verifications_provider_challenge_uq", table: "identity_contact_verifications", columns: []string{"provider", "provider_challenge_id"}, unique: true},
	{name: "identity_sessions_user_expiry_idx", table: "identity_sessions", columns: []string{"user_id", "expires_at"}},
	{name: "identity_sessions_expiry_idx", table: "identity_sessions", columns: []string{"expires_at"}},
	{name: "identity_user_roles_role_idx", table: "identity_user_roles", columns: []string{"role_id"}},
	{name: "identity_role_permissions_permission_idx", table: "identity_role_permissions", columns: []string{"permission_id"}},
}

func DatabaseSchema() Schema {
	return Schema{
		Models: []any{
			(*UserModel)(nil),
			(*UserContactModel)(nil),
			(*ContactVerificationModel)(nil),
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
			"identity_contact_verifications",
			"identity_user_contacts",
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
	for _, index := range requiredIndexes {
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
	for _, removedColumn := range []string{"phone_e164", "email"} {
		exists, err := schemaColumnExists(ctx, db, "identity_users", removedColumn)
		if err != nil {
			return fmt.Errorf("inspect removed identity schema column identity_users.%s: %w", removedColumn, err)
		}
		if exists {
			return fmt.Errorf("identity schema is stale: removed identity_users.%s is still present", removedColumn)
		}
	}
	for _, column := range []struct {
		table    string
		name     string
		nullable bool
	}{
		{table: "identity_users", name: "username", nullable: false},
		{table: "identity_user_contacts", name: "verified_at", nullable: false},
		{table: "identity_contact_verifications", name: "consumed_at", nullable: true},
	} {
		nullable, err := schemaColumnNullable(ctx, db, column.table, column.name)
		if err != nil {
			return fmt.Errorf("inspect identity schema nullability %s.%s: %w", column.table, column.name, err)
		}
		if nullable != column.nullable {
			return fmt.Errorf("identity schema is invalid: %s.%s nullable=%t, want %t", column.table, column.name, nullable, column.nullable)
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
	for _, constraint := range []string{
		"identity_users_state_chk",
		"identity_users_username_chk",
		"identity_user_contacts_kind_chk",
		"identity_user_contacts_value_chk",
		"identity_contact_verifications_kind_chk",
		"identity_contact_verifications_status_chk",
		"identity_contact_verifications_value_chk",
	} {
		table := "identity_users"
		if strings.HasPrefix(constraint, "identity_user_contacts") {
			table = "identity_user_contacts"
		}
		if strings.HasPrefix(constraint, "identity_contact_verifications") {
			table = "identity_contact_verifications"
		}
		exists, err := schemaConstraintExists(ctx, db, table, constraint)
		if err != nil {
			return fmt.Errorf("inspect identity schema constraint %s: %w", constraint, err)
		}
		if !exists {
			return fmt.Errorf("identity schema is incomplete: missing constraint %s", constraint)
		}
	}
	for _, index := range requiredIndexes {
		matches, err := schemaIndexMatches(ctx, db, index)
		if err != nil {
			return fmt.Errorf("inspect identity schema index %s: %w", index.name, err)
		}
		if !matches {
			return fmt.Errorf("identity schema is incomplete or invalid: index %s", index.name)
		}
	}
	return nil
}

func schemaColumnNullable(ctx context.Context, db *bun.DB, table, column string) (bool, error) {
	switch db.Dialect().Name() {
	case dialect.SQLite:
		var rows []struct {
			Required int `bun:"required"`
		}
		if err := db.NewRaw(`SELECT "notnull" AS required FROM pragma_table_info(?) WHERE name = ?`, table, column).Scan(ctx, &rows); err != nil {
			return false, err
		}
		if len(rows) != 1 {
			return false, fmt.Errorf("column %s.%s not found", table, column)
		}
		return rows[0].Required == 0, nil
	case dialect.PG:
		var rows []struct {
			Nullable string `bun:"is_nullable"`
		}
		if err := db.NewRaw("SELECT is_nullable FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = ? AND column_name = ?", table, column).Scan(ctx, &rows); err != nil {
			return false, err
		}
		if len(rows) != 1 {
			return false, fmt.Errorf("column %s.%s not found", table, column)
		}
		return rows[0].Nullable == "YES", nil
	default:
		return false, fmt.Errorf("unsupported database dialect %s", db.Dialect().Name())
	}
}

func schemaConstraintExists(ctx context.Context, db *bun.DB, table, constraint string) (bool, error) {
	var count int
	switch db.Dialect().Name() {
	case dialect.SQLite:
		err := db.NewRaw("SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ? AND lower(sql) LIKE ?", table, "%constraint "+strings.ToLower(constraint)+" %").Scan(ctx, &count)
		return count > 0, err
	case dialect.PG:
		err := db.NewRaw(`
			SELECT COUNT(*)
			FROM pg_catalog.pg_constraint AS constraint_info
			JOIN pg_catalog.pg_class AS table_info ON table_info.oid = constraint_info.conrelid
			JOIN pg_catalog.pg_namespace AS namespace_info ON namespace_info.oid = table_info.relnamespace
			WHERE namespace_info.nspname = current_schema()
			  AND table_info.relname = ?
			  AND constraint_info.conname = ?
		`, table, constraint).Scan(ctx, &count)
		return count > 0, err
	default:
		return false, fmt.Errorf("unsupported database dialect %s", db.Dialect().Name())
	}
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

func schemaIndexMatches(ctx context.Context, db *bun.DB, required schemaIndexRequirement) (bool, error) {
	switch db.Dialect().Name() {
	case dialect.SQLite:
		var indexes []struct {
			Name   string `bun:"name"`
			Unique int    `bun:"unique"`
		}
		if err := db.NewRaw(`SELECT name, "unique" FROM pragma_index_list(?) WHERE name = ?`, required.table, required.name).Scan(ctx, &indexes); err != nil {
			return false, err
		}
		if len(indexes) != 1 || (indexes[0].Unique == 1) != required.unique {
			return false, nil
		}
		var columns []struct {
			Name string `bun:"name"`
		}
		if err := db.NewRaw("SELECT name FROM pragma_index_info(?) ORDER BY seqno", required.name).Scan(ctx, &columns); err != nil {
			return false, err
		}
		if len(columns) != len(required.columns) {
			return false, nil
		}
		for i := range required.columns {
			if columns[i].Name != required.columns[i] {
				return false, nil
			}
		}
		return true, nil
	case dialect.PG:
		var indexes []struct {
			Unique bool `bun:"is_unique"`
		}
		if err := db.NewRaw(`
			SELECT index_info.indisunique AS is_unique
			FROM pg_catalog.pg_class AS table_info
			JOIN pg_catalog.pg_namespace AS namespace_info ON namespace_info.oid = table_info.relnamespace
			JOIN pg_catalog.pg_index AS index_info ON index_info.indrelid = table_info.oid
			JOIN pg_catalog.pg_class AS index_table ON index_table.oid = index_info.indexrelid
			WHERE namespace_info.nspname = current_schema()
			  AND table_info.relname = ?
			  AND index_table.relname = ?
		`, required.table, required.name).Scan(ctx, &indexes); err != nil {
			return false, err
		}
		if len(indexes) != 1 || indexes[0].Unique != required.unique {
			return false, nil
		}
		var columns []struct {
			Name string `bun:"column_name"`
		}
		if err := db.NewRaw(`
			SELECT attribute_info.attname AS column_name
			FROM pg_catalog.pg_class AS table_info
			JOIN pg_catalog.pg_namespace AS namespace_info ON namespace_info.oid = table_info.relnamespace
			JOIN pg_catalog.pg_index AS index_info ON index_info.indrelid = table_info.oid
			JOIN pg_catalog.pg_class AS index_table ON index_table.oid = index_info.indexrelid
			CROSS JOIN LATERAL unnest(index_info.indkey::smallint[]) WITH ORDINALITY AS key_parts(attnum, ordinal)
			JOIN pg_catalog.pg_attribute AS attribute_info
			  ON attribute_info.attrelid = table_info.oid
			 AND attribute_info.attnum = key_parts.attnum
			WHERE namespace_info.nspname = current_schema()
			  AND table_info.relname = ?
			  AND index_table.relname = ?
			ORDER BY key_parts.ordinal
		`, required.table, required.name).Scan(ctx, &columns); err != nil {
			return false, err
		}
		if len(columns) != len(required.columns) {
			return false, nil
		}
		for i := range required.columns {
			if columns[i].Name != required.columns[i] {
				return false, nil
			}
		}
		return true, nil
	default:
		return false, fmt.Errorf("unsupported database dialect %s", db.Dialect().Name())
	}
}
