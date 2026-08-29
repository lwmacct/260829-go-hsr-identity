package repository

import (
	"context"
	"fmt"

	"github.com/uptrace/bun"
)

type Schema struct {
	Models []any
	Tables []string
}

func DatabaseSchema() Schema {
	return Schema{
		Models: []any{(*UserModel)(nil), (*PasswordModel)(nil), (*SessionModel)(nil)},
		Tables: []string{"identity_sessions", "identity_passwords", "identity_users"},
	}
}

// Apply creates the identity tables and indexes. It is intended for tests and
// hosts that use Bun's model-driven schema setup; production migrations remain
// owned by the host application.
func (s Schema) Apply(ctx context.Context, db bun.IDB) error {
	if db == nil {
		return fmt.Errorf("identity schema: database is required")
	}
	for _, model := range s.Models {
		if _, err := db.NewCreateTable().Model(model).IfNotExists().WithForeignKeys().Exec(ctx); err != nil {
			return fmt.Errorf("create identity table: %w", err)
		}
	}
	indexes := []struct {
		name, table string
		columns     []string
	}{
		{"identity_sessions_user_expiry_idx", "identity_sessions", []string{"user_id", "expires_at"}},
		{"identity_sessions_expiry_idx", "identity_sessions", []string{"expires_at"}},
	}
	for _, index := range indexes {
		if _, err := db.NewCreateIndex().Model((*SessionModel)(nil)).Index(index.name).Table(index.table).Column(index.columns...).IfNotExists().Exec(ctx); err != nil {
			return fmt.Errorf("create identity index: %w", err)
		}
	}
	return nil
}
