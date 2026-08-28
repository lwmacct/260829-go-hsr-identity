// Package testkit contains database helpers intended only for identity tests.
package testkit

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	"github.com/lwmacct/260829-go-hsr-identity/pkg/identity/migrations"
)

// ApplySchema installs the latest identity schema in a transaction. It is
// useful for tests and local fixtures; production applications should use a
// versioned migration runner with migrations.FS instead.
func ApplySchema(ctx context.Context, db *sql.DB) error {
	if db == nil {
		return errors.New("identity/testkit: database is required")
	}
	contents, err := migrations.FS.ReadFile("001_identity.sql")
	if err != nil {
		return err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for _, statement := range strings.Split(string(contents), ";") {
		statement = strings.TrimSpace(statement)
		if statement == "" {
			continue
		}
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return err
		}
	}
	return tx.Commit()
}
