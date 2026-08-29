// Package testkit provides Bun database helpers for identity tests.
package testkit

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"testing"

	"github.com/lwmacct/260829-go-hsr-identity/pkg/identity"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/sqlitedialect"
	"github.com/uptrace/bun/driver/sqliteshim"
)

// NewSQLite creates an in-memory SQLite Bun database and registers cleanup.
func NewSQLite(t testing.TB) *bun.DB {
	t.Helper()
	dsn := fmt.Sprintf("file:identity-testkit-%s?mode=memory&cache=shared", strings.NewReplacer("/", "-", " ", "-").Replace(t.Name()))
	dbsql, err := sql.Open(sqliteshim.ShimName, dsn)
	if err != nil {
		t.Fatal(err)
	}
	db := bun.NewDB(dbsql, sqlitedialect.New())
	t.Cleanup(func() { _ = db.Close(); _ = dbsql.Close() })
	if err := identity.ApplySchema(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	return db
}
