//go:build integration

package identity_test

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"strings"
	"testing"
	"uuid"

	"github.com/lwmacct/260829-go-hsr-identity/pkg/identity"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"
	"github.com/uptrace/bun/driver/pgdriver"
)

// TestPostgreSQLLifecycle uses an isolated schema and removes it after the
// test. Set IDENTITY_TEST_POSTGRES_DSN to a PostgreSQL connection URL and run:
//
//	go test -tags=integration ./pkg/identity -run TestPostgreSQLLifecycle
func TestPostgreSQLLifecycle(t *testing.T) {
	dsn := os.Getenv("IDENTITY_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("IDENTITY_TEST_POSTGRES_DSN is not set")
	}
	ctx := context.Background()
	sqlDB := sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(dsn)))
	sqlDB.SetMaxOpenConns(1)
	db := bun.NewDB(sqlDB, pgdialect.New())
	var versionNum int
	if err := db.NewRaw("SHOW server_version_num").Scan(ctx, &versionNum); err != nil {
		t.Fatal(err)
	}
	if versionNum < identity.MinimumPostgreSQLMajor*10000 {
		t.Fatalf("PostgreSQL %d is unsupported; PostgreSQL %d+ is required", versionNum, identity.MinimumPostgreSQLMajor)
	}
	schema := "identity_test_" + strings.ReplaceAll(uuid.NewV7().String(), "-", "_")
	if _, err := db.NewRaw("CREATE SCHEMA ?", bun.Ident(schema)).Exec(ctx); err != nil {
		_ = db.Close()
		_ = sqlDB.Close()
		t.Fatal(err)
	}
	if _, err := db.NewRaw("SET search_path TO ?", bun.Ident(schema)).Exec(ctx); err != nil {
		_ = db.Close()
		_ = sqlDB.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.NewRaw("DROP SCHEMA ? CASCADE", bun.Ident(schema)).Exec(context.Background())
		_ = db.Close()
		_ = sqlDB.Close()
	})

	if err := identity.ApplySchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	now := "2026-08-30T00:00:00Z"
	if _, err := db.NewRaw(
		"INSERT INTO identity_users (id, username, display_name, avatar_url, state, created_at, updated_at) VALUES (?, 'bad-v4', 'bad-v4', '', 'active', ?, ?)",
		"00000000-0000-4000-8000-000000000000", now, now,
	).Exec(ctx); err == nil {
		t.Fatal("PostgreSQL schema accepted a UUIDv4 identity user")
	}
	module, err := identity.New(identity.Options{
		DB:       db,
		Password: identity.PasswordOptions{Policy: identity.PasswordPolicy{MinLength: 8}},
	})
	if err != nil {
		t.Fatal(err)
	}
	user, err := module.RegisterUser(ctx, identity.UserCreateInput{Username: "postgres-user"}, "correct horse")
	if err != nil {
		t.Fatal(err)
	}
	_, issued, err := module.Login(ctx, user.Username, "correct horse", identity.RequestMeta{ClientIP: "127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := module.ResolveSession(ctx, issued.Token, identity.RequestMeta{ClientIP: "127.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	if err := module.SetUserState(ctx, []identity.UserID{user.ID}, identity.StateDisabled); err != nil {
		t.Fatal(err)
	}
	if _, err := module.ResolveSession(ctx, issued.Token, identity.RequestMeta{ClientIP: "127.0.0.1"}); !errors.Is(err, identity.ErrRevoked) {
		t.Fatalf("disabled user session error = %v", err)
	}
}
