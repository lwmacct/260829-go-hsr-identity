package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/lwmacct/260829-go-hsr-identity/pkg/identity"
	_ "modernc.org/sqlite"
)

func TestApplySchemaIsIdempotent(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := ApplySchema(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	if err := ApplySchema(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	if err := ResetSchema(context.Background(), db); err != nil {
		t.Fatal(err)
	}
}

func TestWithinTxRollsBackAllRepositories(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := ApplySchema(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	store := New(db)
	now := time.Unix(1, 0).UTC()
	want := errors.New("abort")
	err = store.WithinTx(context.Background(), func(ctx context.Context, unit identity.UnitOfWork) error {
		_, err := unit.Users().CreateUser(ctx, identity.UserCreate{ID: "u1", Handle: "u1", DisplayName: "User", State: identity.StateActive, CreatedAt: now, UpdatedAt: now})
		if err != nil {
			return err
		}
		return want
	})
	if !errors.Is(err, want) {
		t.Fatalf("transaction err=%v", err)
	}
	if _, err := store.GetUser(context.Background(), "u1"); !errors.Is(err, identity.ErrNotFound) {
		t.Fatalf("rolled back user err=%v", err)
	}
}
