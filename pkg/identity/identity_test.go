package identity_test

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lwmacct/260829-go-hsr-identity/pkg/identity"
	"github.com/lwmacct/260829-go-hsr-identity/pkg/identity/account"
	"github.com/lwmacct/260829-go-hsr-identity/pkg/identity/httpauth"
	"github.com/lwmacct/260829-go-hsr-identity/pkg/identity/password"
	"github.com/lwmacct/260829-go-hsr-identity/pkg/identity/session"
	"github.com/lwmacct/260829-go-hsr-identity/pkg/identity/sqlstore"
	"github.com/lwmacct/260829-go-hsr-identity/pkg/identity/testkit"
	_ "modernc.org/sqlite"
)

func TestSQLiteLifecycle(t *testing.T) {
	sqlDB, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer sqlDB.Close()
	if err := testkit.ApplySchema(context.Background(), sqlDB); err != nil {
		t.Fatal(err)
	}
	if err := testkit.ApplySchema(context.Background(), sqlDB); err != nil {
		t.Fatal(err)
	}
	store := sqlstore.New(sqlDB)
	users, err := identity.New(identity.Options{Users: store, Transactions: store, Now: func() time.Time { return time.Unix(100, 0).UTC() }})
	if err != nil {
		t.Fatal(err)
	}
	passwords, err := password.New(password.Options{Credentials: store, Users: store, UserUpdates: store, Policy: password.Policy{MinLength: 8, MaxLength: 64}, Now: func() time.Time { return time.Unix(100, 0).UTC() }})
	if err != nil {
		t.Fatal(err)
	}
	accounts, err := account.New(account.Options{Users: users, Passwords: passwords, Transactions: store})
	if err != nil {
		t.Fatal(err)
	}
	user, err := accounts.Register(context.Background(), identity.UserCreateInput{Handle: "Alice", DisplayName: "Alice"}, "correct horse")
	if err != nil {
		t.Fatal(err)
	}
	if user.Handle != "alice" {
		t.Fatalf("handle=%q", user.Handle)
	}
	if _, err := users.Create(context.Background(), identity.UserCreateInput{Handle: "alice"}); !errors.Is(err, identity.ErrHandleTaken) {
		t.Fatalf("duplicate handle err=%v", err)
	}
	if _, err := users.Create(context.Background(), identity.UserCreateInput{ID: user.ID, Handle: "other"}); !errors.Is(err, identity.ErrConflict) || errors.Is(err, identity.ErrHandleTaken) {
		t.Fatalf("duplicate id err=%v", err)
	}
	if listed, total, err := users.Users(context.Background(), identity.UserFilter{Page: 1, PageSize: 10}); err != nil || total != 1 || len(listed) != 1 {
		t.Fatalf("list users=%d/%d err=%v", len(listed), total, err)
	}
	if listed, total, err := users.Users(context.Background(), identity.UserFilter{Keyword: "ali", State: identity.StateActive, Page: 0, PageSize: 0}); err != nil || total != 1 || len(listed) != 1 {
		t.Fatalf("filtered users=%d/%d err=%v", len(listed), total, err)
	}
	if _, err := passwords.Authenticate(context.Background(), "ALICE", "correct horse"); err != nil {
		t.Fatal(err)
	}
	if err := accounts.ChangePassword(context.Background(), user.ID, user.Handle, "correct horse", "new correct horse"); err != nil {
		t.Fatalf("change password: %v", err)
	}
	if _, err := passwords.Authenticate(context.Background(), "ALICE", "new correct horse"); err != nil {
		t.Fatalf("authenticate changed password: %v", err)
	}
	sessions, err := session.New(session.Options{Repository: store, Users: store, Binding: session.IPBinding{}, TTL: time.Hour, TouchInterval: time.Minute, Now: func() time.Time { return time.Unix(100, 0).UTC() }})
	if err != nil {
		t.Fatal(err)
	}
	token, record, err := sessions.Create(context.Background(), user.ID, identity.RequestMeta{ClientIP: "127.0.0.1", UserAgent: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if record.ID == "" || record.ID == identity.SessionID(token) {
		t.Fatalf("invalid session id: %q", record.ID)
	}
	principal, err := sessions.Resolve(context.Background(), token, identity.RequestMeta{ClientIP: "127.0.0.1", UserAgent: "test"})
	if err != nil || !principal.Active() {
		t.Fatalf("resolve principal=%#v err=%v", principal, err)
	}
	if _, err := sessions.Resolve(context.Background(), token, identity.RequestMeta{ClientIP: "127.0.0.2", UserAgent: "test"}); !errors.Is(err, identity.ErrBindingMismatch) {
		t.Fatalf("binding error=%v", err)
	}
	if err := sessions.Revoke(context.Background(), token, "logout", identity.RequestMeta{ClientIP: "127.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := sessions.Resolve(context.Background(), token, identity.RequestMeta{ClientIP: "127.0.0.1"}); err == nil {
		t.Fatal("revoked session resolved")
	}
	if err := users.DeleteUsers(context.Background(), []identity.UserID{user.ID}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetUser(context.Background(), user.ID); !errors.Is(err, identity.ErrNotFound) {
		t.Fatalf("deleted user err=%v", err)
	}
	if _, err := store.GetPasswordCredential(context.Background(), user.ID); !errors.Is(err, identity.ErrNotFound) {
		t.Fatalf("deleted password err=%v", err)
	}
	if _, err := store.GetSessionByTokenHash(context.Background(), identity.HashBytes(token)); !errors.Is(err, identity.ErrNotFound) {
		t.Fatalf("deleted session err=%v", err)
	}
}

func TestHTTPAuthMiddleware(t *testing.T) {
	resolver := resolverFunc(func(context.Context, string, identity.RequestMeta) (*identity.Principal, error) {
		return &identity.Principal{Subject: "u1", User: &identity.User{ID: "u1", Handle: "alice", State: identity.StateActive}}, nil
	})
	config := httpauth.DefaultCookieConfig()
	auth := httpauth.New(resolver, config)
	called := false
	handler := auth.Required(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		if p, ok := httpauth.Principal(r.Context()); !ok || p.Subject != "u1" {
			t.Error("principal missing")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	req.AddCookie(&http.Cookie{Name: config.Name, Value: "sess_token"})
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if !called || res.Code != http.StatusNoContent {
		t.Fatalf("called=%v status=%d", called, res.Code)
	}
}

func TestHTTPRequestMetaAdapter(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "https://example.test/", nil)
	req.RemoteAddr = "192.0.2.10:443"
	req.Header.Set("User-Agent", "identity-test")
	meta, ok := httpauth.RequestMetaFromHTTP(req)
	if !ok || meta.ClientIP != "192.0.2.10" || meta.UserAgent != "identity-test" {
		t.Fatalf("meta=%#v ok=%v", meta, ok)
	}
	if _, err := identity.NormalizeRequestMeta(identity.RequestMeta{ClientIP: "not-an-ip"}); !errors.Is(err, identity.ErrInvalid) || !errors.Is(err, identity.ErrInvalidRequestMeta) {
		t.Fatalf("validation err=%v", err)
	}
}

func TestSessionIdleTimeout(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := testkit.ApplySchema(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	store := sqlstore.New(db)
	users, err := identity.New(identity.Options{Users: store, Now: func() time.Time { return time.Unix(200, 0).UTC() }})
	if err != nil {
		t.Fatal(err)
	}
	user, err := users.Create(context.Background(), identity.UserCreateInput{Handle: "idle"})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(200, 0).UTC()
	sessions, err := session.New(session.Options{Repository: store, Users: store, TTL: time.Hour, IdleTimeout: 10 * time.Minute, TouchInterval: time.Hour, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	token, _, err := sessions.Create(context.Background(), user.ID, identity.RequestMeta{})
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(11 * time.Minute)
	if _, err := sessions.Resolve(context.Background(), token, identity.RequestMeta{}); !errors.Is(err, identity.ErrUnauthenticated) {
		t.Fatalf("idle session err=%v", err)
	}
}

type resolverFunc func(context.Context, string, identity.RequestMeta) (*identity.Principal, error)

func (f resolverFunc) Resolve(ctx context.Context, token string, meta identity.RequestMeta) (*identity.Principal, error) {
	return f(ctx, token, meta)
}
