package identity_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"github.com/lwmacct/260829-go-hsr-identity/pkg/identity"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/sqlitedialect"
	"github.com/uptrace/bun/driver/sqliteshim"
)

func testModule(t *testing.T) (*identity.Module, *bun.DB) {
	t.Helper()
	sqlDB, err := sql.Open(sqliteshim.ShimName, "file:identity-test?mode=memory&cache=shared")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })
	db := bun.NewDB(sqlDB, sqlitedialect.New())
	t.Cleanup(func() { _ = db.Close() })
	if err := identity.ApplySchema(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	if err := identity.ApplySchema(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	m, err := identity.New(identity.Options{DB: db, Clock: func() time.Time { return time.Unix(100, 0).UTC() }, Password: identity.PasswordOptions{Policy: identity.PasswordPolicy{MinLength: 8, MaxLength: 64, RejectHandle: true}}, Session: identity.SessionOptions{Binding: identity.IPBinding{}}, HTTP: identity.HTTPOptions{RegistrationEnabled: true}})
	if err != nil {
		t.Fatal(err)
	}
	return m, db
}

func TestModuleLifecycle(t *testing.T) {
	m, db := testModule(t)
	ctx := context.Background()
	u, err := m.RegisterUser(ctx, identity.UserCreateInput{Handle: "Alice", DisplayName: "Alice"}, "correct horse")
	if err != nil {
		t.Fatal(err)
	}
	if u.Handle != "alice" {
		t.Fatalf("handle = %q", u.Handle)
	}
	if _, err := m.RegisterUser(ctx, identity.UserCreateInput{Handle: "alice"}, "correct horse"); !errors.Is(err, identity.ErrHandleTaken) && !errors.Is(err, identity.ErrConflict) {
		t.Fatalf("duplicate handle err = %v", err)
	}
	if _, err := m.Authenticate(ctx, "ALICE", "correct horse"); err != nil {
		t.Fatal(err)
	}
	issued, err := m.CreateSession(ctx, u.ID, identity.RequestMeta{ClientIP: "127.0.0.1", UserAgent: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if issued.Token == "" || issued.Session.ID == "" {
		t.Fatalf("issued session = %#v", issued)
	}
	p, err := m.ResolveSession(ctx, issued.Token, identity.RequestMeta{ClientIP: "127.0.0.1", UserAgent: "test"})
	if err != nil || !p.Active() {
		t.Fatalf("principal = %#v err = %v", p, err)
	}
	if _, err := m.ResolveSession(ctx, issued.Token, identity.RequestMeta{ClientIP: "127.0.0.2", UserAgent: "test"}); !errors.Is(err, identity.ErrBindingMismatch) {
		t.Fatalf("binding err = %v", err)
	}
	if err := m.RevokeSession(ctx, issued.Token, "logout", identity.RequestMeta{}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.ResolveSession(ctx, issued.Token, identity.RequestMeta{}); !errors.Is(err, identity.ErrRevoked) {
		t.Fatalf("revoked err = %v", err)
	}
	if err := m.DeleteUsers(ctx, []identity.UserID{u.ID}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.UserByID(ctx, u.ID); !errors.Is(err, identity.ErrNotFound) {
		t.Fatalf("deleted user err = %v", err)
	}
	var passwordCount, sessionCount int
	if err := db.NewRaw("SELECT count(*) FROM identity_passwords").Scan(ctx, &passwordCount); err != nil {
		t.Fatal(err)
	}
	if err := db.NewRaw("SELECT count(*) FROM identity_sessions").Scan(ctx, &sessionCount); err != nil {
		t.Fatal(err)
	}
	if passwordCount != 0 || sessionCount != 0 {
		t.Fatalf("dependent rows after delete: passwords=%d sessions=%d", passwordCount, sessionCount)
	}
}

func TestLoginUpdatesLastLoginAndPasswordChangeRevokesSessions(t *testing.T) {
	m, _ := testModule(t)
	ctx := context.Background()
	u, err := m.RegisterUser(ctx, identity.UserCreateInput{Handle: "login-user"}, "correct horse")
	if err != nil {
		t.Fatal(err)
	}
	_, issued, err := m.Login(ctx, "login-user", "correct horse", identity.RequestMeta{ClientIP: "127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	if u2, err := m.UserByID(ctx, u.ID); err != nil || u2.LastLoginAt == nil {
		t.Fatalf("last login was not recorded: user=%#v err=%v", u2, err)
	}
	if err := m.ChangePassword(ctx, u.ID, "correct horse", "new correct horse"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.ResolveSession(ctx, issued.Token, identity.RequestMeta{ClientIP: "127.0.0.1"}); !errors.Is(err, identity.ErrRevoked) {
		t.Fatalf("old session after password change = %v", err)
	}
}

func TestDisablingUserRevokesSessions(t *testing.T) {
	m, _ := testModule(t)
	ctx := context.Background()
	u, err := m.RegisterUser(ctx, identity.UserCreateInput{Handle: "disable-user"}, "correct horse")
	if err != nil {
		t.Fatal(err)
	}
	issued, err := m.CreateSession(ctx, u.ID, identity.RequestMeta{ClientIP: "127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.SetUserState(ctx, []identity.UserID{u.ID}, identity.StateDisabled); err != nil {
		t.Fatal(err)
	}
	if _, err := m.ResolveSession(ctx, issued.Token, identity.RequestMeta{ClientIP: "127.0.0.1"}); !errors.Is(err, identity.ErrRevoked) {
		t.Fatalf("session after disable = %v", err)
	}
}

func TestResetPasswordRevokesSessions(t *testing.T) {
	m, _ := testModule(t)
	ctx := context.Background()
	u, err := m.RegisterUser(ctx, identity.UserCreateInput{Handle: "reset-user"}, "correct horse")
	if err != nil {
		t.Fatal(err)
	}
	issued, err := m.CreateSession(ctx, u.ID, identity.RequestMeta{ClientIP: "127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.ResetPassword(ctx, u.ID, "new correct horse"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.ResolveSession(ctx, issued.Token, identity.RequestMeta{ClientIP: "127.0.0.1"}); !errors.Is(err, identity.ErrRevoked) {
		t.Fatalf("session after password reset = %v", err)
	}
}

func TestResetPasswordUsesStoredHandlePolicy(t *testing.T) {
	m, _ := testModule(t)
	ctx := context.Background()
	u, err := m.RegisterUser(ctx, identity.UserCreateInput{Handle: "same-as-password"}, "correct horse")
	if err != nil {
		t.Fatal(err)
	}
	if err := m.ResetPassword(ctx, u.ID, u.Handle); !errors.Is(err, identity.ErrWeakPassword) {
		t.Fatalf("reset password equal to handle = %v", err)
	}
}

func TestUserIDsAreUUIDv7(t *testing.T) {
	m, _ := testModule(t)
	u, err := m.RegisterUser(context.Background(), identity.UserCreateInput{Handle: "generated-id"}, "correct horse")
	if err != nil {
		t.Fatal(err)
	}
	if err := identity.ValidateUserID(u.ID); err != nil {
		t.Fatalf("generated ID is not UUIDv7: %v", err)
	}
}

func TestModuleTransactionRollback(t *testing.T) {
	_, db := testModule(t)
	storeSchema := identity.DatabaseSchema()
	_ = storeSchema
	// A duplicate handle must roll back the second account's password write;
	// the following query confirms only one user exists.
	ctx := context.Background()
	m := identity.MustNew(identity.Options{DB: db, Clock: func() time.Time { return time.Unix(200, 0).UTC() }, Password: identity.PasswordOptions{Policy: identity.PasswordPolicy{MinLength: 8}}})
	if _, err := m.RegisterUser(ctx, identity.UserCreateInput{Handle: "bob"}, "correct horse"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.RegisterUser(ctx, identity.UserCreateInput{Handle: "bob"}, "another horse"); err == nil {
		t.Fatal("duplicate registration succeeded")
	}
	var count int
	if err := db.NewRaw("SELECT count(*) FROM identity_passwords").Scan(ctx, &count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("password rows = %d", count)
	}
}

func TestHumaRoutes(t *testing.T) {
	m, _ := testModule(t)
	mux := http.NewServeMux()
	api := humago.New(mux, huma.DefaultConfig("test", "1.0.0"))
	m.Register(api)
	body := `{"handle":"alice","password":"correct horse"}`
	req := httptest.NewRequest(http.MethodPost, "/auth/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	res := httptest.NewRecorder()
	mux.ServeHTTP(res, req)
	if res.Code != http.StatusCreated {
		t.Fatalf("register status = %d body = %s", res.Code, res.Body.String())
	}
	if res.Header().Get("Set-Cookie") == "" {
		t.Fatal("register did not set cookie")
	}
	var response map[string]any
	if err := json.Unmarshal(res.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response["authenticated"] != true {
		t.Fatalf("response = %#v", response)
	}

	protected := httptest.NewRequest(http.MethodGet, "/auth/session", nil)
	protected.Header.Set("Cookie", res.Header().Get("Set-Cookie"))
	protectedRes := httptest.NewRecorder()
	mux.ServeHTTP(protectedRes, protected)
	if protectedRes.Code != http.StatusOK {
		t.Fatalf("session status = %d body = %s", protectedRes.Code, protectedRes.Body.String())
	}

	unauth := httptest.NewRequest(http.MethodGet, "/auth/session", nil)
	unauthRes := httptest.NewRecorder()
	mux.ServeHTTP(unauthRes, unauth)
	if unauthRes.Code != http.StatusUnauthorized {
		t.Fatalf("unauth status = %d", unauthRes.Code)
	}
}

func TestBearerAuthentication(t *testing.T) {
	m, _ := testModule(t)
	ctx := context.Background()
	u, err := m.RegisterUser(ctx, identity.UserCreateInput{Handle: "bearer-user"}, "correct horse")
	if err != nil {
		t.Fatal(err)
	}
	issued, err := m.CreateSession(ctx, u.ID, identity.RequestMeta{ClientIP: "127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	api := humago.New(mux, huma.DefaultConfig("test", "1.0.0"))
	m.Register(api)
	req := httptest.NewRequest(http.MethodGet, "/auth/session", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("Authorization", "Bearer "+issued.Token)
	res := httptest.NewRecorder()
	mux.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("bearer status = %d body = %s", res.Code, res.Body.String())
	}
}

func TestSessionIdleTimeout(t *testing.T) {
	_, db := testModule(t)
	now := time.Unix(1_000, 0).UTC()
	m, err := identity.New(identity.Options{
		DB:       db,
		Clock:    func() time.Time { return now },
		Password: identity.PasswordOptions{Policy: identity.PasswordPolicy{MinLength: 8}},
		Session:  identity.SessionOptions{IdleTimeout: time.Minute},
	})
	if err != nil {
		t.Fatal(err)
	}
	u, err := m.RegisterUser(context.Background(), identity.UserCreateInput{Handle: "idle-user"}, "correct horse")
	if err != nil {
		t.Fatal(err)
	}
	issued, err := m.CreateSession(context.Background(), u.ID, identity.RequestMeta{})
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Minute)
	if _, err := m.ResolveSession(context.Background(), issued.Token, identity.RequestMeta{}); !errors.Is(err, identity.ErrExpired) {
		t.Fatalf("idle session error = %v", err)
	}
}

func TestAdminAuthorizerAndResetPolicy(t *testing.T) {
	_, db := testModule(t)
	var actions []string
	m, err := identity.New(identity.Options{
		DB:       db,
		Password: identity.PasswordOptions{Policy: identity.PasswordPolicy{MinLength: 8, RejectHandle: true}},
		HTTP:     identity.HTTPOptions{EnableAdminRoutes: true},
		Authorizer: func(_ context.Context, _ *identity.Principal, action string) error {
			actions = append(actions, action)
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	admin, err := m.RegisterUser(ctx, identity.UserCreateInput{Handle: "admin-user"}, "correct horse")
	if err != nil {
		t.Fatal(err)
	}
	target, err := m.RegisterUser(ctx, identity.UserCreateInput{Handle: "target-password"}, "correct horse")
	if err != nil {
		t.Fatal(err)
	}
	issued, err := m.CreateSession(ctx, admin.ID, identity.RequestMeta{})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	api := humago.New(mux, huma.DefaultConfig("test", "1.0.0"))
	m.Register(api)

	list := httptest.NewRequest(http.MethodGet, "/admin/users", nil)
	list.Header.Set("Authorization", "Bearer "+issued.Token)
	listRes := httptest.NewRecorder()
	mux.ServeHTTP(listRes, list)
	if listRes.Code != http.StatusOK || len(actions) != 1 || actions[0] != identity.ActionUserList {
		t.Fatalf("admin list status=%d actions=%v body=%s", listRes.Code, actions, listRes.Body.String())
	}

	body := `{"newPassword":"target-password"}`
	reset := httptest.NewRequest(http.MethodPost, "/admin/users/"+string(target.ID)+"/password/reset", strings.NewReader(body))
	reset.Header.Set("Authorization", "Bearer "+issued.Token)
	reset.Header.Set("Content-Type", "application/json")
	resetRes := httptest.NewRecorder()
	mux.ServeHTTP(resetRes, reset)
	if resetRes.Code != http.StatusUnprocessableEntity {
		t.Fatalf("admin reset status=%d body=%s", resetRes.Code, resetRes.Body.String())
	}
	if actions[len(actions)-1] != identity.ActionUserResetPassword {
		t.Fatalf("reset action = %q", actions[len(actions)-1])
	}
}

func TestSessionCookieAttributes(t *testing.T) {
	_, db := testModule(t)
	m, err := identity.New(identity.Options{
		DB:       db,
		Password: identity.PasswordOptions{Policy: identity.PasswordPolicy{MinLength: 8}},
		HTTP: identity.HTTPOptions{
			RegistrationEnabled: true,
			CookiePath:          "/auth",
			SecureCookie:        true,
			SameSite:            http.SameSiteStrictMode,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	api := humago.New(mux, huma.DefaultConfig("test", "1.0.0"))
	m.Register(api)
	req := httptest.NewRequest(http.MethodPost, "/auth/register", strings.NewReader(`{"handle":"cookie-user","password":"correct horse"}`))
	req.Header.Set("Content-Type", "application/json")
	res := httptest.NewRecorder()
	mux.ServeHTTP(res, req)
	cookie := res.Header().Get("Set-Cookie")
	for _, attribute := range []string{"Path=/auth", "HttpOnly", "Secure", "SameSite=Strict"} {
		if !strings.Contains(cookie, attribute) {
			t.Fatalf("cookie %q does not contain %q", cookie, attribute)
		}
	}
}

func TestLogoutClearsInvalidCookie(t *testing.T) {
	m, _ := testModule(t)
	mux := http.NewServeMux()
	api := humago.New(mux, huma.DefaultConfig("test", "1.0.0"))
	m.Register(api)
	req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	req.Header.Set("Cookie", "identity_session=expired-token")
	res := httptest.NewRecorder()
	mux.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("logout status = %d body = %s", res.Code, res.Body.String())
	}
	if cookie := res.Header().Get("Set-Cookie"); !strings.Contains(cookie, "Max-Age=0") {
		t.Fatalf("logout did not clear cookie: %q", cookie)
	}
}
