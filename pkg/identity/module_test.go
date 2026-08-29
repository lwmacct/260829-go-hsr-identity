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
	m, err := identity.New(identity.Options{DB: db, Clock: func() time.Time { return time.Unix(100, 0).UTC() }, Password: identity.PasswordOptions{Policy: identity.PasswordPolicy{MinLength: 8, MaxLength: 64, RejectUsername: true}}, Session: identity.SessionOptions{Binding: identity.IPBinding{}}, HTTP: identity.HTTPOptions{RegistrationEnabled: true}})
	if err != nil {
		t.Fatal(err)
	}
	return m, db
}

func TestModuleLifecycle(t *testing.T) {
	m, db := testModule(t)
	ctx := context.Background()
	u, err := m.RegisterUser(ctx, identity.UserCreateInput{Username: "Alice", DisplayName: "Alice"}, "correct horse")
	if err != nil {
		t.Fatal(err)
	}
	if u.Username != "alice" {
		t.Fatalf("username = %q", u.Username)
	}
	if _, err := m.RegisterUser(ctx, identity.UserCreateInput{Username: "alice"}, "correct horse"); !errors.Is(err, identity.ErrUsernameTaken) && !errors.Is(err, identity.ErrConflict) {
		t.Fatalf("duplicate username err = %v", err)
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

func TestModuleDeleteUsersCallsBeforeDeleteHook(t *testing.T) {
	_, db := testModule(t)
	ctx := context.Background()
	var got []identity.UserID
	m, err := identity.New(identity.Options{
		DB:       db,
		Password: identity.PasswordOptions{Policy: identity.PasswordPolicy{MinLength: 8}},
		BeforeDeleteUsers: func(_ context.Context, ids []identity.UserID) error {
			got = append(got, ids...)
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	u, err := m.RegisterUser(ctx, identity.UserCreateInput{Username: "hook-user"}, "correct horse")
	if err != nil {
		t.Fatal(err)
	}
	if err := m.DeleteUsers(ctx, []identity.UserID{u.ID}); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != u.ID {
		t.Fatalf("delete hook ids = %#v, want [%s]", got, u.ID)
	}
}

func TestModuleDeleteUsersAbortsWhenBeforeDeleteHookFails(t *testing.T) {
	_, db := testModule(t)
	ctx := context.Background()
	want := errors.New("dependent cleanup failed")
	m, err := identity.New(identity.Options{
		DB:       db,
		Password: identity.PasswordOptions{Policy: identity.PasswordPolicy{MinLength: 8}},
		BeforeDeleteUsers: func(context.Context, []identity.UserID) error {
			return want
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	u, err := m.RegisterUser(ctx, identity.UserCreateInput{Username: "hook-failure"}, "correct horse")
	if err != nil {
		t.Fatal(err)
	}
	if err := m.DeleteUsers(ctx, []identity.UserID{u.ID}); !errors.Is(err, want) {
		t.Fatalf("delete error = %v, want %v", err, want)
	}
	if _, err := m.UserByID(ctx, u.ID); err != nil {
		t.Fatalf("user after aborted delete = %v", err)
	}
}

func TestBootstrapUserCreatesOnlyUnassignedRole(t *testing.T) {
	m, _ := testModule(t)
	ctx := context.Background()
	if _, err := m.EnsureRole(ctx, identity.RoleInput{Code: "admin", Name: "Administrator", System: true}); err != nil {
		t.Fatal(err)
	}

	admin, err := m.BootstrapUser(ctx, identity.BootstrapInput{
		User:      identity.UserCreateInput{Username: "Admin", DisplayName: "Administrator"},
		Password:  "correct horse",
		RoleCodes: []string{" ADMIN "},
	})
	if err != nil {
		t.Fatal(err)
	}
	if admin.Username != "admin" || admin.DisplayName != "Administrator" {
		t.Fatalf("bootstrapped user = %#v", admin)
	}
	if _, err := m.Authenticate(ctx, "admin", "correct horse"); err != nil {
		t.Fatal(err)
	}
	roles, err := m.UserRoles(ctx, admin.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(roles) != 1 || roles[0].Code != "admin" {
		t.Fatalf("admin roles = %#v", roles)
	}

	if _, err := m.BootstrapUser(ctx, identity.BootstrapInput{
		User:      identity.UserCreateInput{Username: "another-admin"},
		Password:  "correct horse",
		RoleCodes: []string{"admin"},
	}); !errors.Is(err, identity.ErrBootstrapCompleted) {
		t.Fatalf("second bootstrap error = %v", err)
	}
}

func TestBootstrapUserRequiresRole(t *testing.T) {
	m, _ := testModule(t)
	_, err := m.BootstrapUser(context.Background(), identity.BootstrapInput{
		User:     identity.UserCreateInput{Username: "admin"},
		Password: "correct horse",
	})
	if err == nil {
		t.Fatal("bootstrap without a role succeeded")
	}
}

func TestLoginUpdatesLastLoginAndPasswordChangeRevokesSessions(t *testing.T) {
	m, _ := testModule(t)
	ctx := context.Background()
	u, err := m.RegisterUser(ctx, identity.UserCreateInput{Username: "login-user"}, "correct horse")
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
	u, err := m.RegisterUser(ctx, identity.UserCreateInput{Username: "disable-user"}, "correct horse")
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
	u, err := m.RegisterUser(ctx, identity.UserCreateInput{Username: "reset-user"}, "correct horse")
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

func TestResetPasswordUsesStoredUsernamePolicy(t *testing.T) {
	m, _ := testModule(t)
	ctx := context.Background()
	u, err := m.RegisterUser(ctx, identity.UserCreateInput{Username: "same-as-password"}, "correct horse")
	if err != nil {
		t.Fatal(err)
	}
	if err := m.ResetPassword(ctx, u.ID, u.Username); !errors.Is(err, identity.ErrWeakPassword) {
		t.Fatalf("reset password equal to username = %v", err)
	}
}

func TestUserIDsAreUUIDv7(t *testing.T) {
	m, _ := testModule(t)
	u, err := m.RegisterUser(context.Background(), identity.UserCreateInput{Username: "generated-id"}, "correct horse")
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
	// A duplicate username must roll back the second account's password write;
	// the following query confirms only one user exists.
	ctx := context.Background()
	m := identity.MustNew(identity.Options{DB: db, Clock: func() time.Time { return time.Unix(200, 0).UTC() }, Password: identity.PasswordOptions{Policy: identity.PasswordPolicy{MinLength: 8}}})
	if _, err := m.RegisterUser(ctx, identity.UserCreateInput{Username: "bob"}, "correct horse"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.RegisterUser(ctx, identity.UserCreateInput{Username: "bob"}, "another horse"); err == nil {
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
	body := `{"username":"alice","password":"correct horse"}`
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

type testHumanChallengeProvider struct{}

func (testHumanChallengeProvider) Name() string { return "image" }

func (testHumanChallengeProvider) PublicConfig() identity.HumanChallengeConfig {
	return identity.HumanChallengeConfig{Provider: "image"}
}

func (testHumanChallengeProvider) Create(context.Context, identity.RequestMeta) (*identity.HumanChallenge, error) {
	return &identity.HumanChallenge{
		Provider:    "image",
		ChallengeID: "test-challenge",
		Image:       "data:image/png;base64,",
		ExpiresAt:   time.Now().UTC().Add(time.Minute),
	}, nil
}

func (testHumanChallengeProvider) Verify(_ context.Context, response identity.HumanChallengeResponse, _ identity.RequestMeta) error {
	if response.Provider != "image" || response.ChallengeID != "test-challenge" || response.Answer != "2468" {
		return identity.ErrHumanChallengeInvalid
	}
	return nil
}

func TestHumanChallengeRoutesAndModuleContract(t *testing.T) {
	_, db := testModule(t)
	m, err := identity.New(identity.Options{
		DB:       db,
		Password: identity.PasswordOptions{Policy: identity.PasswordPolicy{MinLength: 8}},
		HTTP: identity.HTTPOptions{
			RegistrationEnabled: true,
			ChallengeProvider:   testHumanChallengeProvider{},
			RequireChallenge:    true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	if got := m.ChallengeConfig(); !got.Required || got.Provider != "image" {
		t.Fatalf("challenge config = %#v", got)
	}
	if err := m.VerifyChallenge(context.Background(), identity.HumanChallengeResponse{Provider: "turnstile", Token: "ok"}, identity.RequestMeta{}); !errors.Is(err, identity.ErrHumanChallengeInvalid) {
		t.Fatalf("provider mismatch error = %v", err)
	}

	mux := http.NewServeMux()
	api := humago.New(mux, huma.DefaultConfig("test", "1.0.0"))
	m.Register(api)

	configReq := httptest.NewRequest(http.MethodGet, "/auth/config", nil)
	configRes := httptest.NewRecorder()
	mux.ServeHTTP(configRes, configReq)
	if configRes.Code != http.StatusOK {
		t.Fatalf("config status = %d body = %s", configRes.Code, configRes.Body.String())
	}
	var configBody struct {
		RegistrationEnabled bool `json:"registrationEnabled"`
		Challenge           struct {
			Provider string `json:"provider"`
			Required bool   `json:"required"`
		} `json:"challenge"`
	}
	if err := json.Unmarshal(configRes.Body.Bytes(), &configBody); err != nil {
		t.Fatal(err)
	}
	if !configBody.RegistrationEnabled || configBody.Challenge.Provider != "image" || !configBody.Challenge.Required {
		t.Fatalf("config body = %#v", configBody)
	}

	challengeReq := httptest.NewRequest(http.MethodPost, "/auth/challenges", nil)
	challengeRes := httptest.NewRecorder()
	mux.ServeHTTP(challengeRes, challengeReq)
	if challengeRes.Code != http.StatusOK {
		t.Fatalf("challenge status = %d body = %s", challengeRes.Code, challengeRes.Body.String())
	}

	register := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/auth/register", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		res := httptest.NewRecorder()
		mux.ServeHTTP(res, req)
		return res
	}
	if res := register(`{"username":"challenge-user","password":"correct horse"}`); res.Code != http.StatusUnprocessableEntity {
		t.Fatalf("missing challenge status = %d body = %s", res.Code, res.Body.String())
	}
	if res := register(`{"username":"challenge-user","password":"correct horse","challenge":{"provider":"image","challengeId":"test-challenge","answer":"2468"}}`); res.Code != http.StatusCreated {
		t.Fatalf("valid challenge status = %d body = %s", res.Code, res.Body.String())
	}
}

func TestBearerAuthentication(t *testing.T) {
	m, _ := testModule(t)
	ctx := context.Background()
	u, err := m.RegisterUser(ctx, identity.UserCreateInput{Username: "bearer-user"}, "correct horse")
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
	u, err := m.RegisterUser(context.Background(), identity.UserCreateInput{Username: "idle-user"}, "correct horse")
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
		Password: identity.PasswordOptions{Policy: identity.PasswordPolicy{MinLength: 8, RejectUsername: true}},
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
	for _, code := range []string{identity.ActionUserList, identity.ActionUserResetPassword} {
		if _, err := m.EnsurePermission(ctx, identity.PermissionInput{Code: code, Name: code, System: true}); err != nil {
			t.Fatal(err)
		}
	}
	role, err := m.EnsureRole(ctx, identity.RoleInput{Code: "test-admin", Name: "Test Admin", System: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.SetRolePermissions(ctx, role.ID, []string{identity.ActionUserList, identity.ActionUserResetPassword}); err != nil {
		t.Fatal(err)
	}
	admin, err := m.RegisterUser(ctx, identity.UserCreateInput{Username: "admin-user"}, "correct horse")
	if err != nil {
		t.Fatal(err)
	}
	if err := m.SetUserRoles(ctx, admin.ID, []string{"test-admin"}); err != nil {
		t.Fatal(err)
	}
	target, err := m.RegisterUser(ctx, identity.UserCreateInput{Username: "target-password"}, "correct horse")
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

func TestRBACClaimsAndDefaultRoles(t *testing.T) {
	_, db := testModule(t)
	ctx := context.Background()
	m := identity.MustNew(identity.Options{DB: db, Authorization: identity.AuthorizationOptions{DefaultRoleCodes: []string{"member"}}, Password: identity.PasswordOptions{Policy: identity.PasswordPolicy{MinLength: 8}}})
	if _, err := m.EnsurePermission(ctx, identity.PermissionInput{Code: "relay.read", Name: "Read", System: true}); err != nil {
		t.Fatal(err)
	}
	role, err := m.EnsureRole(ctx, identity.RoleInput{Code: "member", Name: "Member", System: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.SetRolePermissions(ctx, role.ID, []string{"relay.read"}); err != nil {
		t.Fatal(err)
	}
	user, err := m.RegisterUser(ctx, identity.UserCreateInput{Username: "rbac-user"}, "correct horse")
	if err != nil {
		t.Fatal(err)
	}
	issued, err := m.CreateSession(ctx, user.ID, identity.RequestMeta{})
	if err != nil {
		t.Fatal(err)
	}
	principal, err := m.ResolveSession(ctx, issued.Token, identity.RequestMeta{})
	if err != nil {
		t.Fatal(err)
	}
	if !m.HasPermission(principal, "relay.read") || m.HasPermission(principal, "relay.write") {
		t.Fatalf("unexpected claims: %#v", principal.Claims)
	}
	if err := m.Authorize(ctx, principal, "relay.read"); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(m.Authorize(ctx, principal, "relay.write"), identity.ErrForbidden) {
		t.Fatalf("missing permission error = %v", err)
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
	req := httptest.NewRequest(http.MethodPost, "/auth/register", strings.NewReader(`{"username":"cookie-user","password":"correct horse"}`))
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
