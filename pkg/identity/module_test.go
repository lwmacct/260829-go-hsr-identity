package identity_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"github.com/lwmacct/260829-go-hsr-identity/pkg/identity"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/sqlitedialect"
	"github.com/uptrace/bun/driver/sqliteshim"
	"uuid"
)

func testModule(t *testing.T) (*identity.Module, *bun.DB) {
	t.Helper()
	sqlDB, err := sql.Open(sqliteshim.ShimName, "file:identity-test?mode=memory&cache=shared")
	if err != nil {
		t.Fatal(err)
	}
	sqlDB.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = sqlDB.Close() })
	db := bun.NewDB(sqlDB, sqlitedialect.New())
	t.Cleanup(func() { _ = db.Close() })
	if err := identity.ApplySchema(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	m, err := identity.New(identity.Options{DB: db, Clock: func() time.Time { return time.Unix(100, 0).UTC() }, Password: identity.PasswordOptions{Policy: identity.PasswordPolicy{MinLength: 8, MaxLength: 64, RejectLoginIdentifier: true}}, Session: identity.SessionOptions{Binding: identity.IPBinding{}}, HTTP: identity.HTTPOptions{LoginEnabled: true, RegistrationEnabled: true}})
	if err != nil {
		t.Fatal(err)
	}
	return m, db
}

func TestModuleLifecycle(t *testing.T) {
	m, db := testModule(t)
	ctx := context.Background()
	u, err := m.RegisterUser(ctx, identity.UserCreateInput{Username: "alice", DisplayName: "Alice"}, "correct horse")
	if err != nil {
		t.Fatal(err)
	}
	if u.Username != "alice" {
		t.Fatalf("username = %q", u.Username)
	}
	if _, err := m.RegisterUser(ctx, identity.UserCreateInput{Username: "alice"}, "correct horse"); !errors.Is(err, identity.ErrUsernameTaken) && !errors.Is(err, identity.ErrConflict) {
		t.Fatalf("duplicate username err = %v", err)
	}
	if _, err := m.Authenticate(ctx, "alice", "correct horse"); err != nil {
		t.Fatal(err)
	}
	issued, err := m.CreateSession(ctx, u.ID, identity.RequestMeta{ClientIP: "127.0.0.1", UserAgent: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if issued.Token == "" || issued.Session.ID == (identity.SessionID{}) {
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

func TestModuleDeleteUsersCallsDeleteParticipant(t *testing.T) {
	_, db := testModule(t)
	ctx := context.Background()
	var got []identity.User
	m, err := identity.New(identity.Options{
		DB:       db,
		Password: identity.PasswordOptions{Policy: identity.PasswordPolicy{MinLength: 8}},
		DeleteParticipant: func(_ context.Context, tx bun.IDB, users []identity.User) error {
			if tx == nil {
				t.Fatal("delete transaction is nil")
			}
			got = append(got, users...)
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
	if len(got) != 1 || got[0].ID != u.ID {
		t.Fatalf("delete participant users = %#v, want [%s]", got, u.ID)
	}
}

func TestModuleDeleteUsersEmitsEventAfterCommit(t *testing.T) {
	_, db := testModule(t)
	ctx := context.Background()
	var observed identity.Event
	var visibleAfterCommit bool
	m, err := identity.New(identity.Options{
		DB:       db,
		Password: identity.PasswordOptions{Policy: identity.PasswordPolicy{MinLength: 8}},
		Events: identity.EventSinkFunc(func(observerCtx context.Context, event identity.Event) {
			if event.Type != identity.EventUserDeleted {
				return
			}
			observed = event
			var count int
			if err := db.NewRaw("SELECT count(*) FROM identity_users WHERE id = ?", event.UserID.String()).Scan(observerCtx, &count); err != nil {
				t.Fatalf("query committed user deletion: %v", err)
			}
			visibleAfterCommit = count == 0
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	user, err := m.RegisterUser(ctx, identity.UserCreateInput{Username: "after-delete"}, "correct horse")
	if err != nil {
		t.Fatal(err)
	}
	if err := m.DeleteUsers(ctx, []identity.UserID{user.ID}); err != nil {
		t.Fatal(err)
	}
	if observed.UserID != user.ID || observed.Username != user.Username || !visibleAfterCommit {
		t.Fatalf("observer user=%#v committed=%v", observed, visibleAfterCommit)
	}
}

func TestModuleDeleteUsersRollsBackWhenDeleteParticipantFails(t *testing.T) {
	_, db := testModule(t)
	ctx := context.Background()
	want := errors.New("dependent cleanup failed")
	var observed []identity.Event
	m, err := identity.New(identity.Options{
		DB:       db,
		Password: identity.PasswordOptions{Policy: identity.PasswordPolicy{MinLength: 8}},
		DeleteParticipant: func(context.Context, bun.IDB, []identity.User) error {
			return want
		},
		Events: identity.EventSinkFunc(func(_ context.Context, event identity.Event) {
			observed = append(observed, event)
		}),
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
	for _, event := range observed {
		if event.Type == identity.EventUserDeleted {
			t.Fatal("delete event ran after a rolled-back deletion")
		}
	}
}

func TestLoginIdentifiersNormalizeAndRemainUnique(t *testing.T) {
	m, _ := testModule(t)
	ctx := context.Background()
	user, err := m.RegisterUser(ctx, identity.UserCreateInput{
		Username: "elodie",
		Phone:    "+8613812345678",
		Email:    "Elodie@Example.com",
	}, "correct horse")
	if err != nil {
		t.Fatal(err)
	}
	if user.Username != "elodie" || user.Phone != "+8613812345678" || user.Email != "elodie@example.com" {
		t.Fatalf("stored identifiers = %#v", user)
	}
	for _, identifier := range []string{"elodie", "+8613812345678", "ELODIE@EXAMPLE.COM"} {
		found, err := m.UserByLoginIdentifier(ctx, identifier)
		if err != nil || found.ID != user.ID {
			t.Fatalf("identifier %q lookup user=%#v err=%v", identifier, found, err)
		}
		if _, _, err := m.Login(ctx, identifier, "correct horse", identity.RequestMeta{ClientIP: "127.0.0.1"}); err != nil {
			t.Fatalf("identifier %q login error = %v", identifier, err)
		}
	}
	duplicates := []struct {
		identifier string
		wantErr    error
	}{
		{"elodie", identity.ErrUsernameTaken},
		{"+8613812345678", identity.ErrPhoneTaken},
		{"elodie@example.com", identity.ErrEmailTaken},
	}
	for _, duplicate := range duplicates {
		identifier := duplicate.identifier
		input := identity.UserCreateInput{Username: "other-user"}
		switch identifier[0] {
		case '+':
			input.Phone = identifier
		case 'e':
			if strings.Contains(identifier, "@") {
				input.Email = identifier
			} else {
				input.Username = identifier
			}
		}
		if _, err := m.RegisterUser(ctx, input, "another horse"); !errors.Is(err, duplicate.wantErr) {
			t.Fatalf("duplicate identifier %q error = %v, want %v", identifier, err, duplicate.wantErr)
		}
	}
	emptyContact, err := m.RegisterUser(ctx, identity.UserCreateInput{Username: "no-contact"}, "another horse")
	if err != nil {
		t.Fatal(err)
	}
	if emptyContact.Phone != "" || emptyContact.Email != "" {
		t.Fatalf("empty contact values = %#v", emptyContact)
	}
	emptyContact2, err := m.RegisterUser(ctx, identity.UserCreateInput{Username: "no-contact-2"}, "another horse")
	if err != nil {
		t.Fatal(err)
	}
	if emptyContact2.Phone != "" || emptyContact2.Email != "" {
		t.Fatalf("second empty contact values = %#v", emptyContact2)
	}
	phone := "+14155552671"
	email := "no-contact@example.com"
	avatar := "https://example.test/avatar.png"
	updated, err := m.UpdateUserProfile(ctx, emptyContact.ID, identity.UserUpdateProfileInput{
		DisplayName: "No Contact Updated",
		Phone:       &phone,
		Email:       &email,
		AvatarURL:   &avatar,
	})
	if err != nil {
		t.Fatal(err)
	}
	if updated.Phone != phone || updated.Email != email || updated.AvatarURL != avatar {
		t.Fatalf("updated contact values = %#v", updated)
	}
	updated, err = m.UpdateUserProfile(ctx, emptyContact.ID, identity.UserUpdateProfileInput{DisplayName: "Display Only"})
	if err != nil {
		t.Fatal(err)
	}
	if updated.Phone != phone || updated.Email != email || updated.AvatarURL != avatar {
		t.Fatalf("display-only update cleared identifiers = %#v", updated)
	}
	clear := ""
	updated, err = m.UpdateUserProfile(ctx, emptyContact.ID, identity.UserUpdateProfileInput{
		DisplayName: "Contacts Cleared",
		Phone:       &clear,
		Email:       &clear,
	})
	if err != nil {
		t.Fatal(err)
	}
	if updated.Phone != "" || updated.Email != "" {
		t.Fatalf("cleared contact values = %#v", updated)
	}
	if _, err := m.RegisterUser(ctx, identity.UserCreateInput{Username: "contact-password", Phone: "+14155552671"}, "+14155552671"); !errors.Is(err, identity.ErrWeakPassword) {
		t.Fatalf("phone-as-password error = %v", err)
	}
	if _, err := m.RegisterUser(ctx, identity.UserCreateInput{Username: "email-password", Email: "password@example.com"}, "password@example.com"); !errors.Is(err, identity.ErrWeakPassword) {
		t.Fatalf("email-as-password error = %v", err)
	}
}

func TestModuleImplementsPublicUserDirectory(t *testing.T) {
	m, _ := testModule(t)
	var users identity.UserDirectory = m
	user, err := users.UserByUsername(context.Background(), "missing-user")
	if user != nil || !errors.Is(err, identity.ErrNotFound) {
		t.Fatalf("public user directory user=%#v err=%v", user, err)
	}
}

func TestUsernameAndContactNormalizationRules(t *testing.T) {
	valid := []string{"a", "alice", "a1", "a_b", "a-b"}
	for _, value := range valid {
		got, err := identity.NormalizeUsername(value)
		if err != nil || got != value {
			t.Fatalf("NormalizeUsername(%q) = %q, %v", value, got, err)
		}
	}
	for _, value := range []string{"", "1alice", "_alice", "alice_", "alice-", "Alice", "alice!"} {
		if _, err := identity.NormalizeUsername(value); !errors.Is(err, identity.ErrInvalidUsername) {
			t.Fatalf("NormalizeUsername(%q) error = %v", value, err)
		}
	}
	for _, value := range []string{"+8613812345678", "+14155552671"} {
		if got, err := identity.NormalizePhone(value); err != nil || got != value {
			t.Fatalf("NormalizePhone(%q) = %q, %v", value, got, err)
		}
	}
	for _, value := range []string{"13800138000", "+86 13800138000", "+01234567"} {
		if _, err := identity.NormalizePhone(value); !errors.Is(err, identity.ErrInvalidPhone) {
			t.Fatalf("NormalizePhone(%q) error = %v", value, err)
		}
	}
	if got, err := identity.NormalizeEmail(" Alice@Example.com "); err != nil || got != "alice@example.com" {
		t.Fatalf("NormalizeEmail = %q, %v", got, err)
	}
	if _, err := identity.NormalizeLoginIdentifier(strings.Repeat("x", 255)); !errors.Is(err, identity.ErrInvalidIdentifier) {
		t.Fatalf("oversized login identifier error = %v", err)
	}
	if got := identity.LoginAttemptKey("Alice@Example.com"); got == "Alice@Example.com" || len(got) != 64 || got != identity.LoginAttemptKey("alice@example.com") {
		t.Fatalf("email login attempt key = %q", got)
	}
	if got := identity.LoginAttemptKey("+8613812345678"); got == "+8613812345678" || len(got) != 64 {
		t.Fatalf("phone login attempt key = %q", got)
	}
	if got := identity.LoginAttemptKey(strings.Repeat("x", 255)); got != "invalid" {
		t.Fatalf("oversized login attempt key = %q", got)
	}
	if got := identity.LoginAttemptKey("not valid"); got != "invalid" {
		t.Fatalf("invalid login attempt key = %q", got)
	}
}

func TestSQLiteDatabaseChecksRejectInvalidUsernameAndPhone(t *testing.T) {
	_, db := testModule(t)
	ctx := context.Background()
	now := time.Unix(100, 0).UTC()
	for i, username := range []string{"1alice", "_alice", "alice_", "Alice", "alice!"} {
		_, err := db.NewRaw(
			"INSERT INTO identity_users (id, username, display_name, avatar_url, state, created_at, updated_at) VALUES (?, ?, ?, '', 'active', ?, ?)",
			uuid.NewV7().String(), username, username, now, now,
		).Exec(ctx)
		if err == nil {
			t.Fatalf("database accepted invalid username %q at case %d", username, i)
		}
	}
	for _, phone := range []string{"13800138000", "+86 13800138000", "+01234567", "+1234567x"} {
		_, err := db.NewRaw(
			"INSERT INTO identity_users (id, username, phone_e164, display_name, avatar_url, state, created_at, updated_at) VALUES (?, ?, ?, ?, '', 'active', ?, ?)",
			uuid.NewV7().String(), "phone-check-"+strings.ReplaceAll(phone, "+", "p"), phone, phone, now, now,
		).Exec(ctx)
		if err == nil {
			t.Fatalf("database accepted invalid phone %q", phone)
		}
	}
}

func TestProvisionUserCreatesExplicitRoles(t *testing.T) {
	m, _ := testModule(t)
	ctx := context.Background()
	if _, err := m.EnsureRole(ctx, identity.RoleInput{Code: "admin", Name: "Administrator", System: true}); err != nil {
		t.Fatal(err)
	}

	user, err := m.ProvisionUser(ctx, identity.UserProvisionInput{
		User:      identity.UserCreateInput{Username: "provisioned"},
		Password:  "correct horse",
		RoleCodes: []string{"admin"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Authenticate(ctx, "provisioned", "correct horse"); err != nil {
		t.Fatal(err)
	}
	roles, err := m.UserRoles(ctx, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(roles) != 1 || roles[0].Code != "admin" {
		t.Fatalf("provisioned user roles = %#v", roles)
	}
}

func TestRegisterUserAssignsConfiguredDefaultRoles(t *testing.T) {
	_, db := testModule(t)
	ctx := context.Background()
	setup := identity.MustNew(identity.Options{DB: db})
	if _, err := setup.EnsureRole(ctx, identity.RoleInput{Code: "user", Name: "User", System: true}); err != nil {
		t.Fatal(err)
	}
	m, err := identity.New(identity.Options{
		DB:            db,
		Authorization: identity.AuthorizationOptions{DefaultRoleCodes: []string{"user"}},
	})
	if err != nil {
		t.Fatal(err)
	}

	user, err := m.RegisterUser(ctx, identity.UserCreateInput{Username: "default-role-user"}, "correct horse")
	if err != nil {
		t.Fatal(err)
	}
	roles, err := m.UserRoles(ctx, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(roles) != 1 || roles[0].Code != "user" {
		t.Fatalf("default roles = %#v", roles)
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

func TestResetPasswordRejectsStoredLoginIdentifiers(t *testing.T) {
	m, _ := testModule(t)
	ctx := context.Background()
	u, err := m.RegisterUser(ctx, identity.UserCreateInput{Username: "same-as-password", Phone: "+14155552671", Email: "same@example.com"}, "correct horse")
	if err != nil {
		t.Fatal(err)
	}
	if err := m.ResetPassword(ctx, u.ID, u.Username); !errors.Is(err, identity.ErrWeakPassword) {
		t.Fatalf("reset password equal to username error = %v", err)
	}
	if err := m.ResetPassword(ctx, u.ID, u.Phone); !errors.Is(err, identity.ErrWeakPassword) {
		t.Fatalf("reset password equal to phone error = %v", err)
	}
	if err := m.ResetPassword(ctx, u.ID, u.Email); !errors.Is(err, identity.ErrWeakPassword) {
		t.Fatalf("reset password equal to email error = %v", err)
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

func TestSQLiteSchemaRejectsMalformedAndNonV7IDs(t *testing.T) {
	_, db := testModule(t)
	ctx := context.Background()
	now := time.Unix(100, 0).UTC()
	cases := []string{
		"not-a-uuid-----7---------------------",
		"00000000-0000-4000-8000-000000000000",
		"00000000-0000-7000-0000-000000000000",
	}
	for _, id := range cases {
		_, err := db.NewRaw(
			"INSERT INTO identity_users (id, username, display_name, avatar_url, state, created_at, updated_at) VALUES (?, 'invalid-user', 'invalid-user', '', 'active', ?, ?)",
			id, now, now,
		).Exec(ctx)
		if err == nil {
			t.Fatalf("invalid UUIDv7 %q was accepted", id)
		}
	}
}

func TestValidateSchemaRejectsMissingAndIncompleteSchema(t *testing.T) {
	sqlDB, err := sql.Open(sqliteshim.ShimName, "file:identity-schema-validation?mode=memory&cache=shared")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })
	db := bun.NewDB(sqlDB, sqlitedialect.New())
	t.Cleanup(func() { _ = db.Close() })
	if err := identity.ValidateSchema(context.Background(), db); err == nil || !strings.Contains(err.Error(), "missing identity_") {
		t.Fatalf("empty schema validation error = %v", err)
	}
	if _, err := db.NewRaw("CREATE TABLE identity_users (id TEXT PRIMARY KEY)").Exec(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := identity.ValidateSchema(context.Background(), db); err == nil || !strings.Contains(err.Error(), "identity_users.username") {
		t.Fatalf("incomplete schema validation error = %v", err)
	}
}

func TestValidateSchemaRejectsWrongIdentityIndexDefinition(t *testing.T) {
	_, db := testModule(t)
	ctx := context.Background()
	if _, err := db.NewRaw("DROP INDEX identity_users_email_uq").Exec(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := db.NewRaw("CREATE INDEX identity_users_email_uq ON identity_users (username)").Exec(ctx); err != nil {
		t.Fatal(err)
	}
	if err := identity.ValidateSchema(ctx, db); err == nil || !strings.Contains(err.Error(), "identity_users_email_uq") {
		t.Fatalf("wrong identity index validation error = %v", err)
	}
}

func TestValidateSchemaRejectsRemovedUsernameKey(t *testing.T) {
	_, db := testModule(t)
	ctx := context.Background()
	if _, err := db.NewRaw("ALTER TABLE identity_users ADD COLUMN username_key TEXT").Exec(ctx); err != nil {
		t.Fatal(err)
	}
	if err := identity.ValidateSchema(ctx, db); err == nil || !strings.Contains(err.Error(), "username_key") {
		t.Fatalf("stale username_key validation error = %v", err)
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
	body := `{"username":"alice","phone":"+14155552671","email":"alice@example.com","password":"correct horse"}`
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

	loginReq := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(`{"identifier":"ALICE@EXAMPLE.COM","password":"correct horse"}`))
	loginReq.Header.Set("Content-Type", "application/json")
	loginRes := httptest.NewRecorder()
	mux.ServeHTTP(loginRes, loginReq)
	if loginRes.Code != http.StatusOK {
		t.Fatalf("email login status = %d body = %s", loginRes.Code, loginRes.Body.String())
	}

	unauth := httptest.NewRequest(http.MethodGet, "/auth/session", nil)
	unauthRes := httptest.NewRecorder()
	mux.ServeHTTP(unauthRes, unauth)
	if unauthRes.Code != http.StatusUnauthorized {
		t.Fatalf("unauth status = %d", unauthRes.Code)
	}
}

func TestSessionManagementHTTPRoutes(t *testing.T) {
	m, _ := testModule(t)
	ctx := context.Background()
	user, err := m.RegisterUser(ctx, identity.UserCreateInput{Username: "session-routes"}, "correct horse")
	if err != nil {
		t.Fatal(err)
	}
	meta := identity.RequestMeta{ClientIP: "127.0.0.1"}
	first, err := m.CreateSession(ctx, user.ID, meta)
	if err != nil {
		t.Fatal(err)
	}
	second, err := m.CreateSession(ctx, user.ID, meta)
	if err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	api := humago.New(mux, huma.DefaultConfig("test", "1.0.0"))
	m.Register(api)

	list := httptest.NewRequest(http.MethodGet, "/auth/sessions", nil)
	list.RemoteAddr = "127.0.0.1:12345"
	list.Header.Set("Authorization", "Bearer "+first.Token)
	listRes := httptest.NewRecorder()
	mux.ServeHTTP(listRes, list)
	if listRes.Code != http.StatusOK {
		t.Fatalf("session list status = %d body = %s", listRes.Code, listRes.Body.String())
	}
	var listed struct {
		Items []struct {
			ID      string `json:"id"`
			Current bool   `json:"current"`
		} `json:"items"`
	}
	if err := json.Unmarshal(listRes.Body.Bytes(), &listed); err != nil {
		t.Fatal(err)
	}
	if len(listed.Items) != 2 {
		t.Fatalf("session list = %#v", listed)
	}
	current := 0
	for _, item := range listed.Items {
		if item.Current {
			current++
		}
	}
	if current != 1 {
		t.Fatalf("current sessions = %d, want 1", current)
	}

	ambiguous := httptest.NewRequest(http.MethodGet, "/auth/session", nil)
	ambiguous.RemoteAddr = "127.0.0.1:12345"
	ambiguous.Header.Set("Cookie", "identity_session="+first.Token)
	ambiguous.Header.Set("Authorization", "Bearer "+second.Token)
	ambiguousRes := httptest.NewRecorder()
	mux.ServeHTTP(ambiguousRes, ambiguous)
	if ambiguousRes.Code != http.StatusUnauthorized {
		t.Fatalf("ambiguous credentials status = %d body = %s", ambiguousRes.Code, ambiguousRes.Body.String())
	}

	revoke := httptest.NewRequest(http.MethodDelete, "/auth/sessions/"+second.Session.ID.String(), nil)
	revoke.RemoteAddr = "127.0.0.1:12345"
	revoke.Header.Set("Authorization", "Bearer "+first.Token)
	revokeRes := httptest.NewRecorder()
	mux.ServeHTTP(revokeRes, revoke)
	if revokeRes.Code != http.StatusNoContent {
		t.Fatalf("session revoke status = %d body = %s", revokeRes.Code, revokeRes.Body.String())
	}
	if _, err := m.ResolveSession(ctx, second.Token, meta); !errors.Is(err, identity.ErrRevoked) {
		t.Fatalf("revoked session error = %v", err)
	}
}

func TestLoginCanBeDisabledAtHTTPBoundary(t *testing.T) {
	_, db := testModule(t)
	m, err := identity.New(identity.Options{
		DB:       db,
		Password: identity.PasswordOptions{Policy: identity.PasswordPolicy{MinLength: 8}},
		HTTP:     identity.HTTPOptions{LoginEnabled: false, RegistrationEnabled: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	api := humago.New(mux, huma.DefaultConfig("test", "1.0.0"))
	m.Register(api)
	req := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(`{"identifier":"nobody","password":"correct horse"}`))
	req.Header.Set("Content-Type", "application/json")
	res := httptest.NewRecorder()
	mux.ServeHTTP(res, req)
	if res.Code != http.StatusForbidden {
		t.Fatalf("disabled login status = %d body = %s", res.Code, res.Body.String())
	}
}

func TestModuleRejectsInsecureSameSiteNoneCookies(t *testing.T) {
	_, db := testModule(t)
	_, err := identity.New(identity.Options{
		DB:       db,
		HTTP:     identity.HTTPOptions{LoginEnabled: true, SameSite: http.SameSiteNoneMode},
		Password: identity.PasswordOptions{Policy: identity.PasswordPolicy{MinLength: 8}},
	})
	if err == nil || !strings.Contains(err.Error(), "SameSite=None") {
		t.Fatalf("insecure SameSite=None error = %v", err)
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
			LoginEnabled:        true,
			RegistrationEnabled: true,
			Challenge: identity.HTTPChallengeOptions{
				Verifier:              testHumanChallengeProvider{},
				RequireOnLogin:        true,
				RequireOnRegistration: true,
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	if got := m.ChallengeConfig(); got.Provider != "image" {
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
		LoginEnabled        bool `json:"loginEnabled"`
		RegistrationEnabled bool `json:"registrationEnabled"`
		Challenge           struct {
			Provider              string `json:"provider"`
			RequireOnLogin        bool   `json:"requireOnLogin"`
			RequireOnRegistration bool   `json:"requireOnRegistration"`
		} `json:"challenge"`
	}
	if err := json.Unmarshal(configRes.Body.Bytes(), &configBody); err != nil {
		t.Fatal(err)
	}
	if !configBody.LoginEnabled || !configBody.RegistrationEnabled || configBody.Challenge.Provider != "image" || !configBody.Challenge.RequireOnLogin || !configBody.Challenge.RequireOnRegistration {
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

func TestSessionManagementLifecycle(t *testing.T) {
	_, db := testModule(t)
	now := time.Unix(2_000, 0).UTC()
	m, err := identity.New(identity.Options{
		DB:       db,
		Clock:    func() time.Time { return now },
		Password: identity.PasswordOptions{Policy: identity.PasswordPolicy{MinLength: 8}},
		Session:  identity.SessionOptions{TTL: time.Hour},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	user, err := m.RegisterUser(ctx, identity.UserCreateInput{Username: "session-owner"}, "correct horse")
	if err != nil {
		t.Fatal(err)
	}
	first, err := m.CreateSession(ctx, user.ID, identity.RequestMeta{ClientIP: "127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Minute)
	second, err := m.CreateSession(ctx, user.ID, identity.RequestMeta{ClientIP: "127.0.0.2"})
	if err != nil {
		t.Fatal(err)
	}
	sessions, err := m.ListUserSessions(ctx, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 2 || sessions[0].ID != second.Session.ID || sessions[1].ID != first.Session.ID {
		t.Fatalf("sessions = %#v", sessions)
	}
	if err := m.RevokeSessionByID(ctx, first.Session.ID, "operator"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.ResolveSession(ctx, first.Token, identity.RequestMeta{ClientIP: "127.0.0.1"}); !errors.Is(err, identity.ErrRevoked) {
		t.Fatalf("revoked session error = %v", err)
	}
	now = second.Session.ExpiresAt
	deleted, err := m.DeleteExpiredSessions(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if deleted != 2 {
		t.Fatalf("deleted expired sessions = %d, want 2", deleted)
	}
}

type testLoginGuard struct {
	allowErr error
	allowed  int
	records  []bool
	attempts []identity.LoginAttempt
}

func (g *testLoginGuard) Allow(_ context.Context, attempt identity.LoginAttempt) error {
	g.allowed++
	g.attempts = append(g.attempts, attempt)
	return g.allowErr
}

func (g *testLoginGuard) Record(_ context.Context, _ identity.LoginAttempt, success bool) {
	g.records = append(g.records, success)
}

func TestLoginGuardRecordsCredentialOutcomes(t *testing.T) {
	_, db := testModule(t)
	guard := &testLoginGuard{}
	m, err := identity.New(identity.Options{
		DB:         db,
		LoginGuard: guard,
		Password:   identity.PasswordOptions{Policy: identity.PasswordPolicy{MinLength: 8}},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := m.RegisterUser(ctx, identity.UserCreateInput{Username: "guard-user"}, "correct horse"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := m.Login(ctx, "guard-user", "wrong horse", identity.RequestMeta{}); !errors.Is(err, identity.ErrUnauthenticated) {
		t.Fatalf("failed login error = %v", err)
	}
	if _, _, err := m.Login(ctx, "guard-user", "correct horse", identity.RequestMeta{}); err != nil {
		t.Fatal(err)
	}
	if guard.allowed != 2 || len(guard.records) != 2 || guard.records[0] || !guard.records[1] {
		t.Fatalf("guard allowed=%d records=%v", guard.allowed, guard.records)
	}
	if len(guard.attempts) != 2 || guard.attempts[0].IdentifierType != identity.LoginIdentifierUsername || guard.attempts[0].IdentifierKey != guard.attempts[1].IdentifierKey {
		t.Fatalf("guard attempts = %#v", guard.attempts)
	}
	if guard.attempts[0].IdentifierKey == "guard-user" || len(guard.attempts[0].IdentifierKey) != 64 {
		t.Fatalf("guard identifier key is not opaque: %#v", guard.attempts[0])
	}
}

func TestLoginGuardBoundsInvalidIdentifiers(t *testing.T) {
	_, db := testModule(t)
	guard := &testLoginGuard{}
	m, err := identity.New(identity.Options{
		DB:         db,
		LoginGuard: guard,
		Password:   identity.PasswordOptions{Policy: identity.PasswordPolicy{MinLength: 8}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := m.Login(context.Background(), strings.Repeat("x", 4096), "wrong horse", identity.RequestMeta{}); !errors.Is(err, identity.ErrUnauthenticated) {
		t.Fatalf("oversized login error = %v", err)
	}
	if len(guard.attempts) != 1 || guard.attempts[0].IdentifierType != identity.LoginIdentifierInvalid || guard.attempts[0].IdentifierKey != "invalid" {
		t.Fatalf("invalid guard attempt = %#v", guard.attempts)
	}
}

func TestLoginGuardDenialSkipsOutcomeRecord(t *testing.T) {
	_, db := testModule(t)
	guard := &testLoginGuard{allowErr: identity.ErrRateLimited}
	m, err := identity.New(identity.Options{
		DB:         db,
		LoginGuard: guard,
		Password:   identity.PasswordOptions{Policy: identity.PasswordPolicy{MinLength: 8}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := m.Login(context.Background(), "guard-user", "correct horse", identity.RequestMeta{}); !errors.Is(err, identity.ErrRateLimited) {
		t.Fatalf("guard denial error = %v", err)
	}
	if guard.allowed != 1 || len(guard.records) != 0 {
		t.Fatalf("guard allowed=%d records=%v", guard.allowed, guard.records)
	}
}

func TestEventsAreCommittedFactsAndObserverPanicsAreIsolated(t *testing.T) {
	_, db := testModule(t)
	var events []identity.Event
	m, err := identity.New(identity.Options{
		DB:       db,
		Password: identity.PasswordOptions{Policy: identity.PasswordPolicy{MinLength: 8}},
		Events: identity.EventSinkFunc(func(_ context.Context, event identity.Event) {
			events = append(events, event)
			if event.Type == identity.EventLoginSucceeded {
				panic("telemetry unavailable")
			}
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	user, err := m.RegisterUser(ctx, identity.UserCreateInput{Username: "event-user"}, "correct horse")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := m.Login(ctx, user.Username, "wrong horse", identity.RequestMeta{}); !errors.Is(err, identity.ErrUnauthenticated) {
		t.Fatalf("failed login error = %v", err)
	}
	_, issued, err := m.Login(ctx, user.Username, "correct horse", identity.RequestMeta{})
	if err != nil {
		t.Fatalf("successful login after observer panic = %v", err)
	}
	if _, err := m.ResolveSession(ctx, issued.Token, identity.RequestMeta{}); err != nil {
		t.Fatalf("committed session after observer panic = %v", err)
	}
	got := make([]identity.EventType, len(events))
	for i := range events {
		got[i] = events[i].Type
	}
	want := []identity.EventType{
		identity.EventUserCreated,
		identity.EventLoginFailed,
		identity.EventSessionCreated,
		identity.EventLoginSucceeded,
	}
	if !slices.Equal(got, want) {
		t.Fatalf("events = %v, want %v", got, want)
	}
}

func TestAdminAuthorizerAndResetPolicy(t *testing.T) {
	_, db := testModule(t)
	var actions []string
	m, err := identity.New(identity.Options{
		DB:       db,
		Password: identity.PasswordOptions{Policy: identity.PasswordPolicy{MinLength: 8, RejectLoginIdentifier: true}},
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
	reset := httptest.NewRequest(http.MethodPost, "/admin/users/"+target.ID.String()+"/password/reset", strings.NewReader(body))
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
			LoginEnabled:        true,
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
