package repository

import (
	"errors"
	"testing"

	"github.com/lwmacct/260829-go-hsr-identity/pkg/identity/domain"
)

type testPostgresError map[byte]string

func (e testPostgresError) Error() string         { return "postgres constraint error" }
func (e testPostgresError) Field(key byte) string { return e[key] }

type testSQLiteError struct{ code int }

func (e testSQLiteError) Error() string { return "sqlite constraint error" }
func (e testSQLiteError) Code() int     { return e.code }

func TestMapUserWriteErrorUsesPostgresConstraintName(t *testing.T) {
	cases := []struct {
		constraint string
		want       error
	}{
		{constraint: "identity_users_username_uq", want: domain.ErrUsernameTaken},
		{constraint: "identity_users_phone_uq", want: domain.ErrPhoneTaken},
		{constraint: "identity_users_email_uq", want: domain.ErrEmailTaken},
		{constraint: "other_unique_constraint", want: domain.ErrConflict},
	}
	for _, tc := range cases {
		err := mapUserWriteError(testPostgresError{'C': "23505", 'n': tc.constraint})
		if !errors.Is(err, tc.want) {
			t.Fatalf("constraint %q mapped to %v, want %v", tc.constraint, err, tc.want)
		}
	}
}

func TestMapWriteErrorUsesStructuredConstraintCodes(t *testing.T) {
	if err := mapWriteError(testPostgresError{'C': "23514"}); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("PostgreSQL check constraint error = %v", err)
	}
	if err := mapWriteError(testSQLiteError{code: 19}); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("SQLite constraint error = %v", err)
	}
}
