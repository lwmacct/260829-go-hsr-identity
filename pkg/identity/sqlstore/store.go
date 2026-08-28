// Package sqlstore adapts sqlc-generated queries to identity repositories.
package sqlstore

import (
	"context"
	"database/sql"
	_ "embed"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/lwmacct/260829-go-hsr-identity/pkg/identity"
	identitydb "github.com/lwmacct/260829-go-hsr-identity/pkg/identity/sqlc"
)

// schemaSQL is the sqlc schema source and the install-time schema for a fresh
// database. It is deliberately not a migration runner.
//
//go:embed schema.sql
var schemaSQL string

type Store struct {
	db      dbtx
	queries *identitydb.Queries
	root    *sql.DB
}

type dbtx interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	PrepareContext(context.Context, string) (*sql.Stmt, error)
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func New(db *sql.DB) *Store {
	if db == nil {
		return nil
	}
	return newStore(db, db)
}

func newStore(conn dbtx, root *sql.DB) *Store {
	return &Store{db: conn, queries: identitydb.New(conn), root: root}
}

func (s *Store) Users() identity.UserRepository         { return s }
func (s *Store) Passwords() identity.PasswordRepository { return s }
func (s *Store) Sessions() identity.SessionRepository   { return s }

func ApplySchema(ctx context.Context, db *sql.DB) error {
	if db == nil {
		return errors.New("identity/sqlstore: database is required")
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for _, statement := range strings.Split(schemaSQL, ";") {
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

func ResetSchema(ctx context.Context, db *sql.DB) error {
	if db == nil {
		return errors.New("identity/sqlstore: database is required")
	}
	for _, table := range []string{"identity_sessions", "identity_passwords", "identity_users"} {
		if _, err := db.ExecContext(ctx, "DROP TABLE IF EXISTS "+table); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) WithinTx(ctx context.Context, fn func(context.Context, identity.UnitOfWork) error) error {
	if s == nil || s.db == nil {
		return errors.New("identity/sqlstore: store is not configured")
	}
	if fn == nil {
		return errors.New("identity/sqlstore: transaction callback is required")
	}
	if s.root == nil {
		return errors.New("identity/sqlstore: transaction requires root database")
	}
	tx, err := s.root.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	txStore := newStore(tx, s.root)
	defer func() { _ = tx.Rollback() }()
	if err := fn(ctx, txStore); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) CreateUser(ctx context.Context, in identity.UserCreate) (*identity.User, error) {
	row, err := s.queries.CreateUser(ctx, identitydb.CreateUserParams{ID: string(in.ID), Handle: in.Handle, DisplayName: in.DisplayName, Email: in.Email, AvatarUrl: in.AvatarURL, State: string(in.State), DisabledAt: nullableTime(in.DisabledAt), CreatedAt: in.CreatedAt, UpdatedAt: in.UpdatedAt})
	if err != nil {
		return nil, mapWriteError(err, "handle", in.Handle)
	}
	return userFrom(row), nil
}
func (s *Store) GetUser(ctx context.Context, id identity.UserID) (*identity.User, error) {
	row, err := s.queries.GetUser(ctx, string(id))
	if err != nil {
		return nil, mapReadError(err)
	}
	return userFrom(row), nil
}
func (s *Store) GetUserByHandle(ctx context.Context, handle string) (*identity.User, error) {
	row, err := s.queries.GetUserByHandle(ctx, handle)
	if err != nil {
		return nil, mapReadError(err)
	}
	return userFrom(row), nil
}
func (s *Store) UserByID(ctx context.Context, id identity.UserID) (*identity.User, error) {
	return s.GetUser(ctx, id)
}
func (s *Store) UserByHandle(ctx context.Context, handle string) (*identity.User, error) {
	return s.GetUserByHandle(ctx, handle)
}
func (s *Store) ListUsers(ctx context.Context, filter identity.UserFilter) ([]identity.User, int, error) {
	keyword := strings.TrimSpace(filter.Keyword)
	state := string(filter.State)
	page, pageSize := normalizePage(filter.Page, filter.PageSize)
	count, err := s.queries.CountUsers(ctx, identitydb.CountUsersParams{Keyword: keyword, State: state})
	if err != nil {
		return nil, 0, err
	}
	rows, err := s.queries.ListUsers(ctx, identitydb.ListUsersParams{Keyword: keyword, State: state, PageSize: int32(pageSize), PageOffset: int32((page - 1) * pageSize)})
	if err != nil {
		return nil, 0, err
	}
	users := make([]identity.User, len(rows))
	for i, row := range rows {
		users[i] = *userFrom(row)
	}
	return users, int(count), nil
}

func normalizePage(page, pageSize int) (int, int) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 20
	}
	if pageSize > 100 {
		pageSize = 100
	}
	maxPage := int((int64(1<<31-1) / int64(pageSize)) + 1)
	if page > maxPage {
		page = maxPage
	}
	return page, pageSize
}
func (s *Store) UpdateUserProfile(ctx context.Context, id identity.UserID, patch identity.UserProfilePatch) (*identity.User, error) {
	err := s.queries.UpdateUserProfile(ctx, identitydb.UpdateUserProfileParams{DisplayName: patch.DisplayName, Email: patch.Email, AvatarUrl: patch.AvatarURL, UpdatedAt: patch.UpdatedAt, ID: string(id)})
	if err != nil {
		return nil, err
	}
	return s.GetUser(ctx, id)
}
func (s *Store) UpdateUserState(ctx context.Context, ids []identity.UserID, state identity.State, disabledAt *time.Time, now time.Time) (int64, error) {
	var affected int64
	for _, id := range ids {
		result, err := s.queries.UpdateUserState(ctx, identitydb.UpdateUserStateParams{State: string(state), DisabledAt: nullableTime(disabledAt), UpdatedAt: now, ID: string(id)})
		if err != nil {
			return affected, err
		}
		changed, err := result.RowsAffected()
		if err != nil {
			return affected, err
		}
		affected += changed
	}
	return affected, nil
}
func (s *Store) MarkUserLogin(ctx context.Context, id identity.UserID, now time.Time) error {
	return s.queries.MarkUserLogin(ctx, identitydb.MarkUserLoginParams{LastLoginAt: nullableTime(&now), UpdatedAt: now, ID: string(id)})
}
func (s *Store) DeleteUsers(ctx context.Context, ids []identity.UserID) error {
	for _, id := range ids {
		// Keep deletion semantics independent of the database's foreign-key
		// pragma (SQLite applications commonly leave it disabled). PostgreSQL
		// still enforces the same relationship through ON DELETE CASCADE.
		if err := s.queries.DeleteSessionsForUser(ctx, string(id)); err != nil {
			return err
		}
		if err := s.queries.DeletePasswordCredential(ctx, string(id)); err != nil {
			return err
		}
		if err := s.queries.DeleteUser(ctx, string(id)); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) GetPasswordCredential(ctx context.Context, userID identity.UserID) (*identity.PasswordCredential, error) {
	row, err := s.queries.GetPasswordCredential(ctx, string(userID))
	if err != nil {
		return nil, mapReadError(err)
	}
	return &identity.PasswordCredential{UserID: userID, Scheme: row.Scheme, Hash: row.Hash, PasswordChangedAt: row.PasswordChangedAt, CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt}, nil
}
func (s *Store) UpsertPasswordCredential(ctx context.Context, in identity.PasswordCredential) error {
	err := s.queries.UpsertPasswordCredential(ctx, identitydb.UpsertPasswordCredentialParams{UserID: string(in.UserID), Scheme: in.Scheme, Hash: in.Hash, PasswordChangedAt: in.PasswordChangedAt, CreatedAt: in.CreatedAt, UpdatedAt: in.UpdatedAt})
	if err != nil {
		return mapWriteError(err, "", "")
	}
	return nil
}
func (s *Store) DeletePasswordCredentials(ctx context.Context, ids []identity.UserID) error {
	for _, id := range ids {
		if err := s.queries.DeletePasswordCredential(ctx, string(id)); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) CreateSession(ctx context.Context, in identity.SessionRecord) error {
	err := s.queries.CreateSession(ctx, identitydb.CreateSessionParams{ID: string(in.ID), TokenHash: in.TokenHash, UserID: string(in.UserID), LoginIp: in.LoginIP, LastIp: in.LastIP, BindingHash: in.BindingHash, UserAgentHash: in.UserAgentHash, ExpiresAt: in.ExpiresAt, CreatedAt: in.CreatedAt, LastSeenAt: in.LastSeenAt, RevokedAt: nullableTime(in.RevokedAt), RevokedReason: in.RevokedReason})
	if err != nil {
		return mapWriteError(err, "", "")
	}
	return nil
}
func (s *Store) GetSessionByTokenHash(ctx context.Context, hash []byte) (*identity.SessionRecord, error) {
	row, err := s.queries.GetSessionByTokenHash(ctx, hash)
	if err != nil {
		return nil, mapReadError(err)
	}
	return sessionFrom(row), nil
}
func (s *Store) TouchSession(ctx context.Context, id identity.SessionID, ip string, now time.Time) error {
	return s.queries.TouchSession(ctx, identitydb.TouchSessionParams{LastIp: ip, LastSeenAt: now, ID: string(id)})
}
func (s *Store) RevokeSession(ctx context.Context, id identity.SessionID, reason, ip string, now time.Time) error {
	return s.queries.RevokeSession(ctx, identitydb.RevokeSessionParams{RevokedAt: nullableTime(&now), RevokedReason: reason, LastIp: ip, LastSeenAt: now, ID: string(id)})
}
func (s *Store) DeleteSession(ctx context.Context, id identity.SessionID) error {
	return s.queries.DeleteSession(ctx, string(id))
}
func (s *Store) RevokeSessionsForUsers(ctx context.Context, ids []identity.UserID, reason string, now time.Time) error {
	for _, id := range ids {
		if err := s.queries.RevokeSessionsForUser(ctx, identitydb.RevokeSessionsForUserParams{RevokedAt: nullableTime(&now), RevokedReason: reason, UserID: string(id)}); err != nil {
			return err
		}
	}
	return nil
}
func (s *Store) DeleteSessionsForUsers(ctx context.Context, ids []identity.UserID) error {
	for _, id := range ids {
		if err := s.queries.DeleteSessionsForUser(ctx, string(id)); err != nil {
			return err
		}
	}
	return nil
}

func nullableTime(value *time.Time) sql.NullTime {
	if value == nil {
		return sql.NullTime{}
	}
	return sql.NullTime{Time: *value, Valid: true}
}
func userFrom(row identitydb.IdentityUsers) *identity.User {
	return &identity.User{ID: identity.UserID(row.ID), Handle: row.Handle, DisplayName: row.DisplayName, Email: row.Email, AvatarURL: row.AvatarUrl, State: identity.State(row.State), DisabledAt: nullTime(row.DisabledAt), LastLoginAt: nullTime(row.LastLoginAt), CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt}
}
func sessionFrom(row identitydb.IdentitySessions) *identity.SessionRecord {
	return &identity.SessionRecord{ID: identity.SessionID(row.ID), TokenHash: row.TokenHash, UserID: identity.UserID(row.UserID), LoginIP: row.LoginIp, LastIP: row.LastIp, BindingHash: row.BindingHash, UserAgentHash: row.UserAgentHash, ExpiresAt: row.ExpiresAt, CreatedAt: row.CreatedAt, LastSeenAt: row.LastSeenAt, RevokedAt: nullTime(row.RevokedAt), RevokedReason: row.RevokedReason}
}
func nullTime(value sql.NullTime) *time.Time {
	if !value.Valid {
		return nil
	}
	result := value.Time
	return &result
}
func mapReadError(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return identity.ErrNotFound
	}
	return err
}
func mapWriteError(err error, field, value string) error {
	lower := strings.ToLower(err.Error())
	if strings.Contains(lower, "unique") || strings.Contains(lower, "constraint") {
		if field == "handle" && strings.Contains(lower, "handle") {
			return fmt.Errorf("%w: %s", identity.ErrHandleTaken, value)
		}
		return identity.ErrConflict
	}
	return err
}

var _ identity.UserRepository = (*Store)(nil)
var _ identity.PasswordRepository = (*Store)(nil)
var _ identity.SessionRepository = (*Store)(nil)
var _ identity.UnitOfWork = (*Store)(nil)
var _ identity.TxManager = (*Store)(nil)
