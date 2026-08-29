package repository

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/lwmacct/260829-go-hsr-identity/pkg/identity/domain"
	"github.com/uptrace/bun"
)

type Store struct {
	db   bun.IDB
	root *bun.DB
}

func NewStore(db bun.IDB) *Store {
	if db == nil {
		return nil
	}
	root, _ := db.(*bun.DB)
	return &Store{db: db, root: root}
}

func (s *Store) Users() domain.UserRepository                  { return s }
func (s *Store) Passwords() domain.PasswordRepository          { return s }
func (s *Store) Sessions() domain.SessionRepository            { return s }
func (s *Store) Authorization() domain.AuthorizationRepository { return s }

func (s *Store) WithinTx(ctx context.Context, fn func(context.Context, domain.UnitOfWork) error) error {
	if s == nil || s.root == nil {
		return errors.New("identity repository: transaction requires root bun database")
	}
	if fn == nil {
		return errors.New("identity repository: transaction callback is required")
	}
	return s.root.RunInTx(ctx, nil, func(txctx context.Context, tx bun.Tx) error {
		return fn(txctx, NewStore(tx))
	})
}

func (s *Store) CreateUser(ctx context.Context, in domain.UserCreate) (*domain.User, error) {
	id, err := domain.NormalizeUserID(in.ID)
	if err != nil {
		return nil, err
	}
	in.ID = id
	m := &UserModel{ID: string(in.ID), Handle: in.Handle, DisplayName: in.DisplayName, Email: in.Email, AvatarURL: in.AvatarURL, State: string(in.State), DisabledAt: in.DisabledAt, CreatedAt: in.CreatedAt, UpdatedAt: in.UpdatedAt}
	if _, err := s.db.NewInsert().Model(m).Exec(ctx); err != nil {
		return nil, mapWriteError(err, true)
	}
	return userFrom(m), nil
}

func (s *Store) GetUser(ctx context.Context, id domain.UserID) (*domain.User, error) {
	m := new(UserModel)
	if err := s.db.NewSelect().Model(m).Where("u.id = ?", string(id)).Scan(ctx); err != nil {
		return nil, mapReadError(err)
	}
	return userFrom(m), nil
}

func (s *Store) GetUserByHandle(ctx context.Context, handle string) (*domain.User, error) {
	m := new(UserModel)
	if err := s.db.NewSelect().Model(m).Where("u.handle = ?", handle).Scan(ctx); err != nil {
		return nil, mapReadError(err)
	}
	return userFrom(m), nil
}

func (s *Store) UserByID(ctx context.Context, id domain.UserID) (*domain.User, error) {
	return s.GetUser(ctx, id)
}

func (s *Store) UserByHandle(ctx context.Context, handle string) (*domain.User, error) {
	return s.GetUserByHandle(ctx, handle)
}

func (s *Store) ListUsers(ctx context.Context, filter domain.UserFilter) ([]domain.User, int, error) {
	q := s.db.NewSelect().Model((*UserModel)(nil))
	q = applyUserFilter(q, filter)
	var total int
	if err := q.ColumnExpr("count(*)").Scan(ctx, &total); err != nil {
		return nil, 0, err
	}
	page, size := normalizePage(filter.Page, filter.PageSize)
	rows := make([]UserModel, 0, size)
	q = s.db.NewSelect().Model(&rows)
	q = applyUserFilter(q, filter)
	if err := q.OrderExpr("u.created_at DESC, u.id DESC").Limit(size).Offset((page - 1) * size).Scan(ctx); err != nil {
		return nil, 0, err
	}
	out := make([]domain.User, len(rows))
	for i := range rows {
		out[i] = *userFrom(&rows[i])
	}
	return out, total, nil
}

func applyUserFilter(q *bun.SelectQuery, filter domain.UserFilter) *bun.SelectQuery {
	if keyword := strings.TrimSpace(filter.Keyword); keyword != "" {
		like := "%" + keyword + "%"
		q = q.Where("(u.handle LIKE ? OR u.display_name LIKE ? OR u.email LIKE ?)", like, like, like)
	}
	if filter.State != "" {
		q = q.Where("u.state = ?", string(filter.State))
	}
	return q
}

func (s *Store) UpdateUserProfile(ctx context.Context, id domain.UserID, p domain.UserProfilePatch) (*domain.User, error) {
	res, err := s.db.NewUpdate().Model((*UserModel)(nil)).Set("display_name = ?", p.DisplayName).Set("email = ?", p.Email).Set("avatar_url = ?", p.AvatarURL).Set("updated_at = ?", p.UpdatedAt).Where("id = ?", string(id)).Exec(ctx)
	if err != nil {
		return nil, mapWriteError(err, false)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return nil, domain.ErrNotFound
	}
	return s.GetUser(ctx, id)
}

func (s *Store) UpdateUserState(ctx context.Context, ids []domain.UserID, state domain.State, disabledAt *time.Time, now time.Time) (int64, error) {
	if len(ids) == 0 {
		return 0, domain.ErrEmptySelection
	}
	values := make([]string, len(ids))
	args := make([]any, 0, len(ids)+3)
	for i, id := range ids {
		values[i] = "?"
		args = append(args, string(id))
	}
	args = append([]any{string(state), disabledAt, now}, args...)
	query := "UPDATE identity_users SET state = ?, disabled_at = ?, updated_at = ? WHERE id IN (" + strings.Join(values, ",") + ")"
	res, err := s.db.NewRaw(query, args...).Exec(ctx)
	if err != nil {
		return 0, mapWriteError(err, false)
	}
	return res.RowsAffected()
}

func (s *Store) MarkUserLogin(ctx context.Context, id domain.UserID, now time.Time) error {
	res, err := s.db.NewUpdate().Model((*UserModel)(nil)).Set("last_login_at = ?", now).Set("updated_at = ?", now).Where("id = ?", string(id)).Exec(ctx)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return domain.ErrNotFound
	}
	return nil
}

func (s *Store) DeleteUsers(ctx context.Context, ids []domain.UserID) error {
	if len(ids) == 0 {
		return domain.ErrEmptySelection
	}
	for _, id := range ids {
		// Delete dependents explicitly as well as declaring ON DELETE CASCADE.
		// This keeps behavior deterministic on SQLite, where foreign-key
		// enforcement is opt-in, and on hosts with legacy schemas.
		if _, err := s.db.NewDelete().Model((*SessionModel)(nil)).Where("user_id = ?", string(id)).Exec(ctx); err != nil {
			return err
		}
		if _, err := s.db.NewDelete().Model((*PasswordModel)(nil)).Where("user_id = ?", string(id)).Exec(ctx); err != nil {
			return err
		}
		res, err := s.db.NewDelete().Model((*UserModel)(nil)).Where("id = ?", string(id)).Exec(ctx)
		if err != nil {
			return err
		}
		n, _ := res.RowsAffected()
		if n == 0 {
			return domain.ErrNotFound
		}
	}
	return nil
}

func (s *Store) GetPasswordCredential(ctx context.Context, id domain.UserID) (*domain.PasswordCredential, error) {
	m := new(PasswordModel)
	if err := s.db.NewSelect().Model(m).Where("ip.user_id = ?", string(id)).Scan(ctx); err != nil {
		return nil, mapReadError(err)
	}
	return &domain.PasswordCredential{UserID: domain.UserID(m.UserID), Scheme: m.Scheme, Hash: m.Hash, PasswordChangedAt: m.PasswordChangedAt, CreatedAt: m.CreatedAt, UpdatedAt: m.UpdatedAt}, nil
}

func (s *Store) UpsertPasswordCredential(ctx context.Context, in domain.PasswordCredential) error {
	id, err := domain.NormalizeUserID(in.UserID)
	if err != nil {
		return err
	}
	in.UserID = id
	m := &PasswordModel{UserID: string(in.UserID), Scheme: in.Scheme, Hash: in.Hash, PasswordChangedAt: in.PasswordChangedAt, CreatedAt: in.CreatedAt, UpdatedAt: in.UpdatedAt}
	if _, err := s.db.NewInsert().Model(m).On("CONFLICT (user_id) DO UPDATE").Set("scheme = EXCLUDED.scheme").Set("hash = EXCLUDED.hash").Set("password_changed_at = EXCLUDED.password_changed_at").Set("updated_at = EXCLUDED.updated_at").Exec(ctx); err != nil {
		return mapWriteError(err, false)
	}
	return nil
}

func (s *Store) DeletePasswordCredentials(ctx context.Context, ids []domain.UserID) error {
	for _, id := range ids {
		if _, err := s.db.NewDelete().Model((*PasswordModel)(nil)).Where("user_id = ?", string(id)).Exec(ctx); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) CreateSession(ctx context.Context, in domain.SessionRecord) error {
	id, err := domain.NormalizeSessionID(in.ID)
	if err != nil {
		return err
	}
	userID, err := domain.NormalizeUserID(in.UserID)
	if err != nil {
		return err
	}
	in.ID, in.UserID = id, userID
	m := &SessionModel{ID: string(in.ID), TokenHash: in.TokenHash, UserID: string(in.UserID), LoginIP: in.LoginIP, LastIP: in.LastIP, BindingHash: in.BindingHash, UserAgentHash: in.UserAgentHash, ExpiresAt: in.ExpiresAt, CreatedAt: in.CreatedAt, LastSeenAt: in.LastSeenAt, RevokedAt: in.RevokedAt, RevokedReason: in.RevokedReason}
	if _, err := s.db.NewInsert().Model(m).Exec(ctx); err != nil {
		return mapWriteError(err, false)
	}
	return nil
}

func (s *Store) GetSessionByTokenHash(ctx context.Context, hash []byte) (*domain.SessionRecord, error) {
	m := new(SessionModel)
	if err := s.db.NewSelect().Model(m).Where("sess.token_hash = ?", hash).Scan(ctx); err != nil {
		return nil, mapReadError(err)
	}
	return sessionFrom(m), nil
}
func (s *Store) TouchSession(ctx context.Context, id domain.SessionID, ip string, now time.Time) error {
	res, err := s.db.NewUpdate().Model((*SessionModel)(nil)).Set("last_ip = ?", ip).Set("last_seen_at = ?", now).Where("id = ?", string(id)).Exec(ctx)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return domain.ErrNotFound
	}
	return nil
}
func (s *Store) RevokeSession(ctx context.Context, id domain.SessionID, reason, ip string, now time.Time) error {
	res, err := s.db.NewUpdate().Model((*SessionModel)(nil)).Set("revoked_at = ?", now).Set("revoked_reason = ?", reason).Set("last_ip = ?", ip).Set("last_seen_at = ?", now).Where("id = ?", string(id)).Exec(ctx)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return domain.ErrNotFound
	}
	return nil
}
func (s *Store) DeleteSession(ctx context.Context, id domain.SessionID) error {
	_, err := s.db.NewDelete().Model((*SessionModel)(nil)).Where("id = ?", string(id)).Exec(ctx)
	return err
}
func (s *Store) RevokeSessionsForUsers(ctx context.Context, ids []domain.UserID, reason string, now time.Time) error {
	if len(ids) == 0 {
		return nil
	}
	marks := make([]string, len(ids))
	args := []any{now, reason}
	for i, id := range ids {
		marks[i] = "?"
		args = append(args, string(id))
	}
	_, err := s.db.NewRaw("UPDATE identity_sessions SET revoked_at = ?, revoked_reason = ? WHERE user_id IN ("+strings.Join(marks, ",")+") AND revoked_at IS NULL", args...).Exec(ctx)
	return err
}
func (s *Store) DeleteSessionsForUsers(ctx context.Context, ids []domain.UserID) error {
	for _, id := range ids {
		if _, err := s.db.NewDelete().Model((*SessionModel)(nil)).Where("user_id = ?", string(id)).Exec(ctx); err != nil {
			return err
		}
	}
	return nil
}

func normalizePage(page, size int) (int, int) {
	if page < 1 {
		page = 1
	}
	if size < 1 {
		size = 20
	}
	if size > 100 {
		size = 100
	}
	return page, size
}
func mapReadError(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return domain.ErrNotFound
	}
	return err
}
func mapWriteError(err error, handle bool) error {
	lower := strings.ToLower(err.Error())
	if strings.Contains(lower, "unique") || strings.Contains(lower, "duplicate") {
		if handle && strings.Contains(lower, "handle") {
			return domain.ErrHandleTaken
		}
		return domain.ErrConflict
	}
	if strings.Contains(lower, "foreign key") || strings.Contains(lower, "check constraint") {
		return domain.ErrConflict
	}
	return err
}
func userFrom(m *UserModel) *domain.User {
	return &domain.User{ID: domain.UserID(m.ID), Handle: m.Handle, DisplayName: m.DisplayName, Email: m.Email, AvatarURL: m.AvatarURL, State: domain.State(m.State), DisabledAt: m.DisabledAt, LastLoginAt: m.LastLoginAt, CreatedAt: m.CreatedAt, UpdatedAt: m.UpdatedAt}
}
func sessionFrom(m *SessionModel) *domain.SessionRecord {
	return &domain.SessionRecord{ID: domain.SessionID(m.ID), TokenHash: append([]byte(nil), m.TokenHash...), UserID: domain.UserID(m.UserID), LoginIP: m.LoginIP, LastIP: m.LastIP, BindingHash: append([]byte(nil), m.BindingHash...), UserAgentHash: append([]byte(nil), m.UserAgentHash...), ExpiresAt: m.ExpiresAt, CreatedAt: m.CreatedAt, LastSeenAt: m.LastSeenAt, RevokedAt: m.RevokedAt, RevokedReason: m.RevokedReason}
}

var _ domain.UserRepository = (*Store)(nil)
var _ domain.PasswordRepository = (*Store)(nil)
var _ domain.SessionRepository = (*Store)(nil)
var _ domain.UnitOfWork = (*Store)(nil)
var _ domain.TxManager = (*Store)(nil)
