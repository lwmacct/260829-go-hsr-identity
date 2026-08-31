package repository

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
	"uuid"

	"github.com/lwmacct/260829-go-hsr-identity/internal/identity/service"
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

func (s *Store) WithinTx(ctx context.Context, fn func(context.Context, service.UnitOfWork) error) error {
	return s.WithinTxDB(ctx, func(txctx context.Context, _ bun.IDB, uow service.UnitOfWork) error {
		return fn(txctx, uow)
	})
}

func (s *Store) WithinTxDB(ctx context.Context, fn func(context.Context, bun.IDB, service.UnitOfWork) error) error {
	if s == nil || s.root == nil {
		return errors.New("identity repository: transaction requires root bun database")
	}
	if fn == nil {
		return errors.New("identity repository: transaction callback is required")
	}
	return s.root.RunInTx(ctx, nil, func(txctx context.Context, tx bun.Tx) error {
		return fn(txctx, tx, NewStore(tx))
	})
}

func (s *Store) CreateUser(ctx context.Context, in domain.UserCreate) (*domain.User, error) {
	id, err := domain.NormalizeUserID(in.ID)
	if err != nil {
		return nil, err
	}
	in.ID = id
	m := &UserModel{
		ID:          in.ID.String(),
		Username:    in.Username,
		PhoneE164:   optionalString(in.Phone),
		DisplayName: in.DisplayName,
		Email:       optionalString(in.Email),
		AvatarURL:   in.AvatarURL,
		State:       string(in.State),
		DisabledAt:  in.DisabledAt,
		CreatedAt:   in.CreatedAt,
		UpdatedAt:   in.UpdatedAt,
	}
	if _, err := s.db.NewInsert().Model(m).Exec(ctx); err != nil {
		return nil, mapUserWriteError(err)
	}
	return userFrom(m), nil
}

func (s *Store) GetUser(ctx context.Context, id domain.UserID) (*domain.User, error) {
	m := new(UserModel)
	if err := s.db.NewSelect().Model(m).Where("u.id = ?", id.String()).Scan(ctx); err != nil {
		return nil, mapReadError(err)
	}
	return userFrom(m), nil
}

func (s *Store) GetUserByLoginIdentifier(ctx context.Context, identifier domain.LoginIdentifier) (*domain.User, error) {
	if err := domain.ValidateLoginIdentifier(identifier); err != nil {
		return nil, err
	}
	m := new(UserModel)
	query := s.db.NewSelect().Model(m)
	switch identifier.Kind {
	case domain.LoginIdentifierUsername:
		query = query.Where("u.username = ?", identifier.Value)
	case domain.LoginIdentifierPhone:
		query = query.Where("u.phone_e164 = ?", identifier.Value)
	case domain.LoginIdentifierEmail:
		query = query.Where("u.email = ?", identifier.Value)
	default:
		return nil, domain.ErrInvalidIdentifier
	}
	if err := query.Scan(ctx); err != nil {
		return nil, mapReadError(err)
	}
	return userFrom(m), nil
}

func (s *Store) UserByID(ctx context.Context, id domain.UserID) (*domain.User, error) {
	return s.GetUser(ctx, id)
}

func (s *Store) UserByLoginIdentifier(ctx context.Context, identifier domain.LoginIdentifier) (*domain.User, error) {
	return s.GetUserByLoginIdentifier(ctx, identifier)
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
		q = q.Where("(u.username LIKE ? OR u.phone_e164 LIKE ? OR u.display_name LIKE ? OR u.email LIKE ?)", like, like, like, like)
	}
	if filter.State != "" {
		q = q.Where("u.state = ?", string(filter.State))
	}
	return q
}

func (s *Store) UpdateUserProfile(ctx context.Context, id domain.UserID, p domain.UserProfilePatch) (*domain.User, error) {
	query := s.db.NewUpdate().Model((*UserModel)(nil)).
		Set("display_name = ?", p.DisplayName).
		Set("updated_at = ?", p.UpdatedAt).
		Where("id = ?", id.String())
	if p.Phone != nil {
		query = query.Set("phone_e164 = ?", nullableStringValue(p.Phone))
	}
	if p.Email != nil {
		query = query.Set("email = ?", nullableStringValue(p.Email))
	}
	if p.AvatarURL != nil {
		query = query.Set("avatar_url = ?", *p.AvatarURL)
	}
	res, err := query.Exec(ctx)
	if err != nil {
		return nil, mapUserWriteError(err)
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
		args = append(args, id.String())
	}
	args = append([]any{string(state), disabledAt, now}, args...)
	query := "UPDATE identity_users SET state = ?, disabled_at = ?, updated_at = ? WHERE id IN (" + strings.Join(values, ",") + ")"
	res, err := s.db.NewRaw(query, args...).Exec(ctx)
	if err != nil {
		return 0, mapWriteError(err)
	}
	return res.RowsAffected()
}

func (s *Store) MarkUserLogin(ctx context.Context, id domain.UserID, now time.Time) error {
	res, err := s.db.NewUpdate().Model((*UserModel)(nil)).Set("last_login_at = ?", now).Set("updated_at = ?", now).Where("id = ?", id.String()).Exec(ctx)
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
		// This keeps behavior deterministic on SQLite and allows the repository
		// contract to remain safe when foreign-key enforcement is unavailable.
		if _, err := s.db.NewDelete().Model((*SessionModel)(nil)).Where("user_id = ?", id.String()).Exec(ctx); err != nil {
			return err
		}
		if _, err := s.db.NewDelete().Model((*PasswordModel)(nil)).Where("user_id = ?", id.String()).Exec(ctx); err != nil {
			return err
		}
		if _, err := s.db.NewDelete().Model((*UserRoleModel)(nil)).Where("user_id = ?", id.String()).Exec(ctx); err != nil {
			return err
		}
		res, err := s.db.NewDelete().Model((*UserModel)(nil)).Where("id = ?", id.String()).Exec(ctx)
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
	if err := s.db.NewSelect().Model(m).Where("ip.user_id = ?", id.String()).Scan(ctx); err != nil {
		return nil, mapReadError(err)
	}
	userIDRaw, _ := uuid.Parse(m.UserID)
	userID := domain.UserID(userIDRaw)
	return &domain.PasswordCredential{UserID: userID, Scheme: m.Scheme, Hash: m.Hash, PasswordChangedAt: m.PasswordChangedAt, CreatedAt: m.CreatedAt, UpdatedAt: m.UpdatedAt}, nil
}

func (s *Store) UpsertPasswordCredential(ctx context.Context, in domain.PasswordCredential) error {
	id, err := domain.NormalizeUserID(in.UserID)
	if err != nil {
		return err
	}
	in.UserID = id
	m := &PasswordModel{UserID: in.UserID.String(), Scheme: in.Scheme, Hash: in.Hash, PasswordChangedAt: in.PasswordChangedAt, CreatedAt: in.CreatedAt, UpdatedAt: in.UpdatedAt}
	if _, err := s.db.NewInsert().Model(m).On("CONFLICT (user_id) DO UPDATE").Set("scheme = EXCLUDED.scheme").Set("hash = EXCLUDED.hash").Set("password_changed_at = EXCLUDED.password_changed_at").Set("updated_at = EXCLUDED.updated_at").Exec(ctx); err != nil {
		return mapWriteError(err)
	}
	return nil
}

func (s *Store) UpdatePasswordCredentialIfMatch(ctx context.Context, id domain.UserID, expectedScheme, expectedHash string, in domain.PasswordCredential) (bool, error) {
	if _, err := domain.NormalizeUserID(id); err != nil {
		return false, err
	}
	res, err := s.db.NewUpdate().Model((*PasswordModel)(nil)).
		Set("scheme = ?", in.Scheme).
		Set("hash = ?", in.Hash).
		Set("password_changed_at = ?", in.PasswordChangedAt).
		Set("updated_at = ?", in.UpdatedAt).
		Where("user_id = ?", id.String()).
		Where("scheme = ?", expectedScheme).
		Where("hash = ?", expectedHash).
		Exec(ctx)
	if err != nil {
		return false, mapWriteError(err)
	}
	updated, err := res.RowsAffected()
	return updated == 1, err
}

func (s *Store) DeletePasswordCredentials(ctx context.Context, ids []domain.UserID) error {
	for _, id := range ids {
		if _, err := s.db.NewDelete().Model((*PasswordModel)(nil)).Where("user_id = ?", id.String()).Exec(ctx); err != nil {
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
	m := &SessionModel{ID: in.ID.String(), TokenHash: in.TokenHash, UserID: in.UserID.String(), LoginIP: in.LoginIP, LastIP: in.LastIP, BindingHash: in.BindingHash, ExpiresAt: in.ExpiresAt, CreatedAt: in.CreatedAt, LastSeenAt: in.LastSeenAt, RevokedAt: in.RevokedAt, RevokedReason: in.RevokedReason}
	if _, err := s.db.NewInsert().Model(m).Exec(ctx); err != nil {
		return mapWriteError(err)
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
func (s *Store) ListSessionsForUser(ctx context.Context, userID domain.UserID) ([]domain.SessionRecord, error) {
	rows := make([]SessionModel, 0)
	if err := s.db.NewSelect().Model(&rows).Where("sess.user_id = ?", userID.String()).OrderExpr("sess.created_at DESC, sess.id DESC").Scan(ctx); err != nil {
		return nil, mapReadError(err)
	}
	out := make([]domain.SessionRecord, len(rows))
	for i := range rows {
		out[i] = *sessionFrom(&rows[i])
	}
	return out, nil
}
func (s *Store) TouchSession(ctx context.Context, id domain.SessionID, ip string, seenBefore, now time.Time) error {
	res, err := s.db.NewUpdate().Model((*SessionModel)(nil)).Set("last_ip = ?", ip).Set("last_seen_at = ?", now).Where("id = ?", id.String()).Where("last_seen_at <= ?", seenBefore).Where("revoked_at IS NULL").Exec(ctx)
	if err != nil {
		return err
	}
	_, _ = res.RowsAffected()
	return nil
}
func (s *Store) RevokeSession(ctx context.Context, id domain.SessionID, reason, ip string, now time.Time) error {
	res, err := s.db.NewUpdate().Model((*SessionModel)(nil)).Set("revoked_at = ?", now).Set("revoked_reason = ?", reason).Set("last_ip = ?", ip).Set("last_seen_at = ?", now).Where("id = ?", id.String()).Exec(ctx)
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
	_, err := s.db.NewDelete().Model((*SessionModel)(nil)).Where("id = ?", id.String()).Exec(ctx)
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
		args = append(args, id.String())
	}
	_, err := s.db.NewRaw("UPDATE identity_sessions SET revoked_at = ?, revoked_reason = ? WHERE user_id IN ("+strings.Join(marks, ",")+") AND revoked_at IS NULL", args...).Exec(ctx)
	return err
}
func (s *Store) DeleteSessionsForUsers(ctx context.Context, ids []domain.UserID) error {
	for _, id := range ids {
		if _, err := s.db.NewDelete().Model((*SessionModel)(nil)).Where("user_id = ?", id.String()).Exec(ctx); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) DeleteExpiredSessions(ctx context.Context, before time.Time) (int64, error) {
	res, err := s.db.NewDelete().Model((*SessionModel)(nil)).Where("expires_at <= ?", before).Exec(ctx)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
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
func mapWriteError(err error) error {
	if code, _, ok := postgresErrorFields(err); ok {
		switch code {
		case "23502", "23503", "23505", "23514", "23P01":
			return domain.ErrConflict
		}
	}
	if sqliteConstraintError(err) {
		return domain.ErrConflict
	}
	lower := strings.ToLower(err.Error())
	if strings.Contains(lower, "unique") || strings.Contains(lower, "duplicate") {
		return domain.ErrConflict
	}
	if strings.Contains(lower, "foreign key") || strings.Contains(lower, "check constraint") {
		return domain.ErrConflict
	}
	return err
}

func mapUserWriteError(err error) error {
	if code, constraint, ok := postgresErrorFields(err); ok {
		switch code {
		case "23505":
			switch constraint {
			case "identity_users_username_uq":
				return domain.ErrUsernameTaken
			case "identity_users_phone_uq":
				return domain.ErrPhoneTaken
			case "identity_users_email_uq":
				return domain.ErrEmailTaken
			default:
				return domain.ErrConflict
			}
		case "23502", "23503", "23514", "23P01":
			return domain.ErrConflict
		}
	}
	lower := strings.ToLower(err.Error())
	switch {
	case strings.Contains(lower, "identity_users_username_uq"), strings.Contains(lower, "identity_users.username"):
		return domain.ErrUsernameTaken
	case strings.Contains(lower, "identity_users_phone_uq"), strings.Contains(lower, "identity_users.phone_e164"):
		return domain.ErrPhoneTaken
	case strings.Contains(lower, "identity_users_email_uq"), strings.Contains(lower, "identity_users.email"):
		return domain.ErrEmailTaken
	case strings.Contains(lower, "unique"), strings.Contains(lower, "duplicate"):
		return domain.ErrConflict
	case strings.Contains(lower, "foreign key"), strings.Contains(lower, "check constraint"):
		return domain.ErrConflict
	default:
		return err
	}
}

type postgresError interface {
	error
	Field(byte) string
}

type sqliteError interface {
	error
	Code() int
}

func postgresErrorFields(err error) (code, constraint string, ok bool) {
	var pgErr postgresError
	if !errors.As(err, &pgErr) {
		return "", "", false
	}
	return pgErr.Field('C'), pgErr.Field('n'), true
}

func sqliteConstraintError(err error) bool {
	var sqliteErr sqliteError
	return errors.As(err, &sqliteErr) && sqliteErr.Code()&0xff == 19
}

func userFrom(m *UserModel) *domain.User {
	idRaw, _ := uuid.Parse(m.ID)
	return &domain.User{ID: domain.UserID(idRaw), Username: m.Username, Phone: stringValue(m.PhoneE164), DisplayName: m.DisplayName, Email: stringValue(m.Email), AvatarURL: m.AvatarURL, State: domain.State(m.State), DisabledAt: m.DisabledAt, LastLoginAt: m.LastLoginAt, CreatedAt: m.CreatedAt, UpdatedAt: m.UpdatedAt}
}

func optionalString(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

func nullableStringValue(value *string) any {
	if value == nil || *value == "" {
		return nil
	}
	return *value
}

func stringValue(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}
func sessionFrom(m *SessionModel) *domain.SessionRecord {
	sessionIDRaw, _ := uuid.Parse(m.ID)
	userIDRaw, _ := uuid.Parse(m.UserID)
	return &domain.SessionRecord{ID: domain.SessionID(sessionIDRaw), TokenHash: append([]byte(nil), m.TokenHash...), UserID: domain.UserID(userIDRaw), LoginIP: m.LoginIP, LastIP: m.LastIP, BindingHash: append([]byte(nil), m.BindingHash...), ExpiresAt: m.ExpiresAt, CreatedAt: m.CreatedAt, LastSeenAt: m.LastSeenAt, RevokedAt: m.RevokedAt, RevokedReason: m.RevokedReason}
}

var _ domain.UserRepository = (*Store)(nil)
var _ domain.PasswordRepository = (*Store)(nil)
var _ domain.SessionRepository = (*Store)(nil)
var _ service.UnitOfWork = (*Store)(nil)
var _ service.TxManager = (*Store)(nil)
var _ service.TxManagerWithDB = (*Store)(nil)
