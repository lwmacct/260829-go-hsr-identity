package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"uuid"

	"github.com/lwmacct/260829-go-hsr-identity/pkg/identity/domain"
	"github.com/uptrace/bun"
)

// UserDeleteParticipant lets a host remove records outside identity while the
// identity delete transaction is still open. The callback must use the
// supplied transaction handle and must not start another transaction.
type UserDeleteParticipant func(context.Context, bun.IDB, []domain.User) error

type UserService struct {
	repo              domain.UserRepository
	contacts          domain.ContactRepository
	tx                TxManager
	now               domain.Clock
	events            domain.EventSink
	deleteParticipant UserDeleteParticipant
}

func NewUserService(repo domain.UserRepository, contacts domain.ContactRepository, tx TxManager, now domain.Clock) (*UserService, error) {
	if repo == nil {
		return nil, errors.New("identity: user repository is required")
	}
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &UserService{repo: repo, contacts: contacts, tx: tx, now: now}, nil
}

func (s *UserService) SetDeleteParticipant(participant UserDeleteParticipant) {
	if s != nil {
		s.deleteParticipant = participant
	}
}

func (s *UserService) SetEventSink(sink domain.EventSink) {
	if s != nil {
		s.events = sink
	}
}

func (s *UserService) Create(ctx context.Context, in UserCreateInput) (*domain.User, error) {
	username, e := domain.NormalizeUsername(in.Username)
	if e != nil {
		return nil, e
	}
	display := strings.TrimSpace(in.DisplayName)
	if display == "" {
		display = username
	}
	state := in.State
	if state == "" {
		state = domain.StateActive
	}
	if state != domain.StateActive && state != domain.StateDisabled {
		return nil, domain.ErrInvalidState
	}
	id := domain.UserID(uuid.NewV7())
	now := s.now().UTC()
	var disabled *time.Time
	if state == domain.StateDisabled {
		disabled = &now
	}
	user, err := s.repo.CreateUser(ctx, domain.UserCreate{ID: id, Username: username, DisplayName: display, AvatarURL: strings.TrimSpace(in.AvatarURL), State: state, DisabledAt: disabled, CreatedAt: now, UpdatedAt: now})
	if err == nil {
		emitEvent(ctx, s.events, domain.Event{Type: domain.EventUserCreated, At: now, UserID: user.ID, Username: user.Username})
	}
	return user, err
}
func (s *UserService) CreateWithUniqueUsername(ctx context.Context, in UserCreateInput) (*domain.User, error) {
	base, e := domain.NormalizeUsername(in.Username)
	if e != nil {
		return nil, e
	}
	for i := 0; i < 100; i++ {
		in.Username = base
		if i > 0 {
			in.Username = fmt.Sprintf("%s-%d", base, i+1)
		}
		u, e := s.Create(ctx, in)
		if e == nil {
			return u, nil
		}
		if !errors.Is(e, domain.ErrUsernameTaken) {
			return nil, e
		}
	}
	return nil, domain.ErrUsernameTaken
}
func (s *UserService) UserByID(ctx context.Context, id domain.UserID) (*domain.User, error) {
	normalized, err := domain.NormalizeUserID(id)
	if err != nil {
		return nil, err
	}
	return s.repo.GetUser(ctx, normalized)
}
func (s *UserService) UserByUsername(ctx context.Context, h string) (*domain.User, error) {
	n, e := domain.NormalizeUsername(h)
	if e != nil {
		return nil, e
	}
	return s.repo.GetUserByLoginIdentifier(ctx, domain.LoginIdentifier{Kind: domain.LoginIdentifierUsername, Value: n})
}
func (s *UserService) UserByPhone(ctx context.Context, phone string) (*domain.User, error) {
	n, err := domain.NormalizePhone(phone)
	if err != nil || n == "" {
		if err != nil {
			return nil, err
		}
		return nil, domain.ErrInvalidPhone
	}
	return s.repo.GetUserByLoginIdentifier(ctx, domain.LoginIdentifier{Kind: domain.LoginIdentifierPhone, Value: n})
}
func (s *UserService) UserByEmail(ctx context.Context, email string) (*domain.User, error) {
	n, err := domain.NormalizeEmail(email)
	if err != nil || n == "" {
		if err != nil {
			return nil, err
		}
		return nil, domain.ErrInvalidEmail
	}
	return s.repo.GetUserByLoginIdentifier(ctx, domain.LoginIdentifier{Kind: domain.LoginIdentifierEmail, Value: n})
}
func (s *UserService) UserByLoginIdentifier(ctx context.Context, raw string) (*domain.User, error) {
	identifier, err := domain.NormalizeLoginIdentifier(raw)
	if err != nil {
		return nil, err
	}
	return s.repo.GetUserByLoginIdentifier(ctx, identifier)
}
func (s *UserService) Users(ctx context.Context, f domain.UserFilter) ([]domain.User, int, error) {
	if f.State != "" && f.State != domain.StateActive && f.State != domain.StateDisabled {
		return nil, 0, domain.ErrInvalidState
	}
	return s.repo.ListUsers(ctx, f)
}
func (s *UserService) UpdateProfile(ctx context.Context, id domain.UserID, in UserUpdateProfileInput) (*domain.User, error) {
	if strings.TrimSpace(in.DisplayName) == "" {
		return nil, domain.ErrInvalidUser
	}
	var err error
	if id, err = domain.NormalizeUserID(id); err != nil {
		return nil, err
	}
	avatarURL := normalizeOptionalText(in.AvatarURL)
	user, err := s.repo.UpdateUserProfile(ctx, id, domain.UserProfilePatch{DisplayName: strings.TrimSpace(in.DisplayName), AvatarURL: avatarURL, UpdatedAt: s.now().UTC()})
	if err == nil {
		emitEvent(ctx, s.events, domain.Event{Type: domain.EventUserUpdated, At: user.UpdatedAt, UserID: user.ID, Username: user.Username})
	}
	return user, err
}
func (s *UserService) SetState(ctx context.Context, ids []domain.UserID, state domain.State) error {
	if len(ids) == 0 {
		return domain.ErrEmptySelection
	}
	if state != domain.StateActive && state != domain.StateDisabled {
		return domain.ErrInvalidState
	}
	var err error
	if ids, err = normalizeUserIDs(ids); err != nil {
		return err
	}
	now := s.now().UTC()
	var disabled *time.Time
	if state == domain.StateDisabled {
		disabled = &now
	}
	if s.tx == nil {
		return errors.New("identity: transaction manager is required for state changes")
	}
	err = s.tx.WithinTx(ctx, func(c context.Context, u UnitOfWork) error {
		updated, e := u.Users().UpdateUserState(c, ids, state, disabled, now)
		if e != nil {
			return e
		}
		if updated != int64(len(ids)) {
			return domain.ErrNotFound
		}
		if state == domain.StateDisabled {
			return u.Sessions().RevokeSessionsForUsers(c, ids, "user_disabled", now)
		}
		return nil
	})
	if err == nil {
		for _, id := range ids {
			emitEvent(ctx, s.events, domain.Event{Type: domain.EventUserStateChanged, At: now, UserID: id, Attributes: map[string]string{"state": string(state)}})
			if state == domain.StateDisabled {
				emitEvent(ctx, s.events, domain.Event{Type: domain.EventUserSessionsRevoked, At: now, UserID: id, Attributes: map[string]string{"reason": "user_disabled"}})
			}
		}
	}
	return err
}
func (s *UserService) MarkLogin(ctx context.Context, id domain.UserID) error {
	var err error
	if id, err = domain.NormalizeUserID(id); err != nil {
		return err
	}
	return s.repo.MarkUserLogin(ctx, id, s.now().UTC())
}
func (s *UserService) DeleteUsers(ctx context.Context, ids []domain.UserID) error {
	if len(ids) == 0 {
		return domain.ErrEmptySelection
	}
	var err error
	if ids, err = normalizeUserIDs(ids); err != nil {
		return err
	}
	if s.tx == nil {
		return errors.New("identity: transaction manager is required for deleting users")
	}
	if participantTx, ok := s.tx.(TxManagerWithDB); ok {
		var deleted []domain.User
		err := participantTx.WithinTxDB(ctx, func(c context.Context, db bun.IDB, u UnitOfWork) error {
			users := make([]domain.User, 0, len(ids))
			for _, id := range ids {
				user, err := u.Users().GetUser(c, id)
				if err != nil {
					return err
				}
				users = append(users, *user)
			}
			deleted = users
			if s.deleteParticipant != nil {
				if err := s.deleteParticipant(c, db, users); err != nil {
					return err
				}
			}
			return deleteUsersInUnit(c, u, ids)
		})
		if err == nil {
			for _, user := range deleted {
				emitEvent(ctx, s.events, domain.Event{Type: domain.EventUserDeleted, At: s.now().UTC(), UserID: user.ID, Username: user.Username})
			}
		}
		return err
	}
	if s.deleteParticipant != nil {
		return errors.New("identity: delete participant requires a transaction manager with database access")
	}
	err = s.tx.WithinTx(ctx, func(c context.Context, u UnitOfWork) error {
		return deleteUsersInUnit(c, u, ids)
	})
	if err == nil {
		now := s.now().UTC()
		for _, id := range ids {
			emitEvent(ctx, s.events, domain.Event{Type: domain.EventUserDeleted, At: now, UserID: id})
		}
	}
	return err
}

func deleteUsersInUnit(c context.Context, u UnitOfWork, ids []domain.UserID) error {
	return u.Users().DeleteUsers(c, ids)
}

func normalizeUserIDs(ids []domain.UserID) ([]domain.UserID, error) {
	out := make([]domain.UserID, 0, len(ids))
	seen := make(map[domain.UserID]struct{}, len(ids))
	for _, id := range ids {
		normalized, err := domain.NormalizeUserID(id)
		if err != nil {
			return nil, err
		}
		if _, exists := seen[normalized]; exists {
			continue
		}
		seen[normalized] = struct{}{}
		out = append(out, normalized)
	}
	return out, nil
}
func (s *UserService) EnsureActive(u *domain.User) error {
	if u == nil {
		return domain.ErrNotFound
	}
	if !u.Active() {
		return domain.ErrDisabled
	}
	return nil
}

func (s *UserService) LoginIdentifiers(ctx context.Context, id domain.UserID) ([]string, error) {
	if s == nil || s.contacts == nil {
		return nil, errors.New("identity: contact repository is required")
	}
	user, err := s.UserByID(ctx, id)
	if err != nil {
		return nil, err
	}
	contacts, err := s.contacts.ListUserContacts(ctx, id)
	if err != nil {
		return nil, err
	}
	identifiers := []string{user.Username}
	for _, contact := range contacts {
		if contact.VerifiedAt.IsZero() {
			continue
		}
		identifiers = append(identifiers, contact.Value)
	}
	return identifiers, nil
}

type UserCreateInput = domain.UserCreateInput
type UserUpdateProfileInput = domain.UserUpdateProfileInput

func normalizeOptionalText(value *string) *string {
	if value == nil {
		return nil
	}
	normalized := strings.TrimSpace(*value)
	return &normalized
}
