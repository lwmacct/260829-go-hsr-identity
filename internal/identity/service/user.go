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
	tx                domain.TxManager
	username          domain.UsernamePolicy
	now               domain.Clock
	events            domain.EventSink
	deleteParticipant UserDeleteParticipant
}

func NewUserService(repo domain.UserRepository, tx domain.TxManager, username domain.UsernamePolicy, now domain.Clock) (*UserService, error) {
	if repo == nil {
		return nil, errors.New("identity: user repository is required")
	}
	if username == nil {
		username = domain.UsernamePolicyFunc(domain.LowerASCIIUsernamePolicy)
	}
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &UserService{repo: repo, tx: tx, username: username, now: now}, nil
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
	h, e := s.username.Normalize(in.Username)
	if e != nil {
		return nil, e
	}
	display := strings.TrimSpace(in.DisplayName)
	if display == "" {
		display = h
	}
	state := in.State
	if state == "" {
		state = domain.StateActive
	}
	if state != domain.StateActive && state != domain.StateDisabled {
		return nil, domain.ErrInvalidState
	}
	id := uuid.NewV7()
	now := s.now().UTC()
	var disabled *time.Time
	if state == domain.StateDisabled {
		disabled = &now
	}
	user, err := s.repo.CreateUser(ctx, domain.UserCreate{ID: id, Username: h, UsernameKey: domain.UsernameKey(h), DisplayName: display, Email: strings.TrimSpace(in.Email), AvatarURL: strings.TrimSpace(in.AvatarURL), State: state, DisabledAt: disabled, CreatedAt: now, UpdatedAt: now})
	if err == nil {
		emitEvent(ctx, s.events, domain.Event{Type: domain.EventUserCreated, At: now, UserID: user.ID, Username: user.Username})
	}
	return user, err
}
func (s *UserService) CreateWithUniqueUsername(ctx context.Context, in UserCreateInput) (*domain.User, error) {
	base, e := s.username.Normalize(in.Username)
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
	n, e := s.username.Normalize(h)
	if e != nil {
		return nil, e
	}
	return s.repo.GetUserByUsernameKey(ctx, domain.UsernameKey(n))
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
	user, err := s.repo.UpdateUserProfile(ctx, id, domain.UserProfilePatch{DisplayName: strings.TrimSpace(in.DisplayName), Email: strings.TrimSpace(in.Email), AvatarURL: strings.TrimSpace(in.AvatarURL), UpdatedAt: s.now().UTC()})
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
	err = s.tx.WithinTx(ctx, func(c context.Context, u domain.UnitOfWork) error {
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
	if participantTx, ok := s.tx.(domain.TxManagerWithDB); ok {
		var deleted []domain.User
		err := participantTx.WithinTxDB(ctx, func(c context.Context, db bun.IDB, u domain.UnitOfWork) error {
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
	err = s.tx.WithinTx(ctx, func(c context.Context, u domain.UnitOfWork) error {
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

func deleteUsersInUnit(c context.Context, u domain.UnitOfWork, ids []domain.UserID) error {
	if e := u.Sessions().DeleteSessionsForUsers(c, ids); e != nil {
		return e
	}
	if e := u.Passwords().DeletePasswordCredentials(c, ids); e != nil {
		return e
	}
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

type UserCreateInput = domain.UserCreateInput
type UserUpdateProfileInput = domain.UserUpdateProfileInput
