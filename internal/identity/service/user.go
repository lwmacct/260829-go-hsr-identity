package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"uuid"

	"github.com/lwmacct/260829-go-hsr-identity/pkg/identity/domain"
)

type UserService struct {
	repo             domain.UserRepository
	tx               domain.TxManager
	username         domain.UsernamePolicy
	now              domain.Clock
	beforeDeleteHook domain.UserDeleteHook
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

func (s *UserService) SetBeforeDeleteHook(hook domain.UserDeleteHook) {
	if s != nil {
		s.beforeDeleteHook = hook
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
	id := domain.UserID(uuid.NewV7().String())
	now := s.now().UTC()
	var disabled *time.Time
	if state == domain.StateDisabled {
		disabled = &now
	}
	return s.repo.CreateUser(ctx, domain.UserCreate{ID: id, Username: h, DisplayName: display, Email: strings.TrimSpace(in.Email), AvatarURL: strings.TrimSpace(in.AvatarURL), State: state, DisabledAt: disabled, CreatedAt: now, UpdatedAt: now})
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
	return s.repo.GetUserByUsername(ctx, n)
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
	return s.repo.UpdateUserProfile(ctx, id, domain.UserProfilePatch{DisplayName: strings.TrimSpace(in.DisplayName), Email: strings.TrimSpace(in.Email), AvatarURL: strings.TrimSpace(in.AvatarURL), UpdatedAt: s.now().UTC()})
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
	return s.tx.WithinTx(ctx, func(c context.Context, u domain.UnitOfWork) error {
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
	if s.beforeDeleteHook != nil {
		if err := s.beforeDeleteHook(ctx, ids); err != nil {
			return err
		}
	}
	if s.tx == nil {
		return errors.New("identity: transaction manager is required for deleting users")
	}
	return s.tx.WithinTx(ctx, func(c context.Context, u domain.UnitOfWork) error {
		if e := u.Sessions().DeleteSessionsForUsers(c, ids); e != nil {
			return e
		}
		if e := u.Passwords().DeletePasswordCredentials(c, ids); e != nil {
			return e
		}
		return u.Users().DeleteUsers(c, ids)
	})
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
