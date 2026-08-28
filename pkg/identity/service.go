package identity

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"uuid"
)

type Options struct {
	Users        UserRepository
	Transactions TxManager
	IDGenerator  IDGenerator
	HandlePolicy HandlePolicy
	Now          Clock
}

type Service struct {
	users        UserRepository
	transactions TxManager
	idGenerator  IDGenerator
	handlePolicy HandlePolicy
	now          Clock
}

func New(options Options) (*Service, error) {
	if options.Users == nil {
		return nil, errors.New("identity: user repository is required")
	}
	if options.IDGenerator == nil {
		options.IDGenerator = func() (UserID, error) { return UserID(uuid.NewV7().String()), nil }
	}
	if options.HandlePolicy == nil {
		options.HandlePolicy = HandlePolicyFunc(LowerASCIIHandlePolicy)
	}
	if options.Now == nil {
		options.Now = func() time.Time { return time.Now().UTC() }
	}
	return &Service{users: options.Users, transactions: options.Transactions, idGenerator: options.IDGenerator, handlePolicy: options.HandlePolicy, now: options.Now}, nil
}

func MustNew(options Options) *Service {
	service, err := New(options)
	if err != nil {
		panic(err)
	}
	return service
}

func (s *Service) WithUsers(users UserRepository) *Service {
	if s == nil {
		return nil
	}
	copy := *s
	copy.users = users
	return &copy
}

func (s *Service) Create(ctx context.Context, input UserCreateInput) (*User, error) {
	if s == nil || s.users == nil {
		return nil, errors.New("identity: service is not configured")
	}
	handle, err := s.handlePolicy.Normalize(input.Handle)
	if err != nil {
		return nil, err
	}
	displayName := strings.TrimSpace(input.DisplayName)
	if displayName == "" {
		displayName = handle
	}
	state := input.State
	if state == "" {
		state = StateActive
	}
	if state != StateActive && state != StateDisabled {
		return nil, ErrInvalidState
	}
	id := UserID(strings.TrimSpace(string(input.ID)))
	if id == "" {
		id, err = s.idGenerator()
		if err != nil {
			return nil, err
		}
		id = UserID(strings.TrimSpace(string(id)))
		if id == "" {
			return nil, ErrInvalidUser
		}
	}
	now := s.now().UTC()
	var disabledAt *time.Time
	if state == StateDisabled {
		disabledAt = &now
	}
	created, err := s.users.CreateUser(ctx, UserCreate{ID: id, Handle: handle, DisplayName: displayName, Email: strings.TrimSpace(input.Email), AvatarURL: strings.TrimSpace(input.AvatarURL), State: state, DisabledAt: disabledAt, CreatedAt: now, UpdatedAt: now})
	if err != nil {
		return nil, err
	}
	return created, nil
}

type UserCreateInput struct {
	ID          UserID
	Handle      string
	DisplayName string
	Email       string
	AvatarURL   string
	State       State
}

func (s *Service) CreateWithUniqueHandle(ctx context.Context, input UserCreateInput) (*User, error) {
	if s == nil || s.users == nil {
		return nil, errors.New("identity: service is not configured")
	}
	base, err := s.handlePolicy.Normalize(input.Handle)
	if err != nil {
		return nil, err
	}
	for attempt := 0; attempt < 100; attempt++ {
		candidate := base
		if attempt > 0 {
			candidate = fmt.Sprintf("%s-%d", base, attempt+1)
		}
		input.Handle = candidate
		user, createErr := s.Create(ctx, input)
		if createErr == nil {
			return user, nil
		}
		if !errors.Is(createErr, ErrHandleTaken) {
			return nil, createErr
		}
	}
	return nil, ErrHandleTaken
}

func (s *Service) UserByID(ctx context.Context, id UserID) (*User, error) {
	if s == nil || s.users == nil {
		return nil, errors.New("identity: service is not configured")
	}
	if strings.TrimSpace(string(id)) == "" {
		return nil, ErrInvalidUser
	}
	return s.users.GetUser(ctx, UserID(strings.TrimSpace(string(id))))
}

func (s *Service) UserByHandle(ctx context.Context, handle string) (*User, error) {
	if s == nil || s.users == nil {
		return nil, errors.New("identity: service is not configured")
	}
	normalized, err := s.handlePolicy.Normalize(handle)
	if err != nil {
		return nil, err
	}
	return s.users.GetUserByHandle(ctx, normalized)
}

func (s *Service) Users(ctx context.Context, filter UserFilter) ([]User, int, error) {
	if s == nil || s.users == nil {
		return nil, 0, errors.New("identity: service is not configured")
	}
	if filter.State != "" && filter.State != StateActive && filter.State != StateDisabled {
		return nil, 0, ErrInvalidState
	}
	filter.Page, filter.PageSize = normalizePage(filter.Page, filter.PageSize)
	return s.users.ListUsers(ctx, filter)
}

func (s *Service) UpdateProfile(ctx context.Context, id UserID, input UserUpdateProfileInput) (*User, error) {
	if s == nil || s.users == nil {
		return nil, errors.New("identity: service is not configured")
	}
	displayName := strings.TrimSpace(input.DisplayName)
	if displayName == "" {
		return nil, ErrInvalidUser
	}
	return s.users.UpdateUserProfile(ctx, id, UserProfilePatch{DisplayName: displayName, Email: strings.TrimSpace(input.Email), AvatarURL: strings.TrimSpace(input.AvatarURL), UpdatedAt: s.now().UTC()})
}

type UserUpdateProfileInput struct {
	DisplayName string
	Email       string
	AvatarURL   string
}

func (s *Service) SetState(ctx context.Context, ids []UserID, state State) error {
	if s == nil || s.users == nil {
		return errors.New("identity: service is not configured")
	}
	if len(ids) == 0 {
		return ErrEmptySelection
	}
	if state != StateActive && state != StateDisabled {
		return ErrInvalidState
	}
	now := s.now().UTC()
	var disabledAt *time.Time
	if state == StateDisabled {
		disabledAt = &now
	}
	if s.transactions == nil {
		_, err := s.users.UpdateUserState(ctx, ids, state, disabledAt, now)
		return err
	}
	return s.transactions.WithinTx(ctx, func(txctx context.Context, unit UnitOfWork) error {
		if _, err := unit.Users().UpdateUserState(txctx, ids, state, disabledAt, now); err != nil {
			return err
		}
		if state == StateDisabled {
			return unit.Sessions().RevokeSessionsForUsers(txctx, ids, "user_disabled", now)
		}
		return nil
	})
}

func (s *Service) EnsureActive(user *User) error {
	if user == nil {
		return ErrNotFound
	}
	if !user.Active() {
		return ErrDisabled
	}
	return nil
}

func (s *Service) MarkLogin(ctx context.Context, id UserID) error {
	if s == nil || s.users == nil {
		return errors.New("identity: service is not configured")
	}
	return s.users.MarkUserLogin(ctx, id, s.now().UTC())
}

func (s *Service) DeleteUsers(ctx context.Context, ids []UserID) error {
	if s == nil || s.users == nil {
		return errors.New("identity: service is not configured")
	}
	if len(ids) == 0 {
		return ErrEmptySelection
	}
	if s.transactions == nil {
		return s.users.DeleteUsers(ctx, ids)
	}
	return s.transactions.WithinTx(ctx, func(txctx context.Context, unit UnitOfWork) error {
		if err := unit.Sessions().DeleteSessionsForUsers(txctx, ids); err != nil {
			return err
		}
		if err := unit.Passwords().DeletePasswordCredentials(txctx, ids); err != nil {
			return err
		}
		return unit.Users().DeleteUsers(txctx, ids)
	})
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
	return page, pageSize
}

var _ UserDirectory = (*Service)(nil)
