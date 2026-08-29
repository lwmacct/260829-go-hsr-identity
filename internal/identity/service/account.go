package service

import (
	"context"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/lwmacct/260829-go-hsr-identity/pkg/identity/domain"
)

type AccountService struct {
	users         *UserService
	passwords     *PasswordService
	sessions      *SessionService
	authorization *AuthorizationService
	tx            domain.TxManager
}

func NewAccountService(users *UserService, passwords *PasswordService, sessions *SessionService, authorization *AuthorizationService, tx domain.TxManager) (*AccountService, error) {
	if users == nil || passwords == nil || sessions == nil || authorization == nil || tx == nil {
		return nil, errors.New("identity: account dependencies are required")
	}
	return &AccountService{users: users, passwords: passwords, sessions: sessions, authorization: authorization, tx: tx}, nil
}
func (s *AccountService) Register(ctx context.Context, in UserCreateInput, password string) (*domain.User, error) {
	if e := s.passwords.Validate(in.Handle, password); e != nil {
		return nil, e
	}
	hash, e := s.passwords.Hash(password)
	if e != nil {
		return nil, e
	}
	var u *domain.User
	e = s.tx.WithinTx(ctx, func(c context.Context, uow domain.UnitOfWork) error {
		users, err := s.userService(uow)
		if err != nil {
			return err
		}
		u, e = users.Create(c, in)
		if e != nil {
			return e
		}
		if e = s.authorization.assignDefaultRoles(c, uow, u.ID); e != nil {
			return e
		}
		pw, err := s.passwordService(uow)
		if err != nil {
			return err
		}
		return pw.SetHash(c, u.ID, hash)
	})
	return u, e
}

// BootstrapUser atomically creates the first user for one or more roles. Each
// role must be unassigned; once any requested role has a user, the operation
// fails with ErrBootstrapCompleted rather than changing existing privileges.
func (s *AccountService) BootstrapUser(ctx context.Context, in domain.BootstrapInput) (*domain.User, error) {
	roleCodes, err := normalizeBootstrapRoleCodes(in.RoleCodes)
	if err != nil {
		return nil, err
	}
	if in.User.State != "" && in.User.State != domain.StateActive {
		return nil, domain.ErrInvalidState
	}
	if err := s.passwords.Validate(in.User.Handle, in.Password); err != nil {
		return nil, err
	}
	hash, err := s.passwords.Hash(in.Password)
	if err != nil {
		return nil, err
	}
	var user *domain.User
	err = s.tx.WithinTx(ctx, func(c context.Context, uow domain.UnitOfWork) error {
		roleIDs := make([]domain.RoleID, 0, len(roleCodes))
		for _, code := range roleCodes {
			role, err := uow.Authorization().LockRoleByCode(c, code)
			if err != nil {
				return err
			}
			count, err := uow.Authorization().CountRoleUsers(c, role.ID)
			if err != nil {
				return err
			}
			if count > 0 {
				return domain.ErrBootstrapCompleted
			}
			roleIDs = append(roleIDs, role.ID)
		}

		users, err := s.userService(uow)
		if err != nil {
			return err
		}
		user, err = users.Create(c, in.User)
		if err != nil {
			return err
		}
		passwords, err := s.passwordService(uow)
		if err != nil {
			return err
		}
		if err := passwords.SetHash(c, user.ID, hash); err != nil {
			return err
		}
		return uow.Authorization().ReplaceUserRoles(c, user.ID, roleIDs)
	})
	if err != nil {
		return nil, err
	}
	return user, nil
}

// RegisterAndLogin atomically creates an account, its password, a Session,
// and the first last-login timestamp. The issued token is returned only once.
func (s *AccountService) RegisterAndLogin(ctx context.Context, in UserCreateInput, password string, meta domain.RequestMeta) (*domain.User, *domain.IssuedSession, error) {
	if e := s.passwords.Validate(in.Handle, password); e != nil {
		return nil, nil, e
	}
	hash, e := s.passwords.Hash(password)
	if e != nil {
		return nil, nil, e
	}
	var user *domain.User
	var issued *domain.IssuedSession
	e = s.tx.WithinTx(ctx, func(c context.Context, uow domain.UnitOfWork) error {
		users, err := s.userService(uow)
		if err != nil {
			return err
		}
		user, err = users.Create(c, in)
		if err != nil {
			return err
		}
		if err = s.authorization.assignDefaultRoles(c, uow, user.ID); err != nil {
			return err
		}
		pw, err := s.passwordService(uow)
		if err != nil {
			return err
		}
		if err = pw.SetHash(c, user.ID, hash); err != nil {
			return err
		}
		sessions := s.sessions.withRepositories(uow.Sessions(), domain.DirectoryFromRepository(uow.Users()))
		issued, err = sessions.Create(c, user.ID, meta)
		if err != nil {
			return err
		}
		loginAt := s.users.now().UTC()
		if err = users.MarkLogin(c, user.ID); err != nil {
			return err
		}
		user.LastLoginAt = timePtr(loginAt)
		user.UpdatedAt = loginAt
		return nil
	})
	if e != nil {
		return nil, nil, e
	}
	return user, issued, nil
}

// Login verifies credentials, creates a Session, and records last_login_at in
// one transaction. Callers that only need credential verification should use
// PasswordService.Authenticate through Module.Authenticate.
func (s *AccountService) Login(ctx context.Context, handle, password string, meta domain.RequestMeta) (*domain.User, *domain.IssuedSession, error) {
	var user *domain.User
	var issued *domain.IssuedSession
	err := s.tx.WithinTx(ctx, func(c context.Context, uow domain.UnitOfWork) error {
		pw, err := s.passwordService(uow)
		if err != nil {
			return err
		}
		user, err = pw.Authenticate(c, handle, password)
		if err != nil {
			return err
		}
		sessions := s.sessions.withRepositories(uow.Sessions(), domain.DirectoryFromRepository(uow.Users()))
		issued, err = sessions.Create(c, user.ID, meta)
		if err != nil {
			return err
		}
		users, err := s.userService(uow)
		if err != nil {
			return err
		}
		loginAt := s.users.now().UTC()
		if err = users.MarkLogin(c, user.ID); err != nil {
			return err
		}
		user.LastLoginAt = timePtr(loginAt)
		user.UpdatedAt = loginAt
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	return user, issued, nil
}

// IssueSession creates a session and records last_login_at atomically. It is
// used by external-login flows (OAuth, SSH, etc.) after the host has verified
// the external credential.
func (s *AccountService) IssueSession(ctx context.Context, id domain.UserID, meta domain.RequestMeta) (*domain.IssuedSession, error) {
	var issued *domain.IssuedSession
	err := s.tx.WithinTx(ctx, func(c context.Context, uow domain.UnitOfWork) error {
		users, err := s.userService(uow)
		if err != nil {
			return err
		}
		user, err := users.UserByID(c, id)
		if err != nil {
			return err
		}
		if err = users.EnsureActive(user); err != nil {
			return err
		}
		sessions := s.sessions.withRepositories(uow.Sessions(), domain.DirectoryFromRepository(uow.Users()))
		issued, err = sessions.Create(c, id, meta)
		if err != nil {
			return err
		}
		if err = users.MarkLogin(c, id); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return issued, nil
}

func (s *AccountService) ChangePassword(ctx context.Context, id domain.UserID, current, next string) error {
	return s.tx.WithinTx(ctx, func(c context.Context, u domain.UnitOfWork) error {
		users, err := s.userService(u)
		if err != nil {
			return err
		}
		user, err := users.UserByID(c, id)
		if err != nil {
			return err
		}
		if err = users.EnsureActive(user); err != nil {
			return err
		}
		pw, err := s.passwordService(u)
		if err != nil {
			return err
		}
		if e := pw.AuthenticateUser(c, id, current); e != nil {
			return e
		}
		if e := pw.Validate(user.Handle, next); e != nil {
			return e
		}
		h, e := pw.Hash(next)
		if e != nil {
			return e
		}
		if err = pw.SetHash(c, id, h); err != nil {
			return err
		}
		return u.Sessions().RevokeSessionsForUsers(c, []domain.UserID{id}, "password_changed", s.passwords.Now())
	})
}

func (s *AccountService) ResetPassword(ctx context.Context, id domain.UserID, next string) error {
	return s.tx.WithinTx(ctx, func(c context.Context, u domain.UnitOfWork) error {
		users, err := s.userService(u)
		if err != nil {
			return err
		}
		user, err := users.UserByID(c, id)
		if err != nil {
			return err
		}
		if err = s.passwords.Validate(user.Handle, next); err != nil {
			return err
		}
		h, err := s.passwords.Hash(next)
		if err != nil {
			return err
		}
		pw, err := s.passwordService(u)
		if err != nil {
			return err
		}
		if err = pw.SetHash(c, id, h); err != nil {
			return err
		}
		return u.Sessions().RevokeSessionsForUsers(c, []domain.UserID{id}, "password_reset", s.passwords.Now())
	})
}

func (s *AccountService) userService(uow domain.UnitOfWork) (*UserService, error) {
	return NewUserService(uow.Users(), nil, s.users.handle, s.users.now)
}

func (s *AccountService) passwordService(uow domain.UnitOfWork) (*PasswordService, error) {
	return NewPasswordService(uow.Passwords(), domain.DirectoryFromRepository(uow.Users()), PasswordOptions{Hasher: s.passwords.hasher, Policy: s.passwords.policy}, s.passwords.now, s.passwords.handle)
}

func timePtr(value time.Time) *time.Time { return &value }

func normalizeBootstrapRoleCodes(codes []string) ([]string, error) {
	if len(codes) == 0 {
		return nil, errors.New("identity: at least one bootstrap role is required")
	}
	normalized := make([]string, 0, len(codes))
	seen := make(map[string]struct{}, len(codes))
	for _, code := range codes {
		code = strings.ToLower(strings.TrimSpace(code))
		code, err := normalizeCode(code, "role")
		if err != nil {
			return nil, err
		}
		if _, ok := seen[code]; ok {
			continue
		}
		seen[code] = struct{}{}
		normalized = append(normalized, code)
	}
	sort.Strings(normalized)
	return normalized, nil
}
