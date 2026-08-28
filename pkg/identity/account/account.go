// Package account orchestrates atomic user-account operations across identity
// repositories. Credential algorithms remain in identity/password.
package account

import (
	"context"
	"errors"

	"github.com/lwmacct/260829-go-hsr-identity/pkg/identity"
	"github.com/lwmacct/260829-go-hsr-identity/pkg/identity/password"
)

type Options struct {
	Users        *identity.Service
	Passwords    *password.Service
	Transactions identity.TxManager
}

type Service struct {
	users        *identity.Service
	passwords    *password.Service
	transactions identity.TxManager
}

func New(options Options) (*Service, error) {
	if options.Users == nil {
		return nil, errors.New("identity/account: user service is required")
	}
	if options.Passwords == nil {
		return nil, errors.New("identity/account: password service is required")
	}
	if options.Transactions == nil {
		return nil, errors.New("identity/account: transaction manager is required")
	}
	return &Service{users: options.Users, passwords: options.Passwords, transactions: options.Transactions}, nil
}

func (s *Service) Register(ctx context.Context, input identity.UserCreateInput, rawPassword string) (*identity.User, error) {
	if s == nil || s.transactions == nil || s.users == nil || s.passwords == nil {
		return nil, errors.New("identity/account: service is not configured")
	}
	if err := s.passwords.Validate(input.Handle, rawPassword); err != nil {
		return nil, err
	}
	hash, err := s.passwords.Hash(rawPassword)
	if err != nil {
		return nil, err
	}
	var created *identity.User
	err = s.transactions.WithinTx(ctx, func(txctx context.Context, unit identity.UnitOfWork) error {
		users := s.users.WithUsers(unit.Users())
		var err error
		created, err = users.Create(txctx, input)
		if err != nil {
			return err
		}
		passwords := s.passwords.WithRepositories(unit.Passwords(), identity.DirectoryFromRepository(unit.Users()), unit.Users())
		return passwords.SetHash(txctx, created.ID, hash)
	})
	if err != nil {
		return nil, err
	}
	return created, nil
}

func (s *Service) ChangePassword(ctx context.Context, userID identity.UserID, handle, current, next string) error {
	if s == nil || s.transactions == nil || s.passwords == nil {
		return errors.New("identity/account: service is not configured")
	}
	return s.transactions.WithinTx(ctx, func(txctx context.Context, unit identity.UnitOfWork) error {
		passwords := s.passwords.WithRepositories(unit.Passwords(), identity.DirectoryFromRepository(unit.Users()), unit.Users())
		if err := passwords.AuthenticateUser(txctx, userID, current); err != nil {
			return err
		}
		if err := passwords.Validate(handle, next); err != nil {
			return err
		}
		hash, err := passwords.Hash(next)
		if err != nil {
			return err
		}
		if err := passwords.SetHash(txctx, userID, hash); err != nil {
			return err
		}
		return unit.Sessions().RevokeSessionsForUsers(txctx, []identity.UserID{userID}, "password_changed", passwords.Now())
	})
}

func (s *Service) ResetPassword(ctx context.Context, userID identity.UserID, handle, next string) error {
	if s == nil || s.transactions == nil || s.passwords == nil {
		return errors.New("identity/account: service is not configured")
	}
	if err := s.passwords.Validate(handle, next); err != nil {
		return err
	}
	hash, err := s.passwords.Hash(next)
	if err != nil {
		return err
	}
	return s.transactions.WithinTx(ctx, func(txctx context.Context, unit identity.UnitOfWork) error {
		if _, err := unit.Users().GetUser(txctx, userID); err != nil {
			return err
		}
		passwords := s.passwords.WithRepositories(unit.Passwords(), identity.DirectoryFromRepository(unit.Users()), unit.Users())
		if err := passwords.SetHash(txctx, userID, hash); err != nil {
			return err
		}
		return unit.Sessions().RevokeSessionsForUsers(txctx, []identity.UserID{userID}, "password_reset", passwords.Now())
	})
}
