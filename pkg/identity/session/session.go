// Package session implements opaque, revocable login sessions.
package session

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"strings"
	"time"
	"uuid"

	"github.com/lwmacct/260829-go-hsr-identity/pkg/identity"
)

type BindingPolicy interface {
	Bind(identity.RequestMeta) ([]byte, error)
	Validate(identity.SessionRecord, identity.RequestMeta) error
}

type NoBinding struct{}

func (NoBinding) Bind(identity.RequestMeta) ([]byte, error)                   { return nil, nil }
func (NoBinding) Validate(identity.SessionRecord, identity.RequestMeta) error { return nil }

type IPBinding struct{}

func (IPBinding) Bind(meta identity.RequestMeta) ([]byte, error) {
	meta, err := identity.NormalizeRequestMeta(meta)
	if err != nil || meta.ClientIP == "" {
		return nil, identity.ErrInvalidRequestMeta
	}
	return identity.HashBytes(meta.ClientIP), nil
}

func (IPBinding) Validate(record identity.SessionRecord, meta identity.RequestMeta) error {
	if meta.ClientIP == "" || record.LoginIP == "" {
		return identity.ErrBindingMismatch
	}
	binding, err := (IPBinding{}).Bind(meta)
	if err != nil || subtle.ConstantTimeCompare(record.BindingHash, binding) != 1 {
		return identity.ErrBindingMismatch
	}
	return nil
}

type BindingFunc struct {
	Hash func(identity.RequestMeta) ([]byte, error)
}

func (f BindingFunc) Bind(meta identity.RequestMeta) ([]byte, error) {
	if f.Hash == nil {
		return nil, identity.ErrUnsupported
	}
	return f.Hash(meta)
}

func (f BindingFunc) Validate(record identity.SessionRecord, meta identity.RequestMeta) error {
	b, err := f.Bind(meta)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(record.BindingHash, b) != 1 {
		return identity.ErrBindingMismatch
	}
	return nil
}

type Options struct {
	Repository    identity.SessionRepository
	Users         identity.UserDirectory
	TTL           time.Duration
	IdleTimeout   time.Duration
	TouchInterval time.Duration
	TokenBytes    int
	Binding       BindingPolicy
	Now           identity.Clock
	Claims        identity.ClaimsResolver
	IDGenerator   func() (identity.SessionID, error)
}

type Service struct {
	repository    identity.SessionRepository
	users         identity.UserDirectory
	ttl           time.Duration
	idleTimeout   time.Duration
	touchInterval time.Duration
	tokenBytes    int
	binding       BindingPolicy
	now           identity.Clock
	claims        identity.ClaimsResolver
	idGenerator   func() (identity.SessionID, error)
}

func New(options Options) (*Service, error) {
	if options.Repository == nil {
		return nil, errors.New("identity/session: session repository is required")
	}
	if options.TTL == 0 {
		options.TTL = 30 * 24 * time.Hour
	}
	if options.TTL <= 0 {
		return nil, errors.New("identity/session: ttl must be positive")
	}
	if options.IdleTimeout < 0 {
		return nil, errors.New("identity/session: idle timeout must not be negative")
	}
	if options.TouchInterval == 0 {
		options.TouchInterval = 5 * time.Minute
	}
	if options.TouchInterval < 0 {
		return nil, errors.New("identity/session: touch interval must not be negative")
	}
	if options.TokenBytes == 0 {
		options.TokenBytes = 32
	}
	if options.TokenBytes < 16 {
		return nil, errors.New("identity/session: token entropy is too short")
	}
	if options.Binding == nil {
		options.Binding = NoBinding{}
	}
	if options.Now == nil {
		options.Now = func() time.Time { return time.Now().UTC() }
	}
	if options.IDGenerator == nil {
		options.IDGenerator = func() (identity.SessionID, error) { return identity.SessionID(uuid.NewV7().String()), nil }
	}
	return &Service{repository: options.Repository, users: options.Users, ttl: options.TTL, idleTimeout: options.IdleTimeout, touchInterval: options.TouchInterval, tokenBytes: options.TokenBytes, binding: options.Binding, now: options.Now, claims: options.Claims, idGenerator: options.IDGenerator}, nil
}

func (s *Service) Create(ctx context.Context, userID identity.UserID, meta identity.RequestMeta) (string, *identity.SessionRecord, error) {
	if s == nil || s.repository == nil {
		return "", nil, errors.New("identity/session: service is not configured")
	}
	userID = identity.UserID(strings.TrimSpace(string(userID)))
	if userID == "" {
		return "", nil, identity.ErrInvalidUser
	}
	meta, err := identity.NormalizeRequestMeta(meta)
	if err != nil {
		return "", nil, err
	}
	if s.users != nil {
		user, e := s.users.UserByID(ctx, userID)
		if e != nil {
			return "", nil, e
		}
		if user == nil || !user.Active() {
			return "", nil, identity.ErrDisabled
		}
	}
	raw := make([]byte, s.tokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", nil, err
	}
	token := "sess_" + base64.RawURLEncoding.EncodeToString(raw)
	now := s.now().UTC()
	bindingHash, err := s.binding.Bind(meta)
	if err != nil {
		return "", nil, err
	}
	sessionID, err := s.idGenerator()
	if err != nil {
		return "", nil, err
	}
	sessionID = identity.SessionID(strings.TrimSpace(string(sessionID)))
	if sessionID == "" {
		return "", nil, identity.ErrInvalidUser
	}
	record := &identity.SessionRecord{ID: sessionID, TokenHash: identity.HashBytes(token), UserID: userID, LoginIP: meta.ClientIP, LastIP: meta.ClientIP, BindingHash: bindingHash, UserAgentHash: identity.HashBytes(meta.UserAgent), ExpiresAt: now.Add(s.ttl), CreatedAt: now, LastSeenAt: now}
	if err := s.repository.CreateSession(ctx, *record); err != nil {
		return "", nil, err
	}
	return token, record, nil
}

func (s *Service) CreateToken(ctx context.Context, userID identity.UserID, meta identity.RequestMeta) (string, time.Time, error) {
	token, record, err := s.Create(ctx, userID, meta)
	if err != nil {
		return "", time.Time{}, err
	}
	return token, record.ExpiresAt, nil
}

func (s *Service) Resolve(ctx context.Context, token string, meta identity.RequestMeta) (*identity.Principal, error) {
	if s == nil || s.repository == nil {
		return nil, errors.New("identity/session: service is not configured")
	}
	if strings.TrimSpace(token) == "" {
		return nil, identity.ErrUnauthenticated
	}
	meta, err := identity.NormalizeRequestMeta(meta)
	if err != nil {
		return nil, err
	}
	record, err := s.repository.GetSessionByTokenHash(ctx, identity.HashBytes(token))
	if err != nil {
		if errors.Is(err, identity.ErrNotFound) {
			return nil, identity.ErrUnauthenticated
		}
		return nil, err
	}
	if record == nil {
		return nil, identity.ErrUnauthenticated
	}
	now := s.now().UTC()
	if record.RevokedAt != nil {
		return nil, identity.ErrUnauthenticated
	}
	if !record.ExpiresAt.After(now) || (s.idleTimeout > 0 && now.Sub(record.LastSeenAt) >= s.idleTimeout) {
		return nil, identity.ErrUnauthenticated
	}
	if err := s.binding.Validate(*record, meta); err != nil {
		return nil, err
	}
	if s.users == nil {
		return nil, errors.New("identity/session: user directory is required")
	}
	user, err := s.users.UserByID(ctx, record.UserID)
	if err != nil {
		if errors.Is(err, identity.ErrNotFound) {
			return nil, identity.ErrUnauthenticated
		}
		return nil, err
	}
	if user == nil || !user.Active() {
		return nil, identity.ErrUnauthenticated
	}
	if s.touchInterval == 0 || now.Sub(record.LastSeenAt) >= s.touchInterval {
		if err := s.repository.TouchSession(ctx, record.ID, meta.ClientIP, now); err != nil && !errors.Is(err, identity.ErrNotFound) {
			return nil, err
		}
	}
	claims := identity.Claims{}
	if s.claims != nil {
		claims, err = s.claims(ctx, user)
		if err != nil {
			return nil, err
		}
	}
	return &identity.Principal{Subject: user.ID, User: user, Claims: claims, AuthenticatedAt: record.CreatedAt, SessionID: record.ID}, nil
}

func (s *Service) ResolveSession(ctx context.Context, token string, meta identity.RequestMeta) (*identity.Principal, error) {
	return s.Resolve(ctx, token, meta)
}
func (s *Service) Parse(ctx context.Context, token string, meta identity.RequestMeta) (*identity.Principal, error) {
	return s.Resolve(ctx, token, meta)
}

func (s *Service) User(ctx context.Context, token string, meta identity.RequestMeta) (*identity.User, error) {
	principal, err := s.Resolve(ctx, token, meta)
	if err != nil {
		return nil, err
	}
	return principal.User, nil
}

func (s *Service) Touch(ctx context.Context, token string, meta identity.RequestMeta) error {
	if s == nil || s.repository == nil {
		return errors.New("identity/session: service is not configured")
	}
	if strings.TrimSpace(token) == "" {
		return identity.ErrUnauthenticated
	}
	meta, err := identity.NormalizeRequestMeta(meta)
	if err != nil {
		return err
	}
	now := s.now().UTC()
	record, err := s.repository.GetSessionByTokenHash(ctx, identity.HashBytes(token))
	if err != nil {
		return err
	}
	if record.RevokedAt != nil {
		return identity.ErrUnauthenticated
	}
	if !record.ExpiresAt.After(now) || (s.idleTimeout > 0 && now.Sub(record.LastSeenAt) >= s.idleTimeout) {
		return identity.ErrUnauthenticated
	}
	if err := s.binding.Validate(*record, meta); err != nil {
		return err
	}
	return s.repository.TouchSession(ctx, record.ID, meta.ClientIP, now)
}

func (s *Service) Revoke(ctx context.Context, token, reason string, meta identity.RequestMeta) error {
	if s == nil || s.repository == nil {
		return errors.New("identity/session: service is not configured")
	}
	if strings.TrimSpace(token) == "" {
		return identity.ErrUnauthenticated
	}
	meta, err := identity.NormalizeRequestMeta(meta)
	if err != nil {
		return err
	}
	record, err := s.repository.GetSessionByTokenHash(ctx, identity.HashBytes(token))
	if err != nil {
		return err
	}
	return s.repository.RevokeSession(ctx, record.ID, reason, meta.ClientIP, s.now().UTC())
}
func (s *Service) RevokeSession(ctx context.Context, token, reason string, meta identity.RequestMeta) error {
	return s.Revoke(ctx, token, reason, meta)
}
func (s *Service) Delete(ctx context.Context, token string) error {
	if s == nil || s.repository == nil {
		return errors.New("identity/session: service is not configured")
	}
	if strings.TrimSpace(token) == "" {
		return identity.ErrUnauthenticated
	}
	record, err := s.repository.GetSessionByTokenHash(ctx, identity.HashBytes(token))
	if err != nil {
		return err
	}
	return s.repository.DeleteSession(ctx, record.ID)
}
func (s *Service) DeleteSession(ctx context.Context, token string) error { return s.Delete(ctx, token) }
func (s *Service) RevokeForUsers(ctx context.Context, userIDs []identity.UserID, reason string) error {
	if s == nil || s.repository == nil {
		return errors.New("identity/session: service is not configured")
	}
	return s.repository.RevokeSessionsForUsers(ctx, userIDs, reason, s.now().UTC())
}
func (s *Service) DeleteForUsers(ctx context.Context, userIDs []identity.UserID) error {
	if s == nil || s.repository == nil {
		return errors.New("identity/session: service is not configured")
	}
	return s.repository.DeleteSessionsForUsers(ctx, userIDs)
}

var _ identity.SessionResolver = (*Service)(nil)
