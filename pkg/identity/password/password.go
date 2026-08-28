// Package password provides a password policy and Argon2id credential service.
// Account creation and transaction orchestration live in identity/account.
package password

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/lwmacct/260829-go-hsr-identity/pkg/identity"
	"golang.org/x/crypto/argon2"
)

const SchemeArgon2id = "argon2id"

type Hasher interface {
	Scheme() string
	Hash(string) (string, error)
	Verify(string, string) bool
}

type Params struct {
	Memory      uint32
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

func DefaultParams() Params {
	return Params{Memory: 64 * 1024, Iterations: 3, Parallelism: 2, SaltLength: 16, KeyLength: 32}
}

func (p Params) valid() bool {
	return p.Memory >= 8*1024 && p.Memory <= 1024*1024 && p.Iterations > 0 && p.Iterations <= 20 && p.Parallelism > 0 && p.Parallelism <= 64 && p.SaltLength >= 8 && p.SaltLength <= 256 && p.KeyLength >= 16 && p.KeyLength <= 128
}

type Argon2id struct{ Params Params }

func NewArgon2id(params Params) (Argon2id, error) {
	if params == (Params{}) {
		params = DefaultParams()
	}
	if !params.valid() {
		return Argon2id{}, errors.New("identity/password: invalid argon2 parameters")
	}
	return Argon2id{Params: params}, nil
}

func (h Argon2id) Scheme() string { return SchemeArgon2id }

func (h Argon2id) Hash(value string) (string, error) {
	if !h.Params.valid() {
		return "", errors.New("identity/password: invalid argon2 parameters")
	}
	salt := make([]byte, h.Params.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(value), salt, h.Params.Iterations, h.Params.Memory, h.Params.Parallelism, h.Params.KeyLength)
	enc := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", h.Params.Memory, h.Params.Iterations, h.Params.Parallelism, enc.EncodeToString(salt), enc.EncodeToString(key)), nil
}

func (h Argon2id) Verify(encoded, value string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != SchemeArgon2id || parts[2] != "v=19" {
		return false
	}
	var memory, iterations uint32
	var parallelism uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &iterations, &parallelism); err != nil {
		return false
	}
	params := Params{Memory: memory, Iterations: iterations, Parallelism: parallelism, SaltLength: 8, KeyLength: 16}
	enc := base64.RawStdEncoding
	salt, err1 := enc.DecodeString(parts[4])
	expected, err2 := enc.DecodeString(parts[5])
	if err1 != nil || err2 != nil || len(salt) < int(params.SaltLength) || len(salt) > 256 || len(expected) < int(params.KeyLength) || len(expected) > 128 || !params.valid() {
		return false
	}
	actual := argon2.IDKey([]byte(value), salt, iterations, memory, parallelism, uint32(len(expected)))
	return subtle.ConstantTimeCompare(actual, expected) == 1
}

type Policy struct {
	MinLength     int
	MaxLength     int
	RequireUpper  bool
	RequireLower  bool
	RequireDigit  bool
	RequireSymbol bool
	RejectHandle  bool
	RejectCommon  bool
}

func DefaultPolicy() Policy {
	return Policy{MinLength: 12, MaxLength: 128, RejectHandle: true, RejectCommon: true}
}

type Options struct {
	Credentials  identity.PasswordRepository
	Users        identity.UserDirectory
	UserUpdates  identity.UserRepository
	Hasher       Hasher
	HandlePolicy identity.HandlePolicy
	Policy       Policy
	Now          identity.Clock
}

type Service struct {
	credentials  identity.PasswordRepository
	users        identity.UserDirectory
	userUpdates  identity.UserRepository
	hasher       Hasher
	handlePolicy identity.HandlePolicy
	policy       Policy
	now          identity.Clock
}

func New(options Options) (*Service, error) {
	if options.Credentials == nil {
		return nil, errors.New("identity/password: credential repository is required")
	}
	if options.Hasher == nil {
		hasher, err := NewArgon2id(DefaultParams())
		if err != nil {
			return nil, err
		}
		options.Hasher = hasher
	}
	if options.Policy == (Policy{}) {
		options.Policy = DefaultPolicy()
	}
	if options.Policy.MinLength < 1 {
		options.Policy.MinLength = 12
	}
	if options.Policy.MaxLength < options.Policy.MinLength {
		return nil, errors.New("identity/password: invalid password policy")
	}
	if options.HandlePolicy == nil {
		options.HandlePolicy = identity.HandlePolicyFunc(identity.LowerASCIIHandlePolicy)
	}
	if options.Now == nil {
		options.Now = func() time.Time { return time.Now().UTC() }
	}
	return &Service{credentials: options.Credentials, users: options.Users, userUpdates: options.UserUpdates, hasher: options.Hasher, handlePolicy: options.HandlePolicy, policy: options.Policy, now: options.Now}, nil
}

func (s *Service) WithRepositories(credentials identity.PasswordRepository, users identity.UserDirectory, updates identity.UserRepository) *Service {
	if s == nil {
		return nil
	}
	copy := *s
	copy.credentials, copy.users, copy.userUpdates = credentials, users, updates
	return &copy
}

func (s *Service) Validate(handle, value string) error {
	if s == nil {
		return errors.New("identity/password: service is not configured")
	}
	length := utf8.RuneCountInString(value)
	if strings.TrimSpace(value) == "" || length < s.policy.MinLength || length > s.policy.MaxLength {
		return identity.ErrWeakPassword
	}
	var upper, lower, digit, symbol bool
	for _, r := range value {
		switch {
		case unicode.IsUpper(r):
			upper = true
		case unicode.IsLower(r):
			lower = true
		case unicode.IsDigit(r):
			digit = true
		default:
			symbol = true
		}
	}
	if s.policy.RequireUpper && !upper || s.policy.RequireLower && !lower || s.policy.RequireDigit && !digit || s.policy.RequireSymbol && !symbol {
		return identity.ErrWeakPassword
	}
	if s.policy.RejectHandle && handle != "" && strings.EqualFold(strings.TrimSpace(handle), strings.TrimSpace(value)) {
		return identity.ErrWeakPassword
	}
	if s.policy.RejectCommon && isCommon(value) {
		return identity.ErrWeakPassword
	}
	return nil
}

func (s *Service) CheckStrength(handle, value string) error { return s.Validate(handle, value) }
func (s *Service) Hash(value string) (string, error) {
	if s == nil || s.hasher == nil {
		return "", errors.New("identity/password: service is not configured")
	}
	return s.hasher.Hash(value)
}
func (s *Service) Verify(encoded, value string) bool {
	return s != nil && s.hasher != nil && s.hasher.Verify(encoded, value)
}

func (s *Service) Now() time.Time {
	if s == nil || s.now == nil {
		return time.Now().UTC()
	}
	return s.now().UTC()
}

func (s *Service) Set(ctx context.Context, userID identity.UserID, handle, value string) error {
	if userID == "" {
		return identity.ErrInvalidUser
	}
	if err := s.Validate(handle, value); err != nil {
		return err
	}
	hash, err := s.Hash(value)
	if err != nil {
		return err
	}
	return s.SetHash(ctx, userID, hash)
}

func (s *Service) SetHash(ctx context.Context, userID identity.UserID, hash string) error {
	if s == nil || s.credentials == nil || s.hasher == nil {
		return errors.New("identity/password: service is not configured")
	}
	if userID == "" || strings.TrimSpace(hash) == "" {
		return identity.ErrInvalidUser
	}
	now := s.now().UTC()
	return s.credentials.UpsertPasswordCredential(ctx, identity.PasswordCredential{UserID: userID, Scheme: s.hasher.Scheme(), Hash: hash, PasswordChangedAt: now, CreatedAt: now, UpdatedAt: now})
}

func (s *Service) SetPassword(ctx context.Context, userID identity.UserID, handle, value string) error {
	return s.Set(ctx, userID, handle, value)
}

func (s *Service) AuthenticateUser(ctx context.Context, userID identity.UserID, value string) error {
	if s == nil || s.credentials == nil || s.hasher == nil {
		return errors.New("identity/password: service is not configured")
	}
	credential, err := s.credentials.GetPasswordCredential(ctx, userID)
	if err != nil {
		if errors.Is(err, identity.ErrNotFound) {
			return identity.ErrUnauthenticated
		}
		return err
	}
	if credential == nil || credential.Scheme != s.hasher.Scheme() || !s.hasher.Verify(credential.Hash, value) {
		return identity.ErrUnauthenticated
	}
	return nil
}

func (s *Service) Authenticate(ctx context.Context, handle, value string) (*identity.User, error) {
	if s == nil || s.users == nil {
		return nil, errors.New("identity/password: user directory is required")
	}
	normalized, err := s.handlePolicy.Normalize(handle)
	if err != nil {
		return nil, identity.ErrUnauthenticated
	}
	user, err := s.users.UserByHandle(ctx, normalized)
	if err != nil {
		if errors.Is(err, identity.ErrNotFound) {
			return nil, identity.ErrUnauthenticated
		}
		return nil, err
	}
	if user == nil || !user.Active() {
		return nil, identity.ErrUnauthenticated
	}
	if err := s.AuthenticateUser(ctx, user.ID, value); err != nil {
		return nil, err
	}
	if s.userUpdates != nil {
		_ = s.userUpdates.MarkUserLogin(ctx, user.ID, s.now().UTC())
	}
	return user, nil
}

func (s *Service) Change(ctx context.Context, userID identity.UserID, handle, current, next string) error {
	if err := s.AuthenticateUser(ctx, userID, current); err != nil {
		return err
	}
	return s.Set(ctx, userID, handle, next)
}
func (s *Service) ChangePassword(ctx context.Context, userID identity.UserID, handle, current, next string) error {
	return s.Change(ctx, userID, handle, current, next)
}
func (s *Service) Reset(ctx context.Context, userID identity.UserID, handle, value string) error {
	return s.Set(ctx, userID, handle, value)
}
func (s *Service) ResetPassword(ctx context.Context, userID identity.UserID, handle, value string) error {
	return s.Reset(ctx, userID, handle, value)
}

func (s *Service) Generate() (string, error) {
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
	buf := make([]byte, 24)
	bound := byte(256 - (256 % len(alphabet)))
	var random [1]byte
	for index := range buf {
		for {
			if _, err := rand.Read(random[:]); err != nil {
				return "", err
			}
			if random[0] < bound {
				buf[index] = alphabet[int(random[0])%len(alphabet)]
				break
			}
		}
	}
	return string(buf), nil
}

func isCommon(value string) bool {
	switch strings.ToLower(value) {
	case "password", "password123", "123456789012", "qwertyuiop", "letmein123":
		return true
	}
	return false
}
