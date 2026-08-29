package service

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/lwmacct/260829-go-hsr-identity/pkg/identity/domain"
	"golang.org/x/crypto/argon2"
)

const SchemeArgon2id = "argon2id"

const (
	minArgonMemory = 8 * 1024 // KiB
	maxArgonMemory = 256 * 1024
)

type Argon2id struct{ Params Argon2idParams }

func DefaultArgon2idParams() Argon2idParams {
	return Argon2idParams{Memory: 64 * 1024, Iterations: 3, Parallelism: 2, SaltLength: 16, KeyLength: 32}
}
func (p Argon2idParams) valid() bool {
	return p.Memory >= minArgonMemory && p.Memory <= maxArgonMemory && p.Iterations > 0 && p.Iterations <= 20 && p.Parallelism > 0 && p.Parallelism <= 64 && p.Memory >= 8*uint32(p.Parallelism) && p.SaltLength >= 8 && p.SaltLength <= 256 && p.KeyLength >= 16 && p.KeyLength <= 128
}
func NewArgon2id(p Argon2idParams) (Argon2id, error) {
	if p == (Argon2idParams{}) {
		p = DefaultArgon2idParams()
	}
	if !p.valid() {
		return Argon2id{}, errors.New("identity: invalid argon2id parameters")
	}
	return Argon2id{Params: p}, nil
}
func (h Argon2id) Scheme() string { return SchemeArgon2id }
func (h Argon2id) Hash(value string) (string, error) {
	if !h.Params.valid() {
		return "", errors.New("identity: invalid argon2id parameters")
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
	params, salt, expected, ok := parseArgon2id(encoded)
	if !ok || !params.valid() {
		return false
	}
	actual := argon2.IDKey([]byte(value), salt, params.Iterations, params.Memory, params.Parallelism, uint32(len(expected)))
	return subtle.ConstantTimeCompare(actual, expected) == 1
}

// NeedsRehash reports whether an encoded credential uses parameters different
// from the hasher's current policy. Invalid encodings are treated as needing a
// rehash, while Verify still rejects them.
func (h Argon2id) NeedsRehash(encoded string) bool {
	params, salt, expected, ok := parseArgon2id(encoded)
	if !ok || !params.valid() || len(salt) != int(params.SaltLength) || len(expected) != int(params.KeyLength) {
		return true
	}
	return params != h.Params
}

func parseArgon2id(encoded string) (Argon2idParams, []byte, []byte, bool) {
	if len(encoded) == 0 || len(encoded) > 4096 {
		return Argon2idParams{}, nil, nil, false
	}
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != SchemeArgon2id || parts[2] != "v=19" {
		return Argon2idParams{}, nil, nil, false
	}
	fields := strings.Split(parts[3], ",")
	if len(fields) != 3 {
		return Argon2idParams{}, nil, nil, false
	}
	values := make(map[string]string, 3)
	for _, field := range fields {
		key, value, ok := strings.Cut(field, "=")
		if !ok || (key != "m" && key != "t" && key != "p") || value == "" {
			return Argon2idParams{}, nil, nil, false
		}
		if _, exists := values[key]; exists {
			return Argon2idParams{}, nil, nil, false
		}
		values[key] = value
	}
	memory, errM := strconv.ParseUint(values["m"], 10, 32)
	iterations, errT := strconv.ParseUint(values["t"], 10, 32)
	parallelism, errP := strconv.ParseUint(values["p"], 10, 8)
	if errM != nil || errT != nil || errP != nil {
		return Argon2idParams{}, nil, nil, false
	}
	params := Argon2idParams{Memory: uint32(memory), Iterations: uint32(iterations), Parallelism: uint8(parallelism)}
	enc := base64.RawStdEncoding
	salt, errSalt := enc.DecodeString(parts[4])
	expected, errExpected := enc.DecodeString(parts[5])
	if errSalt != nil || errExpected != nil || len(salt) < 8 || len(salt) > 256 || len(expected) < 16 || len(expected) > 128 {
		return Argon2idParams{}, nil, nil, false
	}
	params.SaltLength = uint32(len(salt))
	params.KeyLength = uint32(len(expected))
	return params, salt, expected, true
}

type PasswordService struct {
	credentials domain.PasswordRepository
	users       domain.UserDirectory
	hasher      PasswordHasher
	policy      PasswordPolicy
	now         domain.Clock
	handle      domain.HandlePolicy
}

func NewPasswordService(credentials domain.PasswordRepository, users domain.UserDirectory, options PasswordOptions, now domain.Clock, handle domain.HandlePolicy) (*PasswordService, error) {
	if credentials == nil {
		return nil, errors.New("identity: password repository is required")
	}
	if options.Hasher == nil {
		h, e := NewArgon2id(options.Argon2id)
		if e != nil {
			return nil, e
		}
		options.Hasher = h
	}
	if options.Policy == (PasswordPolicy{}) {
		options.Policy = PasswordPolicy{MinLength: 12, MaxLength: 128, RejectHandle: true, RejectCommon: true}
	}
	if options.Policy.MinLength < 1 {
		options.Policy.MinLength = 12
	}
	if options.Policy.MaxLength < 1 {
		options.Policy.MaxLength = 128
	}
	if options.Policy.MaxLength < options.Policy.MinLength {
		return nil, errors.New("identity: invalid password policy")
	}
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	if handle == nil {
		handle = domain.HandlePolicyFunc(domain.LowerASCIIHandlePolicy)
	}
	return &PasswordService{credentials: credentials, users: users, hasher: options.Hasher, policy: options.Policy, now: now, handle: handle}, nil
}
func (s *PasswordService) Validate(handle, value string) error {
	if s == nil {
		return errors.New("identity: password service is not configured")
	}
	n := utf8.RuneCountInString(value)
	if strings.TrimSpace(value) == "" || n < s.policy.MinLength || n > s.policy.MaxLength {
		return domain.ErrWeakPassword
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
		return domain.ErrWeakPassword
	}
	if s.policy.RejectHandle && handle != "" && strings.EqualFold(strings.TrimSpace(handle), strings.TrimSpace(value)) {
		return domain.ErrWeakPassword
	}
	if s.policy.RejectCommon && isCommon(value) {
		return domain.ErrWeakPassword
	}
	return nil
}
func (s *PasswordService) Hash(value string) (string, error) {
	if s == nil || s.hasher == nil {
		return "", errors.New("identity: password service is not configured")
	}
	return s.hasher.Hash(value)
}
func (s *PasswordService) Verify(hash, value string) bool {
	return s != nil && s.hasher != nil && s.hasher.Verify(hash, value)
}
func (s *PasswordService) AuthenticateUser(ctx context.Context, id domain.UserID, value string) error {
	normalized, err := domain.NormalizeUserID(id)
	if err != nil {
		return domain.ErrUnauthenticated
	}
	id = normalized
	c, e := s.credentials.GetPasswordCredential(ctx, id)
	if e != nil {
		if errors.Is(e, domain.ErrNotFound) {
			return domain.ErrUnauthenticated
		}
		return e
	}
	if c == nil || c.Scheme != s.hasher.Scheme() || !s.hasher.Verify(c.Hash, value) {
		return domain.ErrUnauthenticated
	}
	if rehasher, ok := s.hasher.(PasswordHasherRehash); ok && rehasher.NeedsRehash(c.Hash) {
		hash, err := s.hasher.Hash(value)
		if err != nil {
			return err
		}
		if err := s.SetHash(ctx, id, hash); err != nil {
			return err
		}
	}
	return nil
}
func (s *PasswordService) Set(ctx context.Context, id domain.UserID, handle, value string) error {
	if e := s.Validate(handle, value); e != nil {
		return e
	}
	h, e := s.Hash(value)
	if e != nil {
		return e
	}
	return s.SetHash(ctx, id, h)
}
func (s *PasswordService) SetHash(ctx context.Context, id domain.UserID, hash string) error {
	normalized, err := domain.NormalizeUserID(id)
	if err != nil || strings.TrimSpace(hash) == "" {
		return domain.ErrInvalidUser
	}
	id = normalized
	now := s.now().UTC()
	return s.credentials.UpsertPasswordCredential(ctx, domain.PasswordCredential{UserID: id, Scheme: s.hasher.Scheme(), Hash: hash, PasswordChangedAt: now, CreatedAt: now, UpdatedAt: now})
}
func (s *PasswordService) Authenticate(ctx context.Context, handle, value string) (*domain.User, error) {
	if s.users == nil {
		return nil, errors.New("identity: user directory is required")
	}
	norm, e := s.handle.Normalize(handle)
	if e != nil {
		return nil, domain.ErrUnauthenticated
	}
	u, e := s.users.UserByHandle(ctx, norm)
	if e != nil {
		if errors.Is(e, domain.ErrNotFound) {
			return nil, domain.ErrUnauthenticated
		}
		return nil, e
	}
	if u == nil || !u.Active() {
		return nil, domain.ErrUnauthenticated
	}
	if e := s.AuthenticateUser(ctx, u.ID, value); e != nil {
		return nil, e
	}
	return u, nil
}
func (s *PasswordService) Now() time.Time { return s.now().UTC() }
func isCommon(v string) bool {
	switch strings.ToLower(v) {
	case "password", "password123", "123456789012", "qwertyuiop", "letmein123":
		return true
	}
	return false
}
func equalBytes(a, b []byte) bool { return len(a) == len(b) && subtle.ConstantTimeCompare(a, b) == 1 }
