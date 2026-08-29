package service

import (
	"context"
	"time"

	"github.com/lwmacct/260829-go-hsr-identity/pkg/identity/domain"
)

type PasswordPolicy struct {
	MinLength      int
	MaxLength      int
	RequireUpper   bool
	RequireLower   bool
	RequireDigit   bool
	RequireSymbol  bool
	RejectUsername bool
	RejectCommon   bool
}

type PasswordHasher interface {
	Scheme() string
	Hash(string) (string, error)
	Verify(string, string) bool
}

// PasswordHasherRehash is implemented by hashers that can identify stale
// credential parameters. Successful authentication may use it to transparently
// upgrade a stored credential.
type PasswordHasherRehash interface {
	NeedsRehash(string) bool
}

type Argon2idParams struct {
	Memory      uint32
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

type PasswordOptions struct {
	Policy   PasswordPolicy
	Hasher   PasswordHasher
	Argon2id Argon2idParams
}

type SessionOptions struct {
	TTL           time.Duration
	IdleTimeout   time.Duration
	TouchInterval time.Duration
	TokenBytes    int
	Binding       BindingPolicy
	Claims        domain.ClaimsResolver
}

type IssuedSession = domain.IssuedSession

type Authorizer func(context.Context, *domain.Principal, string) error

type BindingPolicy interface {
	Bind(domain.RequestMeta) ([]byte, error)
	Validate(domain.SessionRecord, domain.RequestMeta) error
}

type NoBinding struct{}

func (NoBinding) Bind(domain.RequestMeta) ([]byte, error)                 { return nil, nil }
func (NoBinding) Validate(domain.SessionRecord, domain.RequestMeta) error { return nil }

type IPBinding struct{}

func (IPBinding) Bind(meta domain.RequestMeta) ([]byte, error) {
	if meta.ClientIP == "" {
		return nil, domain.ErrInvalidRequestMeta
	}
	return domain.HashBytes(meta.ClientIP), nil
}
func (IPBinding) Validate(record domain.SessionRecord, meta domain.RequestMeta) error {
	b, err := (IPBinding{}).Bind(meta)
	if err != nil {
		return err
	}
	if !equalBytes(record.BindingHash, b) {
		return domain.ErrBindingMismatch
	}
	return nil
}
