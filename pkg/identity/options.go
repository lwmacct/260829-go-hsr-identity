package identity

import (
	"context"
	"crypto/subtle"
	"net/http"
	"time"

	"github.com/uptrace/bun"
)

// MinimumPostgreSQLMajor is the minimum PostgreSQL major version supported by
// the Bun schema. PostgreSQL 18 provides the native UUIDv7 SQL functions used
// by the database-level UUIDv7 checks.
const MinimumPostgreSQLMajor = 18

type PasswordHasher interface {
	Scheme() string
	Hash(string) (string, error)
	Verify(string, string) bool
}

// PasswordHasherRehash is an optional extension for hashers that can detect
// stale credential parameters. Successful authentication transparently stores
// a hash generated with the current parameters.
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

type PasswordPolicy struct {
	MinLength     int
	MaxLength     int
	RequireUpper  bool
	RequireLower  bool
	RequireDigit  bool
	RequireSymbol bool
	RejectHandle  bool
	RejectCommon  bool
}

type PasswordOptions struct {
	Policy   PasswordPolicy
	Hasher   PasswordHasher
	Argon2id Argon2idParams
}

type BindingPolicy interface {
	Bind(RequestMeta) ([]byte, error)
	Validate(SessionRecord, RequestMeta) error
}

type NoBinding struct{}

func (NoBinding) Bind(RequestMeta) ([]byte, error)          { return nil, nil }
func (NoBinding) Validate(SessionRecord, RequestMeta) error { return nil }

type IPBinding struct{}

func (IPBinding) Bind(meta RequestMeta) ([]byte, error) {
	if meta.ClientIP == "" {
		return nil, ErrInvalidRequestMeta
	}
	return HashBytes(meta.ClientIP), nil
}
func (IPBinding) Validate(record SessionRecord, meta RequestMeta) error {
	b, err := (IPBinding{}).Bind(meta)
	if err != nil {
		return err
	}
	if len(record.BindingHash) != len(b) || subtle.ConstantTimeCompare(record.BindingHash, b) != 1 {
		return ErrBindingMismatch
	}
	return nil
}

type SessionOptions struct {
	TTL           time.Duration
	IdleTimeout   time.Duration
	TouchInterval time.Duration
	TokenBytes    int
	Binding       BindingPolicy
	Claims        ClaimsResolver
}

type AuthorizationOptions struct {
	// DefaultRoleCodes are assigned atomically to newly created users. Leave
	// empty when the host provisions roles explicitly after account creation.
	DefaultRoleCodes []string
}

type HTTPOptions struct {
	AuthPrefix          string
	AdminPrefix         string
	RegistrationEnabled bool
	EnableAdminRoutes   bool
	EnableRBACRoutes    bool
	CookieName          string
	CookiePath          string
	CookieDomain        string
	SecureCookie        bool
	SameSite            http.SameSite
	TokenExtractor      func(*http.Request) string
	RequestMetaResolver RequestMetaResolver
}

type Options struct {
	DB            *bun.DB
	Clock         Clock
	HandlePolicy  HandlePolicy
	Password      PasswordOptions
	Session       SessionOptions
	Authorization AuthorizationOptions
	HTTP          HTTPOptions
	Authorizer    Authorizer
}

type Authorizer func(context.Context, *Principal, string) error

// RequestMetaResolver lets a host application derive trusted client metadata
// (for example, an IP behind a known reverse proxy). The default resolver only
// uses net/http's RemoteAddr and User-Agent and never trusts forwarding headers.
type RequestMetaResolver func(*http.Request) (RequestMeta, error)

// DefaultOptions returns the module defaults. New applies the same defaults
// for zero-valued nested options.
func DefaultOptions() Options {
	return Options{
		Password: PasswordOptions{Policy: PasswordPolicy{MinLength: 12, MaxLength: 128, RejectHandle: true, RejectCommon: true}},
		Session:  SessionOptions{TTL: 30 * 24 * time.Hour, TouchInterval: 5 * time.Minute, TokenBytes: 32, Binding: NoBinding{}},
		HTTP:     HTTPOptions{AuthPrefix: "/auth", AdminPrefix: "/admin", CookieName: "identity_session", CookiePath: "/", SameSite: http.SameSiteLaxMode},
	}
}
