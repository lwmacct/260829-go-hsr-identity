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

// PasswordHasherSchemes allows a primary hasher to verify explicitly
// configured secondary schemes and upgrade them after successful login.
type PasswordHasherSchemes interface {
	PasswordHasher
	VerifyScheme(scheme, encoded, value string) bool
	NeedsRehashScheme(scheme, encoded string) bool
}

type Argon2idParams struct {
	Memory      uint32
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

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

type HTTPChallengeOptions struct {
	// Verifier is required when either authentication flow enforces a challenge.
	Verifier HumanChallengeVerifier
	// Creator enables POST /auth/challenges. It can be omitted for remote-token
	// providers whose challenge is created by the browser and verified remotely.
	Creator               HumanChallengeCreator
	RequireOnLogin        bool
	RequireOnRegistration bool
}

type HTTPOptions struct {
	AuthPrefix  string
	AdminPrefix string
	// LoginEnabled controls the password login endpoint.
	LoginEnabled bool
	// RegistrationEnabled controls public password registration and automatic
	// Session issuance through the registration endpoint.
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
	Challenge           HTTPChallengeOptions
}

type Options struct {
	DB             *bun.DB
	Clock          Clock
	UsernamePolicy UsernamePolicy
	Password       PasswordOptions
	Session        SessionOptions
	Authorization  AuthorizationOptions
	HTTP           HTTPOptions
	Authorizer     Authorizer
	LoginGuard     LoginGuard
	Events         EventSink
	// DeleteParticipant removes host-owned records in the same Bun transaction
	// used to delete identity records. The callback must not begin a nested
	// transaction.
	DeleteParticipant UserDeleteParticipant
}

type Authorizer func(context.Context, *Principal, string) error

type UserDeleteParticipant func(context.Context, bun.IDB, []User) error

// RequestMetaResolver lets a host application derive trusted client metadata
// (for example, an IP behind a known reverse proxy). The default resolver only
// uses net/http's RemoteAddr and User-Agent and never trusts forwarding headers.
type RequestMetaResolver func(*http.Request) (RequestMeta, error)

// DefaultOptions returns the module defaults. New applies the same defaults
// for zero-valued nested options.
func DefaultOptions() Options {
	return Options{
		Password: PasswordOptions{Policy: PasswordPolicy{MinLength: 12, MaxLength: 128, RejectUsername: true, RejectCommon: true}},
		Session:  SessionOptions{TTL: 30 * 24 * time.Hour, TouchInterval: 5 * time.Minute, TokenBytes: 32, Binding: NoBinding{}},
		HTTP:     HTTPOptions{AuthPrefix: "/auth", AdminPrefix: "/admin", LoginEnabled: true, CookieName: "identity_session", CookiePath: "/", SameSite: http.SameSiteLaxMode},
	}
}
