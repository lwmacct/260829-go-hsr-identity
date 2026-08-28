package identity

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"
)

// UserID and SessionID are intentionally opaque. The default services use
// UUIDv7 values, but applications may use another identifier representation.
type UserID string
type SessionID string

type State string

const (
	StateActive   State = "active"
	StateDisabled State = "disabled"
)

type User struct {
	ID          UserID
	Handle      string
	DisplayName string
	Email       string
	AvatarURL   string
	State       State
	DisabledAt  *time.Time
	LastLoginAt *time.Time
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

func (u *User) Active() bool {
	return u != nil && u.ID != "" && u.State == StateActive && u.DisabledAt == nil
}

type Claims struct {
	Roles       []string
	Permissions []string
	Attributes  map[string]string
}

type Principal struct {
	Subject         UserID
	User            *User
	Claims          Claims
	AuthenticatedAt time.Time
	SessionID       SessionID
}

func (p *Principal) Active() bool {
	return p != nil && p.Subject != "" && p.User != nil && p.User.Active()
}

type RequestMeta struct {
	ClientIP   string
	Scheme     string
	Host       string
	UserAgent  string
	Method     string
	Path       string
	RemoteAddr string
}

type UserCreate struct {
	ID          UserID
	Handle      string
	DisplayName string
	Email       string
	AvatarURL   string
	State       State
	DisabledAt  *time.Time
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type UserProfilePatch struct {
	DisplayName string
	Email       string
	AvatarURL   string
	UpdatedAt   time.Time
}

type UserFilter struct {
	Keyword  string
	State    State
	Page     int
	PageSize int
}

type PasswordCredential struct {
	UserID            UserID
	Scheme            string
	Hash              string
	PasswordChangedAt time.Time
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

type SessionRecord struct {
	ID            SessionID
	TokenHash     []byte
	UserID        UserID
	LoginIP       string
	LastIP        string
	BindingHash   []byte
	UserAgentHash []byte
	ExpiresAt     time.Time
	CreatedAt     time.Time
	LastSeenAt    time.Time
	RevokedAt     *time.Time
	RevokedReason string
}

type UserRepository interface {
	CreateUser(context.Context, UserCreate) (*User, error)
	GetUser(context.Context, UserID) (*User, error)
	GetUserByHandle(context.Context, string) (*User, error)
	ListUsers(context.Context, UserFilter) ([]User, int, error)
	UpdateUserProfile(context.Context, UserID, UserProfilePatch) (*User, error)
	UpdateUserState(context.Context, []UserID, State, *time.Time, time.Time) (int64, error)
	MarkUserLogin(context.Context, UserID, time.Time) error
	DeleteUsers(context.Context, []UserID) error
}

type PasswordRepository interface {
	GetPasswordCredential(context.Context, UserID) (*PasswordCredential, error)
	UpsertPasswordCredential(context.Context, PasswordCredential) error
	DeletePasswordCredentials(context.Context, []UserID) error
}

type SessionRepository interface {
	CreateSession(context.Context, SessionRecord) error
	GetSessionByTokenHash(context.Context, []byte) (*SessionRecord, error)
	TouchSession(context.Context, SessionID, string, time.Time) error
	RevokeSession(context.Context, SessionID, string, string, time.Time) error
	DeleteSession(context.Context, SessionID) error
	RevokeSessionsForUsers(context.Context, []UserID, string, time.Time) error
	DeleteSessionsForUsers(context.Context, []UserID) error
}

// UnitOfWork is the smallest cross-repository transaction surface. Services
// that only need one repository should depend on that repository directly.
type UnitOfWork interface {
	Users() UserRepository
	Passwords() PasswordRepository
	Sessions() SessionRepository
}

type TxManager interface {
	WithinTx(context.Context, func(context.Context, UnitOfWork) error) error
}

type UserDirectory interface {
	UserByID(context.Context, UserID) (*User, error)
	UserByHandle(context.Context, string) (*User, error)
}

func DirectoryFromRepository(repository UserRepository) UserDirectory {
	if repository == nil {
		return nil
	}
	return repositoryDirectory{repository}
}

type repositoryDirectory struct{ UserRepository }

func (r repositoryDirectory) UserByID(ctx context.Context, id UserID) (*User, error) {
	return r.GetUser(ctx, id)
}

func (r repositoryDirectory) UserByHandle(ctx context.Context, handle string) (*User, error) {
	return r.GetUserByHandle(ctx, handle)
}

type SessionResolver interface {
	ResolveSession(context.Context, string, RequestMeta) (*Principal, error)
}

type ClaimsResolver func(context.Context, *User) (Claims, error)
type IDGenerator func() (UserID, error)
type Clock func() time.Time

type HandlePolicy interface {
	Normalize(string) (string, error)
}

type HandlePolicyFunc func(string) (string, error)

func (f HandlePolicyFunc) Normalize(value string) (string, error) {
	if f == nil {
		return "", ErrInvalidHandle
	}
	return f(value)
}

var (
	ErrNotFound           = errors.New("identity not found")
	ErrConflict           = errors.New("identity conflict")
	ErrInvalidHandle      = errors.New("invalid identity handle")
	ErrHandleTaken        = errors.New("identity handle already taken")
	ErrInvalidUser        = errors.New("invalid identity user")
	ErrDisabled           = errors.New("identity user disabled")
	ErrEmptySelection     = errors.New("empty identity selection")
	ErrInvalidState       = errors.New("invalid identity state")
	ErrInvalidRequestMeta = errors.New("invalid identity request metadata")
	ErrUnauthenticated    = errors.New("identity unauthenticated")
	ErrExpired            = errors.New("identity credential expired")
	ErrRevoked            = errors.New("identity credential revoked")
	ErrBindingMismatch    = errors.New("identity session binding mismatch")
	ErrWeakPassword       = errors.New("identity password does not meet policy")
	ErrUnsupported        = errors.New("identity operation unsupported")
)

func LowerASCIIHandlePolicy(raw string) (string, error) {
	value := strings.ToLower(strings.TrimSpace(raw))
	if value == "" || len(value) > 64 {
		return "", ErrInvalidHandle
	}
	var builder strings.Builder
	lastSeparator := false
	for _, r := range value {
		valid := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')
		if valid {
			builder.WriteRune(r)
			lastSeparator = false
			continue
		}
		if (r == '-' || r == '_') && builder.Len() > 0 && !lastSeparator {
			builder.WriteRune(r)
			lastSeparator = true
			continue
		}
		return "", ErrInvalidHandle
	}
	if lastSeparator {
		return "", ErrInvalidHandle
	}
	value = builder.String()
	if value == "" {
		return "", ErrInvalidHandle
	}
	return value, nil
}

func TrimHandlePolicy(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" || len(value) > 128 {
		return "", ErrInvalidHandle
	}
	return value, nil
}

func NormalizeRequestMeta(meta RequestMeta) (RequestMeta, error) {
	meta.ClientIP = strings.TrimSpace(meta.ClientIP)
	if meta.ClientIP != "" {
		if ip, err := netip.ParseAddr(meta.ClientIP); err != nil || !ip.IsValid() {
			return RequestMeta{}, ErrInvalidRequestMeta
		} else {
			meta.ClientIP = ip.String()
		}
	}
	meta.Scheme = strings.TrimSpace(strings.ToLower(meta.Scheme))
	meta.Host = strings.TrimSpace(meta.Host)
	meta.UserAgent = strings.TrimSpace(meta.UserAgent)
	meta.Method = strings.TrimSpace(meta.Method)
	meta.Path = strings.TrimSpace(meta.Path)
	meta.RemoteAddr = strings.TrimSpace(meta.RemoteAddr)
	return meta, nil
}

func ContextWithPrincipal(ctx context.Context, principal *Principal) context.Context {
	return context.WithValue(ctx, principalKey{}, principal)
}

func PrincipalFromContext(ctx context.Context) (*Principal, bool) {
	principal, ok := ctx.Value(principalKey{}).(*Principal)
	return principal, ok && principal != nil
}

type principalKey struct{}

func RequestMetaFromHTTP(r *http.Request) (RequestMeta, bool) {
	if r == nil {
		return RequestMeta{}, false
	}
	ip := r.RemoteAddr
	if host, _, err := net.SplitHostPort(ip); err == nil {
		ip = host
	}
	meta := RequestMeta{ClientIP: ip, Scheme: "http", Host: r.Host, UserAgent: r.UserAgent(), Method: r.Method, Path: r.URL.Path, RemoteAddr: r.RemoteAddr}
	if r.TLS != nil {
		meta.Scheme = "https"
	}
	normalized, err := NormalizeRequestMeta(meta)
	if err != nil {
		return RequestMeta{}, false
	}
	return normalized, true
}
