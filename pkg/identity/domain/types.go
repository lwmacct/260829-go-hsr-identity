package domain

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"
	"uuid"
)

type UserID string
type SessionID string
type RoleID string
type PermissionID string
type State string

const (
	StateActive   State = "active"
	StateDisabled State = "disabled"
)

// NormalizeUserID and NormalizeSessionID enforce canonical UUIDv7 text used by
// the Bun schema and HTTP contract. IDs remain named strings at the domain
// boundary so hosts can pass them through without conversion.
func NormalizeUserID(id UserID) (UserID, error) {
	parsed, ok := parseUUIDv7(string(id))
	if !ok {
		return "", ErrInvalidUser
	}
	return UserID(parsed.String()), nil
}

func ValidateUserID(id UserID) error {
	_, err := NormalizeUserID(id)
	return err
}

func NormalizeSessionID(id SessionID) (SessionID, error) {
	parsed, ok := parseUUIDv7(string(id))
	if !ok {
		return "", ErrInvalid
	}
	return SessionID(parsed.String()), nil
}

func parseUUIDv7(raw string) (uuid.UUID, bool) {
	parsed, err := uuid.Parse(strings.TrimSpace(raw))
	return parsed, err == nil && parsed != uuid.Nil() && parsed[6]>>4 == 7
}

func ValidateSessionID(id SessionID) error {
	_, err := NormalizeSessionID(id)
	return err
}

func NormalizeRoleID(id RoleID) (RoleID, error) {
	parsed, ok := parseUUIDv7(string(id))
	if !ok {
		return "", ErrInvalid
	}
	return RoleID(parsed.String()), nil
}

func NormalizePermissionID(id PermissionID) (PermissionID, error) {
	parsed, ok := parseUUIDv7(string(id))
	if !ok {
		return "", ErrInvalid
	}
	return PermissionID(parsed.String()), nil
}

func ValidateRoleID(id RoleID) error {
	_, err := NormalizeRoleID(id)
	return err
}

func ValidatePermissionID(id PermissionID) error {
	_, err := NormalizePermissionID(id)
	return err
}

// Authorizer action names are stable integration points for host applications.
const (
	ActionUserList             = "identity.user.list"
	ActionUserCreate           = "identity.user.create"
	ActionUserRead             = "identity.user.read"
	ActionUserUpdate           = "identity.user.update"
	ActionUserResetPassword    = "identity.user.reset_password"
	ActionUserDelete           = "identity.user.delete"
	ActionRoleList             = "identity.role.list"
	ActionRoleCreate           = "identity.role.create"
	ActionRoleRead             = "identity.role.read"
	ActionRoleUpdate           = "identity.role.update"
	ActionRoleDelete           = "identity.role.delete"
	ActionPermissionList       = "identity.permission.list"
	ActionPermissionCreate     = "identity.permission.create"
	ActionPermissionRead       = "identity.permission.read"
	ActionPermissionUpdate     = "identity.permission.update"
	ActionPermissionDelete     = "identity.permission.delete"
	ActionUserRoleManage       = "identity.user_role.manage"
	ActionRolePermissionManage = "identity.role_permission.manage"
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
	ExpiresAt       time.Time
}

func (p *Principal) Active() bool {
	return p != nil && p.Subject != "" && p.User != nil && p.User.Active()
}

type RequestMeta struct {
	ClientIP  string
	UserAgent string
	DeviceID  string
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

type UserCreateInput struct {
	Handle      string
	DisplayName string
	Email       string
	AvatarURL   string
	State       State
}

// BootstrapInput describes the first privileged account for an application.
// Role codes are supplied by the host so identity remains independent of any
// particular administrator role name.
type BootstrapInput struct {
	User      UserCreateInput
	Password  string
	RoleCodes []string
}

type UserUpdateProfileInput struct {
	DisplayName string
	Email       string
	AvatarURL   string
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

type Role struct {
	ID          RoleID
	Code        string
	Name        string
	Description string
	System      bool
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type Permission struct {
	ID          PermissionID
	Code        string
	Name        string
	Description string
	System      bool
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type RoleFilter struct {
	Keyword  string
	Page     int
	PageSize int
}

type PermissionFilter struct {
	Keyword  string
	Page     int
	PageSize int
}

type RoleInput struct {
	Code        string
	Name        string
	Description string
	System      bool
}

type PermissionInput struct {
	Code        string
	Name        string
	Description string
	System      bool
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

type IssuedSession struct {
	Session *SessionRecord
	Token   string
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

// AuthorizationRepository stores the generic role/permission graph. Codes are
// stable integration identifiers; IDs are UUIDv7 database identifiers.
type AuthorizationRepository interface {
	ListRoles(context.Context, RoleFilter) ([]Role, int, error)
	GetRole(context.Context, RoleID) (*Role, error)
	GetRoleByCode(context.Context, string) (*Role, error)
	// LockRoleByCode returns a role while holding the transaction lock needed
	// for one-time bootstrap operations.
	LockRoleByCode(context.Context, string) (*Role, error)
	CountRoleUsers(context.Context, RoleID) (int, error)
	CreateRole(context.Context, Role) (*Role, error)
	UpdateRole(context.Context, RoleID, RoleInput, time.Time) (*Role, error)
	DeleteRole(context.Context, RoleID) error
	ListPermissions(context.Context, PermissionFilter) ([]Permission, int, error)
	GetPermission(context.Context, PermissionID) (*Permission, error)
	GetPermissionByCode(context.Context, string) (*Permission, error)
	CreatePermission(context.Context, Permission) (*Permission, error)
	UpdatePermission(context.Context, PermissionID, PermissionInput, time.Time) (*Permission, error)
	DeletePermission(context.Context, PermissionID) error
	ListUserRoles(context.Context, UserID) ([]Role, error)
	ReplaceUserRoles(context.Context, UserID, []RoleID) error
	ListRolePermissions(context.Context, RoleID) ([]Permission, error)
	ReplaceRolePermissions(context.Context, RoleID, []PermissionID) error
	ListUserClaims(context.Context, UserID) (Claims, error)
}

type UnitOfWork interface {
	Users() UserRepository
	Passwords() PasswordRepository
	Sessions() SessionRepository
	Authorization() AuthorizationRepository
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
	Resolve(context.Context, string, RequestMeta) (*Principal, error)
}

type ClaimsResolver func(context.Context, *User) (Claims, error)

type Clock func() time.Time
type HandlePolicy interface{ Normalize(string) (string, error) }
type HandlePolicyFunc func(string) (string, error)

func (f HandlePolicyFunc) Normalize(value string) (string, error) {
	if f == nil {
		return "", ErrInvalidHandle
	}
	return f(value)
}

type ValidationError struct {
	Field string
	Code  string
	Cause error
}

func (e *ValidationError) Error() string {
	if e == nil || (e.Field == "" && e.Code == "") {
		return ErrInvalid.Error()
	}
	if e.Field == "" {
		return e.Code
	}
	if e.Code == "" {
		return e.Field + " is invalid"
	}
	return e.Field + ": " + e.Code
}
func (e *ValidationError) Unwrap() error {
	if e == nil || e.Cause == nil {
		return ErrInvalid
	}
	return e.Cause
}

var (
	ErrInvalid            = errors.New("identity invalid")
	ErrNotFound           = errors.New("identity not found")
	ErrConflict           = errors.New("identity conflict")
	ErrInvalidHandle      = fmt.Errorf("%w: invalid identity handle", ErrInvalid)
	ErrHandleTaken        = errors.New("identity handle already taken")
	ErrBootstrapCompleted = errors.New("identity bootstrap already completed")
	ErrInvalidUser        = fmt.Errorf("%w: invalid identity user", ErrInvalid)
	ErrDisabled           = errors.New("identity user disabled")
	ErrEmptySelection     = errors.New("empty identity selection")
	ErrInvalidState       = fmt.Errorf("%w: invalid identity state", ErrInvalid)
	ErrInvalidRequestMeta = fmt.Errorf("%w: invalid identity request metadata", ErrInvalid)
	ErrUnauthenticated    = errors.New("identity unauthenticated")
	ErrExpired            = errors.New("identity credential expired")
	ErrRevoked            = errors.New("identity credential revoked")
	ErrBindingMismatch    = errors.New("identity session binding mismatch")
	ErrWeakPassword       = fmt.Errorf("%w: identity password does not meet policy", ErrInvalid)
	ErrUnsupported        = errors.New("identity operation unsupported")
	ErrForbidden          = errors.New("identity forbidden")
)

func LowerASCIIHandlePolicy(raw string) (string, error) {
	value := strings.ToLower(strings.TrimSpace(raw))
	if value == "" || len(value) > 64 {
		return "", ErrInvalidHandle
	}
	var b strings.Builder
	lastSeparator := false
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			lastSeparator = false
			continue
		}
		if (r == '-' || r == '_') && b.Len() > 0 && !lastSeparator {
			b.WriteRune(r)
			lastSeparator = true
			continue
		}
		return "", ErrInvalidHandle
	}
	if b.Len() == 0 || lastSeparator {
		return "", ErrInvalidHandle
	}
	return b.String(), nil
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
		ip, err := netip.ParseAddr(meta.ClientIP)
		if err != nil || !ip.IsValid() {
			return RequestMeta{}, &ValidationError{Field: "client_ip", Code: "invalid_ip", Cause: ErrInvalidRequestMeta}
		}
		meta.ClientIP = ip.String()
	}
	meta.UserAgent = strings.TrimSpace(meta.UserAgent)
	meta.DeviceID = strings.TrimSpace(meta.DeviceID)
	return meta, nil
}

type principalKey struct{}

func ContextWithPrincipal(ctx context.Context, principal *Principal) context.Context {
	return context.WithValue(ctx, principalKey{}, principal)
}
func PrincipalFromContext(ctx context.Context) (*Principal, bool) {
	p, ok := ctx.Value(principalKey{}).(*Principal)
	return p, ok && p != nil
}
