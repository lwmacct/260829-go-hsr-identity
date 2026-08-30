package domain

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
	"uuid"

	"github.com/uptrace/bun"
	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"
)

// IDs are UUID values, never opaque strings. All IDs created by identity are
// UUIDv7; the validation helpers reject other UUID versions at the boundary.
type UserID = uuid.UUID
type SessionID = uuid.UUID
type RoleID = uuid.UUID
type PermissionID = uuid.UUID
type State string

const (
	StateActive   State = "active"
	StateDisabled State = "disabled"
)

func NormalizeUserID(id UserID) (UserID, error) {
	if !isUUIDv7(id) {
		return uuid.Nil(), ErrInvalidUser
	}
	return id, nil
}

func ValidateUserID(id UserID) error {
	_, err := NormalizeUserID(id)
	return err
}

func ParseUserID(raw string) (UserID, error) {
	id, err := uuid.Parse(strings.TrimSpace(raw))
	if err != nil {
		return uuid.Nil(), ErrInvalidUser
	}
	return NormalizeUserID(id)
}

func NormalizeSessionID(id SessionID) (SessionID, error) {
	if !isUUIDv7(id) {
		return uuid.Nil(), ErrInvalid
	}
	return id, nil
}

func isUUIDv7(id uuid.UUID) bool {
	return id != uuid.Nil() && id[6]>>4 == 7
}

func ValidateSessionID(id SessionID) error {
	_, err := NormalizeSessionID(id)
	return err
}

func ParseSessionID(raw string) (SessionID, error) {
	id, err := uuid.Parse(strings.TrimSpace(raw))
	if err != nil {
		return uuid.Nil(), ErrInvalid
	}
	return NormalizeSessionID(id)
}

func NormalizeRoleID(id RoleID) (RoleID, error) {
	if !isUUIDv7(id) {
		return uuid.Nil(), ErrInvalid
	}
	return id, nil
}

func NormalizePermissionID(id PermissionID) (PermissionID, error) {
	if !isUUIDv7(id) {
		return uuid.Nil(), ErrInvalid
	}
	return id, nil
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
	Username    string
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
	return u != nil && u.ID != uuid.Nil() && u.State == StateActive && u.DisabledAt == nil
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
	return p != nil && p.User != nil && p.Subject == p.User.ID && p.User.Active()
}

type RequestMeta struct {
	ClientIP  string
	UserAgent string
}

type EventType string

const (
	EventUserCreated            EventType = "identity.user.created"
	EventUserUpdated            EventType = "identity.user.updated"
	EventUserStateChanged       EventType = "identity.user.state_changed"
	EventUserDeleted            EventType = "identity.user.deleted"
	EventBootstrapCompleted     EventType = "identity.bootstrap.completed"
	EventLoginSucceeded         EventType = "identity.login.succeeded"
	EventLoginFailed            EventType = "identity.login.failed"
	EventPasswordChanged        EventType = "identity.password.changed"
	EventPasswordReset          EventType = "identity.password.reset"
	EventSessionCreated         EventType = "identity.session.created"
	EventSessionRevoked         EventType = "identity.session.revoked"
	EventUserSessionsRevoked    EventType = "identity.session.revoked_for_user"
	EventExpiredSessionsDeleted EventType = "identity.session.expired_deleted"
	EventRoleCreated            EventType = "identity.role.created"
	EventRoleUpdated            EventType = "identity.role.updated"
	EventRoleDeleted            EventType = "identity.role.deleted"
	EventPermissionCreated      EventType = "identity.permission.created"
	EventPermissionUpdated      EventType = "identity.permission.updated"
	EventPermissionDeleted      EventType = "identity.permission.deleted"
	EventUserRolesChanged       EventType = "identity.user_roles.changed"
	EventRolePermissionsChanged EventType = "identity.role_permissions.changed"
)

// Event is a committed identity fact exposed to host audit and telemetry
// integrations. Zero-valued IDs mean the event does not concern that entity.
type Event struct {
	Type         EventType
	At           time.Time
	UserID       UserID
	SessionID    SessionID
	RoleID       RoleID
	PermissionID PermissionID
	Username     string
	RequestMeta  RequestMeta
	Attributes   map[string]string
}

// EventSink observes identity facts after the related database operation has
// succeeded. It intentionally cannot fail or roll back the completed action.
type EventSink interface {
	Record(context.Context, Event)
}

type EventSinkFunc func(context.Context, Event)

func (f EventSinkFunc) Record(ctx context.Context, event Event) {
	if f != nil {
		f(ctx, event)
	}
}

type LoginGuard interface {
	Allow(context.Context, string, RequestMeta) error
	Record(context.Context, string, RequestMeta, bool)
}

type UserCreate struct {
	ID          UserID
	Username    string
	UsernameKey string
	DisplayName string
	Email       string
	AvatarURL   string
	State       State
	DisabledAt  *time.Time
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type UserCreateInput struct {
	Username    string
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
	ExpiresAt     time.Time
	CreatedAt     time.Time
	LastSeenAt    time.Time
	RevokedAt     *time.Time
	RevokedReason string
}

// Session is the public, non-secret view of an identity session.
type Session struct {
	ID            SessionID
	UserID        UserID
	LoginIP       string
	LastIP        string
	ExpiresAt     time.Time
	CreatedAt     time.Time
	LastSeenAt    time.Time
	RevokedAt     *time.Time
	RevokedReason string
}

type IssuedSession struct {
	Session *Session
	Token   string
}

type UserRepository interface {
	CreateUser(context.Context, UserCreate) (*User, error)
	GetUser(context.Context, UserID) (*User, error)
	GetUserByUsernameKey(context.Context, string) (*User, error)
	ListUsers(context.Context, UserFilter) ([]User, int, error)
	UpdateUserProfile(context.Context, UserID, UserProfilePatch) (*User, error)
	UpdateUserState(context.Context, []UserID, State, *time.Time, time.Time) (int64, error)
	MarkUserLogin(context.Context, UserID, time.Time) error
	DeleteUsers(context.Context, []UserID) error
}

type PasswordRepository interface {
	GetPasswordCredential(context.Context, UserID) (*PasswordCredential, error)
	UpsertPasswordCredential(context.Context, PasswordCredential) error
	UpdatePasswordCredentialIfMatch(context.Context, UserID, string, string, PasswordCredential) (bool, error)
	DeletePasswordCredentials(context.Context, []UserID) error
}

type SessionRepository interface {
	CreateSession(context.Context, SessionRecord) error
	GetSessionByTokenHash(context.Context, []byte) (*SessionRecord, error)
	ListSessionsForUser(context.Context, UserID) ([]SessionRecord, error)
	TouchSession(context.Context, SessionID, string, time.Time, time.Time) error
	RevokeSession(context.Context, SessionID, string, string, time.Time) error
	DeleteSession(context.Context, SessionID) error
	RevokeSessionsForUsers(context.Context, []UserID, string, time.Time) error
	DeleteSessionsForUsers(context.Context, []UserID) error
	DeleteExpiredSessions(context.Context, time.Time) (int64, error)
}

// AuthorizationRepository stores the generic role/permission graph. Codes are
// stable integration identifiers; IDs are UUIDv7 database identifiers.
type AuthorizationRepository interface {
	ListRoles(context.Context, RoleFilter) ([]Role, int, error)
	GetRole(context.Context, RoleID) (*Role, error)
	GetRoleByCode(context.Context, string) (*Role, error)
	UpsertRole(context.Context, Role) (*Role, error)
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
	UpsertPermission(context.Context, Permission) (*Permission, error)
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

// TxManagerWithDB is implemented by Bun-backed transaction managers that can
// expose the active transaction to host-owned delete participants. The plain
// TxManager contract remains sufficient for identity-only operations.
type TxManagerWithDB interface {
	TxManager
	WithinTxDB(context.Context, func(context.Context, bun.IDB, UnitOfWork) error) error
}

type UserDirectory interface {
	UserByID(context.Context, UserID) (*User, error)
	UserByUsername(context.Context, string) (*User, error)
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
func (r repositoryDirectory) UserByUsername(ctx context.Context, username string) (*User, error) {
	return r.GetUserByUsernameKey(ctx, UsernameKey(username))
}

type SessionResolver interface {
	Resolve(context.Context, string, RequestMeta) (*Principal, error)
}

type ClaimsResolver func(context.Context, *User) (Claims, error)

type Clock func() time.Time
type UsernamePolicy interface{ Normalize(string) (string, error) }
type UsernamePolicyFunc func(string) (string, error)

func (f UsernamePolicyFunc) Normalize(value string) (string, error) {
	if f == nil {
		return "", ErrInvalidUsername
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
	ErrInvalidUsername    = fmt.Errorf("%w: invalid identity username", ErrInvalid)
	ErrUsernameTaken      = errors.New("identity username already taken")
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
	ErrRateLimited        = errors.New("identity rate limited")
)

func LowerASCIIUsernamePolicy(raw string) (string, error) {
	value := strings.ToLower(strings.TrimSpace(raw))
	if value == "" || len(value) > 64 {
		return "", ErrInvalidUsername
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
		return "", ErrInvalidUsername
	}
	if b.Len() == 0 || lastSeparator {
		return "", ErrInvalidUsername
	}
	return b.String(), nil
}

func TrimUsernamePolicy(raw string) (string, error) {
	value := norm.NFC.String(strings.TrimSpace(raw))
	if value == "" || utf8.RuneCountInString(value) > 128 {
		return "", ErrInvalidUsername
	}
	for _, r := range value {
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			return "", ErrInvalidUsername
		}
	}
	return value, nil
}

// UsernameKey returns the canonical comparison key used for username lookup
// and uniqueness. The displayed username is preserved separately.
func UsernameKey(value string) string {
	return norm.NFC.String(cases.Fold().String(norm.NFC.String(strings.TrimSpace(value))))
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
