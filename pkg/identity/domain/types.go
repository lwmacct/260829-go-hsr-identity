package domain

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/mail"
	"net/netip"
	"strings"
	"time"
	"uuid"
)

// IDs are UUID values, never opaque strings. All IDs created by identity are
// UUIDv7; the validation helpers reject other UUID versions at the boundary.
type UserID uuid.UUID
type SessionID uuid.UUID
type RoleID uuid.UUID
type PermissionID uuid.UUID
type ContactID uuid.UUID
type ContactVerificationID uuid.UUID
type State string

func (id UserID) String() string                { return uuid.UUID(id).String() }
func (id SessionID) String() string             { return uuid.UUID(id).String() }
func (id RoleID) String() string                { return uuid.UUID(id).String() }
func (id PermissionID) String() string          { return uuid.UUID(id).String() }
func (id ContactID) String() string             { return uuid.UUID(id).String() }
func (id ContactVerificationID) String() string { return uuid.UUID(id).String() }

func (id UserID) MarshalText() ([]byte, error)       { return []byte(id.String()), nil }
func (id SessionID) MarshalText() ([]byte, error)    { return []byte(id.String()), nil }
func (id RoleID) MarshalText() ([]byte, error)       { return []byte(id.String()), nil }
func (id PermissionID) MarshalText() ([]byte, error) { return []byte(id.String()), nil }
func (id ContactID) MarshalText() ([]byte, error)    { return []byte(id.String()), nil }
func (id ContactVerificationID) MarshalText() ([]byte, error) {
	return []byte(id.String()), nil
}

func (id *UserID) UnmarshalText(raw []byte) error {
	parsed, err := ParseUserID(string(raw))
	if err != nil {
		return err
	}
	*id = parsed
	return nil
}

func (id *SessionID) UnmarshalText(raw []byte) error {
	parsed, err := ParseSessionID(string(raw))
	if err != nil {
		return err
	}
	*id = parsed
	return nil
}

func (id *RoleID) UnmarshalText(raw []byte) error {
	parsed, err := ParseRoleID(string(raw))
	if err != nil {
		return err
	}
	*id = parsed
	return nil
}

func (id *PermissionID) UnmarshalText(raw []byte) error {
	parsed, err := ParsePermissionID(string(raw))
	if err != nil {
		return err
	}
	*id = parsed
	return nil
}

func (id *ContactID) UnmarshalText(raw []byte) error {
	parsed, err := ParseContactID(string(raw))
	if err != nil {
		return err
	}
	*id = parsed
	return nil
}

func (id *ContactVerificationID) UnmarshalText(raw []byte) error {
	parsed, err := ParseContactVerificationID(string(raw))
	if err != nil {
		return err
	}
	*id = parsed
	return nil
}

const (
	StateActive   State = "active"
	StateDisabled State = "disabled"
)

func NormalizeUserID(id UserID) (UserID, error) {
	if !isUUIDv7(uuid.UUID(id)) {
		return UserID(uuid.Nil()), ErrInvalidUser
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
		return UserID(uuid.Nil()), ErrInvalidUser
	}
	return NormalizeUserID(UserID(id))
}

func NormalizeSessionID(id SessionID) (SessionID, error) {
	if !isUUIDv7(uuid.UUID(id)) {
		return SessionID(uuid.Nil()), ErrInvalid
	}
	return id, nil
}

func isUUIDv7(id uuid.UUID) bool {
	return id != uuid.Nil() && id[6]>>4 == 7 && id[8]&0xc0 == 0x80
}

func ValidateSessionID(id SessionID) error {
	_, err := NormalizeSessionID(id)
	return err
}

func ParseSessionID(raw string) (SessionID, error) {
	id, err := uuid.Parse(strings.TrimSpace(raw))
	if err != nil {
		return SessionID(uuid.Nil()), ErrInvalid
	}
	return NormalizeSessionID(SessionID(id))
}

func NormalizeRoleID(id RoleID) (RoleID, error) {
	if !isUUIDv7(uuid.UUID(id)) {
		return RoleID(uuid.Nil()), ErrInvalid
	}
	return id, nil
}

func NormalizePermissionID(id PermissionID) (PermissionID, error) {
	if !isUUIDv7(uuid.UUID(id)) {
		return PermissionID(uuid.Nil()), ErrInvalid
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

func ParseRoleID(raw string) (RoleID, error) {
	id, err := uuid.Parse(strings.TrimSpace(raw))
	if err != nil {
		return RoleID(uuid.Nil()), ErrInvalid
	}
	return NormalizeRoleID(RoleID(id))
}

func ParsePermissionID(raw string) (PermissionID, error) {
	id, err := uuid.Parse(strings.TrimSpace(raw))
	if err != nil {
		return PermissionID(uuid.Nil()), ErrInvalid
	}
	return NormalizePermissionID(PermissionID(id))
}

func NormalizeContactID(id ContactID) (ContactID, error) {
	if !isUUIDv7(uuid.UUID(id)) {
		return ContactID(uuid.Nil()), ErrInvalid
	}
	return id, nil
}

func NormalizeContactVerificationID(id ContactVerificationID) (ContactVerificationID, error) {
	if !isUUIDv7(uuid.UUID(id)) {
		return ContactVerificationID(uuid.Nil()), ErrInvalid
	}
	return id, nil
}

func ParseContactID(raw string) (ContactID, error) {
	id, err := uuid.Parse(strings.TrimSpace(raw))
	if err != nil {
		return ContactID(uuid.Nil()), ErrInvalid
	}
	return NormalizeContactID(ContactID(id))
}

func ParseContactVerificationID(raw string) (ContactVerificationID, error) {
	id, err := uuid.Parse(strings.TrimSpace(raw))
	if err != nil {
		return ContactVerificationID(uuid.Nil()), ErrInvalid
	}
	return NormalizeContactVerificationID(ContactVerificationID(id))
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
	AvatarURL   string
	State       State
	DisabledAt  *time.Time
	LastLoginAt *time.Time
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

func (u *User) Active() bool {
	return u != nil && u.ID != (UserID{}) && u.State == StateActive && u.DisabledAt == nil
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
	EventUserCreated                  EventType = "identity.user.created"
	EventUserUpdated                  EventType = "identity.user.updated"
	EventUserStateChanged             EventType = "identity.user.state_changed"
	EventUserDeleted                  EventType = "identity.user.deleted"
	EventLoginSucceeded               EventType = "identity.login.succeeded"
	EventLoginFailed                  EventType = "identity.login.failed"
	EventPasswordChanged              EventType = "identity.password.changed"
	EventPasswordReset                EventType = "identity.password.reset"
	EventSessionCreated               EventType = "identity.session.created"
	EventSessionRevoked               EventType = "identity.session.revoked"
	EventUserSessionsRevoked          EventType = "identity.session.revoked_for_user"
	EventExpiredSessionsDeleted       EventType = "identity.session.expired_deleted"
	EventRoleCreated                  EventType = "identity.role.created"
	EventRoleUpdated                  EventType = "identity.role.updated"
	EventRoleDeleted                  EventType = "identity.role.deleted"
	EventPermissionCreated            EventType = "identity.permission.created"
	EventPermissionUpdated            EventType = "identity.permission.updated"
	EventPermissionDeleted            EventType = "identity.permission.deleted"
	EventUserRolesChanged             EventType = "identity.user_roles.changed"
	EventRolePermissionsChanged       EventType = "identity.role_permissions.changed"
	EventContactVerificationStarted   EventType = "identity.contact.verification_started"
	EventContactVerificationSucceeded EventType = "identity.contact.verification_succeeded"
	EventContactVerificationFailed    EventType = "identity.contact.verification_failed"
	EventContactBound                 EventType = "identity.contact.bound"
	EventContactUnbound               EventType = "identity.contact.unbound"
)

// Event is a committed identity fact exposed to host audit and telemetry
// integrations. Zero-valued IDs mean the event does not concern that entity.
type Event struct {
	Type           EventType
	At             time.Time
	UserID         UserID
	SessionID      SessionID
	RoleID         RoleID
	PermissionID   PermissionID
	Username       string
	IdentifierType LoginIdentifierKind
	RequestMeta    RequestMeta
	Attributes     map[string]string
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

type LoginAttempt struct {
	IdentifierType LoginIdentifierKind
	// IdentifierKey is an opaque bounded throttling key. It never contains the
	// raw username, phone number, email address, or malformed input.
	IdentifierKey string
	RequestMeta   RequestMeta
}

type LoginIdentifierKind string

const (
	LoginIdentifierUsername LoginIdentifierKind = "username"
	LoginIdentifierPhone    LoginIdentifierKind = "phone"
	LoginIdentifierEmail    LoginIdentifierKind = "email"
	LoginIdentifierInvalid  LoginIdentifierKind = "invalid"

	MaxUsernameLength        = 64
	MaxPhoneLength           = 16
	MaxEmailLength           = 254
	MaxLoginIdentifierLength = MaxEmailLength
)

type LoginIdentifier struct {
	Kind  LoginIdentifierKind
	Value string
}

type LoginGuard interface {
	Allow(context.Context, LoginAttempt) error
	Record(context.Context, LoginAttempt, bool)
}

type UserCreate struct {
	ID          UserID
	Username    string
	DisplayName string
	AvatarURL   string
	State       State
	DisabledAt  *time.Time
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type UserCreateInput struct {
	Username    string
	DisplayName string
	AvatarURL   string
	State       State
}

// UserProvisionInput describes a user account with explicit role bindings.
// It is intended for trusted host-side provisioning, not public registration.
type UserProvisionInput struct {
	User      UserCreateInput
	Password  string
	RoleCodes []string
}

type UserUpdateProfileInput struct {
	DisplayName string
	AvatarURL   *string
}

type UserProfilePatch struct {
	DisplayName string
	AvatarURL   *string
	UpdatedAt   time.Time
}

type ContactKind string

const (
	ContactKindPhone ContactKind = "phone"
	ContactKindEmail ContactKind = "email"
)

func (k ContactKind) Valid() bool {
	return k == ContactKindPhone || k == ContactKindEmail
}

type ContactVerificationStatus string

const (
	ContactVerificationPending   ContactVerificationStatus = "pending"
	ContactVerificationConsumed  ContactVerificationStatus = "consumed"
	ContactVerificationExpired   ContactVerificationStatus = "expired"
	ContactVerificationCancelled ContactVerificationStatus = "cancelled"
	ContactVerificationFailed    ContactVerificationStatus = "failed"
)

type UserContact struct {
	ID         ContactID
	UserID     UserID
	Kind       ContactKind
	Value      string
	VerifiedAt time.Time
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

type ContactVerification struct {
	ID                  ContactVerificationID
	UserID              UserID
	Kind                ContactKind
	Value               string
	Provider            string
	ProviderChallengeID string
	Status              ContactVerificationStatus
	AttemptCount        int
	ExpiresAt           time.Time
	CreatedAt           time.Time
	ConsumedAt          *time.Time
}

type ContactVerificationStart struct {
	UserID      UserID
	Kind        ContactKind
	Value       string
	RequestMeta RequestMeta
}

type ContactVerificationChallenge struct {
	Provider    string
	ChallengeID string
	ExpiresAt   time.Time
}

type ContactVerificationVerify struct {
	UserID      UserID
	Kind        ContactKind
	ChallengeID string
	Code        string
	RequestMeta RequestMeta
}

type ContactVerificationProvider interface {
	Name() string
	Start(context.Context, ContactVerificationStart) (ContactVerificationChallenge, error)
	Verify(context.Context, ContactVerificationVerify) error
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
	GetUserByLoginIdentifier(context.Context, LoginIdentifier) (*User, error)
	ListUsers(context.Context, UserFilter) ([]User, int, error)
	UpdateUserProfile(context.Context, UserID, UserProfilePatch) (*User, error)
	UpdateUserState(context.Context, []UserID, State, *time.Time, time.Time) (int64, error)
	MarkUserLogin(context.Context, UserID, time.Time) error
	DeleteUsers(context.Context, []UserID) error
}

type ContactRepository interface {
	ListUserContacts(context.Context, UserID) ([]UserContact, error)
	GetUserContact(context.Context, UserID, ContactKind) (*UserContact, error)
	GetUserByContact(context.Context, ContactKind, string) (*User, error)
	ReplaceUserContact(context.Context, UserContact) error
	DeleteUserContact(context.Context, UserID, ContactKind) error
	GetContactVerification(context.Context, ContactVerificationID) (*ContactVerification, error)
	GetPendingContactVerification(context.Context, UserID, ContactKind) (*ContactVerification, error)
	CreateContactVerification(context.Context, ContactVerification) error
	UpdateContactVerification(context.Context, ContactVerification) error
	RecordContactVerificationFailure(context.Context, ContactVerificationID, int, time.Time) (*ContactVerification, error)
	CancelPendingContactVerifications(context.Context, UserID, ContactKind, ContactVerificationID) error
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
	ReplaceUserRoles(context.Context, UserID, []RoleID, time.Time) error
	ListRolePermissions(context.Context, RoleID) ([]Permission, error)
	ReplaceRolePermissions(context.Context, RoleID, []PermissionID, time.Time) error
	ListUserClaims(context.Context, UserID) (Claims, error)
}

type UserDirectory interface {
	UserByID(context.Context, UserID) (*User, error)
	UserByLoginIdentifier(context.Context, LoginIdentifier) (*User, error)
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
func (r repositoryDirectory) UserByLoginIdentifier(ctx context.Context, identifier LoginIdentifier) (*User, error) {
	return r.GetUserByLoginIdentifier(ctx, identifier)
}

type SessionResolver interface {
	Resolve(context.Context, string, RequestMeta) (*Principal, error)
}

type ClaimsResolver func(context.Context, *User) (Claims, error)

type Clock func() time.Time

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
	ErrInvalid                 = errors.New("identity invalid")
	ErrNotFound                = errors.New("identity not found")
	ErrConflict                = errors.New("identity conflict")
	ErrInvalidUsername         = fmt.Errorf("%w: invalid identity username", ErrInvalid)
	ErrUsernameTaken           = errors.New("identity username already taken")
	ErrInvalidPhone            = fmt.Errorf("%w: invalid identity phone", ErrInvalid)
	ErrInvalidEmail            = fmt.Errorf("%w: invalid identity email", ErrInvalid)
	ErrInvalidIdentifier       = fmt.Errorf("%w: invalid identity login identifier", ErrInvalid)
	ErrInvalidContactKind      = fmt.Errorf("%w: invalid identity contact kind", ErrInvalid)
	ErrContactTaken            = errors.New("identity contact already taken")
	ErrContactNotFound         = errors.New("identity contact not found")
	ErrVerificationNotFound    = errors.New("identity contact verification not found")
	ErrVerificationExpired     = errors.New("identity contact verification expired")
	ErrVerificationInvalid     = errors.New("identity contact verification invalid")
	ErrVerificationUnavailable = errors.New("identity contact verification unavailable")
	ErrVerificationUnsupported = errors.New("identity contact verification unsupported")
	ErrInvalidUser             = fmt.Errorf("%w: invalid identity user", ErrInvalid)
	ErrDisabled                = errors.New("identity user disabled")
	ErrEmptySelection          = errors.New("empty identity selection")
	ErrInvalidState            = fmt.Errorf("%w: invalid identity state", ErrInvalid)
	ErrInvalidRequestMeta      = fmt.Errorf("%w: invalid identity request metadata", ErrInvalid)
	ErrUnauthenticated         = errors.New("identity unauthenticated")
	ErrExpired                 = errors.New("identity credential expired")
	ErrRevoked                 = errors.New("identity credential revoked")
	ErrBindingMismatch         = errors.New("identity session binding mismatch")
	ErrWeakPassword            = fmt.Errorf("%w: identity password does not meet policy", ErrInvalid)
	ErrUnsupported             = errors.New("identity operation unsupported")
	ErrForbidden               = errors.New("identity forbidden")
	ErrRateLimited             = errors.New("identity rate limited")
)

func NormalizeUsername(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" || len(value) > MaxUsernameLength {
		return "", ErrInvalidUsername
	}
	if value[0] < 'a' || value[0] > 'z' {
		return "", ErrInvalidUsername
	}
	last := value[len(value)-1]
	if !((last >= 'a' && last <= 'z') || (last >= '0' && last <= '9')) {
		return "", ErrInvalidUsername
	}
	for i := 1; i < len(value); i++ {
		switch c := value[i]; {
		case c >= 'a' && c <= 'z':
			continue
		case c >= '0' && c <= '9':
			continue
		case c == '-' || c == '_':
			continue
		default:
			return "", ErrInvalidUsername
		}
	}
	return value, nil
}

func NormalizePhone(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", nil
	}
	if len(value) < 8 || len(value) > MaxPhoneLength || value[0] != '+' {
		return "", ErrInvalidPhone
	}
	if value[1] < '1' || value[1] > '9' {
		return "", ErrInvalidPhone
	}
	for i := 2; i < len(value); i++ {
		if value[i] < '0' || value[i] > '9' {
			return "", ErrInvalidPhone
		}
	}
	return value, nil
}

func NormalizeEmail(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", nil
	}
	if len(value) > MaxEmailLength {
		return "", ErrInvalidEmail
	}
	address, err := mail.ParseAddress(value)
	if err != nil || address.Address != value {
		return "", ErrInvalidEmail
	}
	value = strings.ToLower(value)
	if address, err = mail.ParseAddress(value); err != nil || address.Address != value {
		return "", ErrInvalidEmail
	}
	return value, nil
}

func NormalizeLoginIdentifier(raw string) (LoginIdentifier, error) {
	if len(raw) > MaxLoginIdentifierLength {
		return LoginIdentifier{}, ErrInvalidIdentifier
	}
	value := strings.TrimSpace(raw)
	if value == "" {
		return LoginIdentifier{}, ErrInvalidIdentifier
	}
	if strings.Contains(value, "@") {
		normalized, err := NormalizeEmail(value)
		if err != nil {
			return LoginIdentifier{}, ErrInvalidIdentifier
		}
		return LoginIdentifier{Kind: LoginIdentifierEmail, Value: normalized}, nil
	}
	if strings.HasPrefix(value, "+") {
		normalized, err := NormalizePhone(value)
		if err != nil {
			return LoginIdentifier{}, ErrInvalidIdentifier
		}
		return LoginIdentifier{Kind: LoginIdentifierPhone, Value: normalized}, nil
	}
	normalized, err := NormalizeUsername(value)
	if err != nil {
		return LoginIdentifier{}, ErrInvalidIdentifier
	}
	return LoginIdentifier{Kind: LoginIdentifierUsername, Value: normalized}, nil
}

// LoginAttemptKey returns a stable, non-PII key for login throttling. Valid
// identifiers are normalized before hashing; malformed or oversized inputs
// share one bounded bucket so guards cannot be fed arbitrary attacker data.
func LoginAttemptKey(raw string) string {
	if len(raw) > MaxLoginIdentifierLength {
		return "invalid"
	}
	identifier, err := NormalizeLoginIdentifier(raw)
	if err != nil {
		return "invalid"
	}
	sum := sha256.Sum256([]byte(string(identifier.Kind) + "\x00" + identifier.Value))
	return hex.EncodeToString(sum[:])
}

func ValidateLoginIdentifier(identifier LoginIdentifier) error {
	if identifier.Value == "" {
		return ErrInvalidIdentifier
	}
	switch identifier.Kind {
	case LoginIdentifierUsername:
		normalized, err := NormalizeUsername(identifier.Value)
		if err != nil || normalized != identifier.Value {
			return ErrInvalidIdentifier
		}
	case LoginIdentifierPhone:
		normalized, err := NormalizePhone(identifier.Value)
		if err != nil || normalized != identifier.Value {
			return ErrInvalidIdentifier
		}
	case LoginIdentifierEmail:
		normalized, err := NormalizeEmail(identifier.Value)
		if err != nil || normalized != identifier.Value {
			return ErrInvalidIdentifier
		}
	default:
		return ErrInvalidIdentifier
	}
	return nil
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
