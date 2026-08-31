package identity

import "github.com/lwmacct/260829-go-hsr-identity/pkg/identity/domain"

type UserID = domain.UserID
type SessionID = domain.SessionID
type RoleID = domain.RoleID
type PermissionID = domain.PermissionID
type State = domain.State
type User = domain.User
type Claims = domain.Claims
type Principal = domain.Principal
type RequestMeta = domain.RequestMeta
type EventType = domain.EventType
type Event = domain.Event
type EventSink = domain.EventSink
type EventSinkFunc = domain.EventSinkFunc
type LoginGuard = domain.LoginGuard
type LoginAttempt = domain.LoginAttempt
type LoginIdentifierKind = domain.LoginIdentifierKind
type LoginIdentifier = domain.LoginIdentifier
type UserCreate = domain.UserCreate
type UserProfilePatch = domain.UserProfilePatch
type UserFilter = domain.UserFilter
type Role = domain.Role
type Permission = domain.Permission
type RoleFilter = domain.RoleFilter
type PermissionFilter = domain.PermissionFilter
type RoleInput = domain.RoleInput
type PermissionInput = domain.PermissionInput
type PasswordCredential = domain.PasswordCredential
type SessionRecord = domain.SessionRecord
type Session = domain.Session
type IssuedSession = domain.IssuedSession
type UserCreateInput = domain.UserCreateInput
type UserProvisionInput = domain.UserProvisionInput
type UserUpdateProfileInput = domain.UserUpdateProfileInput
type UserDirectory = domain.UserDirectory
type SessionResolver = domain.SessionResolver
type ClaimsResolver = domain.ClaimsResolver
type Clock = domain.Clock
type ValidationError = domain.ValidationError
type HumanChallengeConfig = domain.HumanChallengeConfig
type HumanChallenge = domain.HumanChallenge
type HumanChallengeResponse = domain.HumanChallengeResponse
type HumanChallengeProvider = domain.HumanChallengeProvider
type HumanChallengeVerifier = domain.HumanChallengeVerifier
type HumanChallengeCreator = domain.HumanChallengeCreator

const (
	StateActive                 = domain.StateActive
	StateDisabled               = domain.StateDisabled
	EventUserCreated            = domain.EventUserCreated
	EventUserUpdated            = domain.EventUserUpdated
	EventUserStateChanged       = domain.EventUserStateChanged
	EventUserDeleted            = domain.EventUserDeleted
	EventLoginSucceeded         = domain.EventLoginSucceeded
	EventLoginFailed            = domain.EventLoginFailed
	EventPasswordChanged        = domain.EventPasswordChanged
	EventPasswordReset          = domain.EventPasswordReset
	EventSessionCreated         = domain.EventSessionCreated
	EventSessionRevoked         = domain.EventSessionRevoked
	EventUserSessionsRevoked    = domain.EventUserSessionsRevoked
	EventExpiredSessionsDeleted = domain.EventExpiredSessionsDeleted
	EventRoleCreated            = domain.EventRoleCreated
	EventRoleUpdated            = domain.EventRoleUpdated
	EventRoleDeleted            = domain.EventRoleDeleted
	EventPermissionCreated      = domain.EventPermissionCreated
	EventPermissionUpdated      = domain.EventPermissionUpdated
	EventPermissionDeleted      = domain.EventPermissionDeleted
	EventUserRolesChanged       = domain.EventUserRolesChanged
	EventRolePermissionsChanged = domain.EventRolePermissionsChanged
	ActionUserList              = domain.ActionUserList
	ActionUserCreate            = domain.ActionUserCreate
	ActionUserRead              = domain.ActionUserRead
	ActionUserUpdate            = domain.ActionUserUpdate
	ActionUserResetPassword     = domain.ActionUserResetPassword
	ActionUserDelete            = domain.ActionUserDelete
	ActionRoleList              = domain.ActionRoleList
	ActionRoleCreate            = domain.ActionRoleCreate
	ActionRoleRead              = domain.ActionRoleRead
	ActionRoleUpdate            = domain.ActionRoleUpdate
	ActionRoleDelete            = domain.ActionRoleDelete
	ActionPermissionList        = domain.ActionPermissionList
	ActionPermissionCreate      = domain.ActionPermissionCreate
	ActionPermissionRead        = domain.ActionPermissionRead
	ActionPermissionUpdate      = domain.ActionPermissionUpdate
	ActionPermissionDelete      = domain.ActionPermissionDelete
	ActionUserRoleManage        = domain.ActionUserRoleManage
	ActionRolePermissionManage  = domain.ActionRolePermissionManage
)

var (
	ErrInvalid                     = domain.ErrInvalid
	ErrNotFound                    = domain.ErrNotFound
	ErrConflict                    = domain.ErrConflict
	ErrInvalidUsername             = domain.ErrInvalidUsername
	ErrUsernameTaken               = domain.ErrUsernameTaken
	ErrInvalidPhone                = domain.ErrInvalidPhone
	ErrPhoneTaken                  = domain.ErrPhoneTaken
	ErrInvalidEmail                = domain.ErrInvalidEmail
	ErrEmailTaken                  = domain.ErrEmailTaken
	ErrInvalidIdentifier           = domain.ErrInvalidIdentifier
	ErrInvalidUser                 = domain.ErrInvalidUser
	ErrDisabled                    = domain.ErrDisabled
	ErrEmptySelection              = domain.ErrEmptySelection
	ErrInvalidState                = domain.ErrInvalidState
	ErrInvalidRequestMeta          = domain.ErrInvalidRequestMeta
	ErrUnauthenticated             = domain.ErrUnauthenticated
	ErrExpired                     = domain.ErrExpired
	ErrRevoked                     = domain.ErrRevoked
	ErrBindingMismatch             = domain.ErrBindingMismatch
	ErrWeakPassword                = domain.ErrWeakPassword
	ErrUnsupported                 = domain.ErrUnsupported
	ErrForbidden                   = domain.ErrForbidden
	ErrRateLimited                 = domain.ErrRateLimited
	ErrHumanChallengeInvalid       = domain.ErrHumanChallengeInvalid
	ErrHumanChallengeUnavailable   = domain.ErrHumanChallengeUnavailable
	ErrHumanChallengeUnsupported   = domain.ErrHumanChallengeUnsupported
	ErrHumanChallengeLimitExceeded = domain.ErrHumanChallengeLimitExceeded
)

const (
	LoginIdentifierUsername = domain.LoginIdentifierUsername
	LoginIdentifierPhone    = domain.LoginIdentifierPhone
	LoginIdentifierEmail    = domain.LoginIdentifierEmail
)

var (
	NormalizeUsername        = domain.NormalizeUsername
	NormalizePhone           = domain.NormalizePhone
	NormalizeEmail           = domain.NormalizeEmail
	NormalizeLoginIdentifier = domain.NormalizeLoginIdentifier
	ValidateLoginIdentifier  = domain.ValidateLoginIdentifier
	NormalizeUserID          = domain.NormalizeUserID
	NormalizeSessionID       = domain.NormalizeSessionID
	ValidateUserID           = domain.ValidateUserID
	ParseUserID              = domain.ParseUserID
	ParseRoleID              = domain.ParseRoleID
	ParsePermissionID        = domain.ParsePermissionID
	ValidateSessionID        = domain.ValidateSessionID
	ParseSessionID           = domain.ParseSessionID
	NormalizeRoleID          = domain.NormalizeRoleID
	NormalizePermissionID    = domain.NormalizePermissionID
	ValidateRoleID           = domain.ValidateRoleID
	ValidatePermissionID     = domain.ValidatePermissionID
	NormalizeRequestMeta     = domain.NormalizeRequestMeta
	ContextWithPrincipal     = domain.ContextWithPrincipal
	PrincipalFromContext     = domain.PrincipalFromContext
	DirectoryFromRepository  = domain.DirectoryFromRepository
)
