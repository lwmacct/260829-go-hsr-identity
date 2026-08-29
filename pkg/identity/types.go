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
type IssuedSession = domain.IssuedSession
type UserCreateInput = domain.UserCreateInput
type BootstrapInput = domain.BootstrapInput
type UserUpdateProfileInput = domain.UserUpdateProfileInput
type UserRepository = domain.UserRepository
type PasswordRepository = domain.PasswordRepository
type SessionRepository = domain.SessionRepository
type UnitOfWork = domain.UnitOfWork
type TxManager = domain.TxManager
type UserDirectory = domain.UserDirectory
type SessionResolver = domain.SessionResolver
type AuthorizationRepository = domain.AuthorizationRepository
type ClaimsResolver = domain.ClaimsResolver
type Clock = domain.Clock
type HandlePolicy = domain.HandlePolicy
type HandlePolicyFunc = domain.HandlePolicyFunc
type ValidationError = domain.ValidationError
type HumanChallengeConfig = domain.HumanChallengeConfig
type HumanChallenge = domain.HumanChallenge
type HumanChallengeResponse = domain.HumanChallengeResponse
type HumanChallengeProvider = domain.HumanChallengeProvider

const (
	StateActive                = domain.StateActive
	StateDisabled              = domain.StateDisabled
	ActionUserList             = domain.ActionUserList
	ActionUserCreate           = domain.ActionUserCreate
	ActionUserRead             = domain.ActionUserRead
	ActionUserUpdate           = domain.ActionUserUpdate
	ActionUserResetPassword    = domain.ActionUserResetPassword
	ActionUserDelete           = domain.ActionUserDelete
	ActionRoleList             = domain.ActionRoleList
	ActionRoleCreate           = domain.ActionRoleCreate
	ActionRoleRead             = domain.ActionRoleRead
	ActionRoleUpdate           = domain.ActionRoleUpdate
	ActionRoleDelete           = domain.ActionRoleDelete
	ActionPermissionList       = domain.ActionPermissionList
	ActionPermissionCreate     = domain.ActionPermissionCreate
	ActionPermissionRead       = domain.ActionPermissionRead
	ActionPermissionUpdate     = domain.ActionPermissionUpdate
	ActionPermissionDelete     = domain.ActionPermissionDelete
	ActionUserRoleManage       = domain.ActionUserRoleManage
	ActionRolePermissionManage = domain.ActionRolePermissionManage
)

var (
	ErrInvalid                     = domain.ErrInvalid
	ErrNotFound                    = domain.ErrNotFound
	ErrConflict                    = domain.ErrConflict
	ErrInvalidHandle               = domain.ErrInvalidHandle
	ErrHandleTaken                 = domain.ErrHandleTaken
	ErrBootstrapCompleted          = domain.ErrBootstrapCompleted
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
	ErrHumanChallengeInvalid       = domain.ErrHumanChallengeInvalid
	ErrHumanChallengeUnsupported   = domain.ErrHumanChallengeUnsupported
	ErrHumanChallengeLimitExceeded = domain.ErrHumanChallengeLimitExceeded
)

var LowerASCIIHandlePolicy = domain.LowerASCIIHandlePolicy
var TrimHandlePolicy = domain.TrimHandlePolicy
var NormalizeUserID = domain.NormalizeUserID
var NormalizeSessionID = domain.NormalizeSessionID
var ValidateUserID = domain.ValidateUserID
var ValidateSessionID = domain.ValidateSessionID
var NormalizeRoleID = domain.NormalizeRoleID
var NormalizePermissionID = domain.NormalizePermissionID
var ValidateRoleID = domain.ValidateRoleID
var ValidatePermissionID = domain.ValidatePermissionID
var NormalizeRequestMeta = domain.NormalizeRequestMeta
var ContextWithPrincipal = domain.ContextWithPrincipal
var PrincipalFromContext = domain.PrincipalFromContext
var DirectoryFromRepository = domain.DirectoryFromRepository
