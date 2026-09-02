# Integration

1. Add this module to the host `go.work` and use a SQLite or PostgreSQL 18+ Bun database.
2. Call `identity.ApplySchema` in tests and explicit database initialization. Production startup should call `identity.ValidateSchema`; registering only `identity.DatabaseSchema().Models` is not sufficient because the package also owns identity indexes.
3. Construct one `identity.Module` during application startup.
4. Call `module.Register(api)` after creating the host Huma API.
5. Set `Authorization.DefaultRoleCodes` to the normal role(s) for public registrations. Initialize the host's permission catalog and role bindings through the module's RBAC API.
6. Use `Options.Authorizer` only for additional host policy (for example resource ownership or tenant checks).
7. Keep OAuth, SSH keys, audit storage, and business associations in host-owned tables and services. For human verification, use a provider from `pkg/identity/challenge` or implement `identity.HumanChallengeVerifier`; providers that issue challenges can also implement `identity.HumanChallengeCreator`. Inject them through `HTTP.Challenge.Verifier` and `HTTP.Challenge.Creator`, and set `HTTP.Challenge.RequireOnLogin` and/or `HTTP.Challenge.RequireOnRegistration` to enforce verification on the selected flows.
8. Configure independent `Options.Contacts.Phone` and `Options.Contacts.Email`
   providers. They are required for the corresponding personal-center binding
   flow. The provider sends and verifies the code; identity owns the pending
   request and commits only verified contacts.
9. Use `Options.Events` for committed audit/telemetry facts and post-commit runtime refresh. It is best-effort observation, not a transactional outbox. Use `DeleteParticipant` when host-owned cleanup must commit or roll back with identity user deletion.
10. Inject `*identity.Module` directly wherever an `identity.UserDirectory` is required. Host services that address persistent usernames should call `UserByUsername`; authentication forms should submit a generic identifier.
11. Treat `LoginAttempt.IdentifierKey` as an opaque throttling key. It contains no raw login identifier and malformed input uses the shared `invalid` bucket.

Provision users through an explicit host CLI command that calls
`Module.ProvisionUser` with the required role codes. The first administrator is
created with `RoleCodes: []string{"admin"}`; public registration should receive
only the host's normal `user` role. Do not put an administrator password in
configuration or environment variables.

Use `Module.ResetPassword` from an explicit offline recovery command when an
existing user's password must be replaced. It revokes the user's active
sessions as part of the same transaction.

The module exposes `GET /auth/config` and `POST /auth/challenges` when a provider is configured. A host can reuse the same provider for non-authentication actions with `module.CreateChallenge` and `module.VerifyChallenge`. Authenticated users can read/update their profile through `/auth/profile`, independently verify phone/email contacts through `/auth/profile/contacts/{kind}/verification`, and manage their own sessions through `/auth/sessions`.

Use `module.Login` for password login and `module.CreateSession` after a host-owned
external login; both record `last_login_at` transactionally. For trusted reverse
proxies, configure `HTTP.RequestMetaResolver`; the default resolver only uses
`RemoteAddr` and `User-Agent`.

When `EnableAdminRoutes` is enabled, authorize the stable action constants
`identity.ActionUserList`, `identity.ActionUserCreate`, `identity.ActionUserRead`,
`identity.ActionUserUpdate`, `identity.ActionUserResetPassword`, and
`identity.ActionUserDelete` in the host callback.

The module's table names are `identity_users`, `identity_user_contacts`, `identity_contact_verifications`, `identity_passwords`, `identity_sessions`, `identity_roles`, `identity_permissions`, `identity_user_roles`, and `identity_role_permissions`. This release intentionally drops `identity_users.phone_e164` and `identity_users.email`; reset SQLite databases or run a destructive host migration before startup. No compatibility double-write layer is provided. Production startup should only open and use the database; schema creation belongs in an explicit deployment/init command.

Phone numbers and emails are optional canonical login aliases only after their
independent verification flow succeeds. Password recovery, MFA, and trusted
notifications must still define their own policy over the verified contacts.
