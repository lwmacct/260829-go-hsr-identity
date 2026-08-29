# Identity architecture

## Ownership

identity owns users, password credentials, sessions, account lifecycle, and generic role-based access control. IDs are PostgreSQL `uuid` values generated as UUIDv7 by Go 1.27; PostgreSQL 18 schema checks also reject non-v7 IDs. Host applications own OAuth providers, SSH keys, challenges, business permission vocabulary, audit events, and domain relationships. PostgreSQL 18+ is the supported production baseline.

## Layer contracts

- `handler` knows Huma, HTTP, cookies, headers, DTOs, and error status codes.
- `service` knows domain rules, password hashing, session lifecycle, RBAC evaluation, authorization callbacks, and cross-repository transactions. It does not import Huma or Bun.
- `repository` knows Bun models and queries. It maps `sql.ErrNoRows` and constraint errors to identity sentinels.
- `pkg/identity.Module` is the composition root and the only supported default entry point.

The dependency direction is one-way: `handler → service → repository → Bun`.

## Transactions

`repository.Store.WithinTx` creates a Bun transaction and binds all repositories to the same `bun.Tx`. Registration with automatic login, password changes, password resets, external-login Session issuance, disabling users, and deleting users use this boundary. `identity.New` never creates tables.

## Security invariants

- Passwords use Argon2id and are never stored in plaintext.
- Session tokens are random opaque values; only SHA-256 hashes are stored.
- Login failures do not reveal whether a handle exists.
- Successful password and external logins update `last_login_at` in the same transaction that creates the Session.
- Disabling a user revokes sessions.
- Password changes and resets revoke old sessions.
- Role and permission changes take effect on the next Session resolution; permissions are not snapshotted into a Session.
