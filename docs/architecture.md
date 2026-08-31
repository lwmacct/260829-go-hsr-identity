# Identity architecture

## Ownership

identity owns users, password credentials, sessions, account lifecycle, generic role-based access control, and the human-challenge lifecycle contract. IDs are database UUID values generated as UUIDv7 by Go 1.27; PostgreSQL 18 and SQLite schema checks reject malformed or non-v7 IDs. The reusable image and remote token providers live in `pkg/identity/challenge`; host applications own external login providers, SSH keys, custom challenge providers, business permission vocabulary, audit storage, and domain relationships. SQLite is the default database and PostgreSQL 18+ is also supported.

## Layer contracts

- `handler` knows Huma, HTTP, cookies, headers, DTOs, and error status codes.
- `service` knows domain rules, password hashing, session lifecycle, RBAC evaluation, authorization callbacks, and cross-repository transactions. It does not import Huma; its transaction participant boundary may use Bun because the module is intentionally Bun-coupled.
- `repository` knows Bun models and queries. It maps `sql.ErrNoRows` and constraint errors to identity sentinels.
- Human challenges are an extensible boundary: verification and challenge creation are separate contracts. Hosts can use the built-in providers in `pkg/identity/challenge` or supply custom implementations; identity owns the public configuration and challenge endpoints, independently configurable login/registration enforcement, and the module methods used by protected host actions.
- `pkg/identity.Module` is the composition root and the only supported default entry point.
- `Options.Events` receives committed facts for host audit and telemetry. Event observers cannot fail the completed identity operation and are not a transactional outbox.

The dependency direction is one-way: `handler → service → repository → Bun`.

## Transactions

`repository.Store.WithinTx` creates a Bun transaction and binds all repositories to the same `bun.Tx`. Registration with automatic login, password changes, password resets, external-login Session issuance, disabling users, and deleting users use this boundary. `identity.New` validates the current identity schema but never creates or alters tables.

Host-owned deletion cleanup can join the same transaction through
`DeleteParticipant`. `Options.Events` runs only after a successful commit and
is appropriate for runtime refresh, logging, audit ingestion, and metrics; it
cannot roll back the completed database work.

`Module.ProvisionUser` uses the same transaction boundary. It locks each
requested role and then creates the account, password credential, and role
bindings atomically. PostgreSQL uses `FOR UPDATE`; SQLite upgrades the
transaction to a writer lock.

## Security invariants

- Passwords use Argon2id and are never stored in plaintext.
- Session tokens are random opaque values; only SHA-256 hashes are stored.
- Login failures do not reveal whether a username exists.
- Successful password and external logins update `last_login_at` in the same transaction that creates the Session.
- Disabling a user revokes sessions.
- Password changes and resets revoke old sessions.
- Role and permission changes take effect on the next Session resolution; permissions are not snapshotted into a Session.
