-- name: CreateUser :one
INSERT INTO identity_users (
    id, handle, display_name, email, avatar_url, state, disabled_at, created_at, updated_at
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
RETURNING *;

-- name: GetUser :one
SELECT * FROM identity_users WHERE id = $1 LIMIT 1;

-- name: GetUserByHandle :one
SELECT * FROM identity_users WHERE handle = $1 LIMIT 1;

-- name: CountUsers :one
SELECT COUNT(*) FROM identity_users
WHERE (CAST(sqlc.arg(keyword) AS VARCHAR) = '' OR handle LIKE '%' || CAST(sqlc.arg(keyword) AS VARCHAR) || '%' OR display_name LIKE '%' || CAST(sqlc.arg(keyword) AS VARCHAR) || '%' OR email LIKE '%' || CAST(sqlc.arg(keyword) AS VARCHAR) || '%')
  AND (CAST(sqlc.arg(state) AS VARCHAR) = '' OR state = CAST(sqlc.arg(state) AS VARCHAR));

-- name: ListUsers :many
SELECT * FROM identity_users
WHERE (CAST(sqlc.arg(keyword) AS VARCHAR) = '' OR handle LIKE '%' || CAST(sqlc.arg(keyword) AS VARCHAR) || '%' OR display_name LIKE '%' || CAST(sqlc.arg(keyword) AS VARCHAR) || '%' OR email LIKE '%' || CAST(sqlc.arg(keyword) AS VARCHAR) || '%')
  AND (CAST(sqlc.arg(state) AS VARCHAR) = '' OR state = CAST(sqlc.arg(state) AS VARCHAR))
ORDER BY created_at DESC LIMIT sqlc.arg('page_size') OFFSET sqlc.arg('page_offset');

-- name: UpdateUserProfile :exec
UPDATE identity_users SET display_name = $1, email = $2, avatar_url = $3, updated_at = $4 WHERE id = $5;

-- name: UpdateUserState :execresult
UPDATE identity_users SET state = $1, disabled_at = $2, updated_at = $3 WHERE id = $4;

-- name: MarkUserLogin :exec
UPDATE identity_users SET last_login_at = $1, updated_at = $2 WHERE id = $3;

-- name: DeleteUser :exec
DELETE FROM identity_users WHERE id = $1;

-- name: GetPasswordCredential :one
SELECT * FROM identity_passwords WHERE user_id = $1 LIMIT 1;

-- name: UpsertPasswordCredential :exec
INSERT INTO identity_passwords (user_id, scheme, hash, password_changed_at, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT(user_id) DO UPDATE SET
    scheme = excluded.scheme,
    hash = excluded.hash,
    password_changed_at = excluded.password_changed_at,
    updated_at = excluded.updated_at;

-- name: DeletePasswordCredential :exec
DELETE FROM identity_passwords WHERE user_id = $1;

-- name: CreateSession :exec
INSERT INTO identity_sessions (
    id, token_hash, user_id, login_ip, last_ip, binding_hash, user_agent_hash,
    expires_at, created_at, last_seen_at, revoked_at, revoked_reason
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12);

-- name: GetSessionByTokenHash :one
SELECT * FROM identity_sessions WHERE token_hash = $1 LIMIT 1;

-- name: TouchSession :exec
UPDATE identity_sessions SET last_ip = $1, last_seen_at = $2 WHERE id = $3;

-- name: RevokeSession :exec
UPDATE identity_sessions SET revoked_at = $1, revoked_reason = $2, last_ip = $3, last_seen_at = $4 WHERE id = $5;

-- name: DeleteSession :exec
DELETE FROM identity_sessions WHERE id = $1;

-- name: RevokeSessionsForUser :exec
UPDATE identity_sessions SET revoked_at = $1, revoked_reason = $2 WHERE user_id = $3 AND revoked_at IS NULL;

-- name: DeleteSessionsForUser :exec
DELETE FROM identity_sessions WHERE user_id = $1;
