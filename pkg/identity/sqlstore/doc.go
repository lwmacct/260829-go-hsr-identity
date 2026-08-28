// Package sqlstore is the database/sql adapter for identity. Schema ownership
// stays with the host migration runner in pkg/identity/migrations.
//
// Query code in pkg/identity/internal/dbgen is generated from migrations and queries.sql
// with sqlc. Regenerate it from the repository root with:
//
//	go run github.com/sqlc-dev/sqlc/cmd/sqlc@v1.29.0 generate
package sqlstore
