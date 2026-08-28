// Package migrations exposes the versioned identity schema for host-owned
// migration runners.
package migrations

import "embed"

// FS contains the identity SQL migrations in version order.
//
// Hosts should execute these files with their migration tool rather than
// creating or altering identity tables at application startup.
//
//go:embed *.sql
var FS embed.FS
