// Package identity provides storage- and transport-neutral identity primitives.
//
// The package owns users and exposes a directory of principals. Passwords,
// sessions, HTTP, OAuth, SSH keys, and application authorization are separate
// capabilities or host-application concerns.
//
// UserID and SessionID are opaque strings. The default services generate
// UUIDv7 values, while callers may inject another IDGenerator. Handles are
// normalized by an injected HandlePolicy, and the default policy accepts
// lowercase ASCII handles.
package identity
