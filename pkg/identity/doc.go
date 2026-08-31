// Package identity provides a Bun-backed user, password, and session module
// with Huma HTTP handlers. It also owns the generic human-challenge contract
// and optional authentication enforcement. Reusable image and remote-token
// providers are available from the sibling pkg/identity/challenge package;
// hosts may still supply their own provider. OAuth, SSH keys, auditing, and
// application data remain host concerns. Trusted hosts can provision users with
// explicit role bindings through Module.ProvisionUser.
package identity
