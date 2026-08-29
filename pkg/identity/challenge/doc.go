// Package challenge provides reusable human-challenge providers for identity.
//
// The package contains the built-in image provider and a remote token provider
// suitable for hCaptcha, Cloudflare Turnstile, and compatible services. The
// identity module owns the provider contract and HTTP lifecycle; this package
// only supplies provider implementations.
package challenge
