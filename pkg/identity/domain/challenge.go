package domain

import (
	"context"
	"errors"
	"time"
)

// HumanChallengeConfig describes the public configuration needed by a client
// to render a human-verification challenge.
type HumanChallengeConfig struct {
	Provider string
	SiteKey  string
	// Required indicates whether the identity HTTP login and registration
	// endpoints require a valid response. Hosts may still use a configured
	// provider for their own protected actions when this is false.
	Required bool
}

// HumanChallenge is a challenge instance returned to a client. Image-based
// providers populate Image and ChallengeID; remote providers may only expose
// the provider configuration.
type HumanChallenge struct {
	Provider    string
	ChallengeID string
	Image       string
	ExpiresAt   time.Time
}

// HumanChallengeResponse is submitted by a client to prove completion of a
// challenge. The fields used depend on the provider.
type HumanChallengeResponse struct {
	Provider    string
	ChallengeID string
	Answer      string
	Token       string
}

// HumanChallengeProvider is the host-extensible challenge contract. Identity
// owns the lifecycle and HTTP integration; hosts may supply image, hCaptcha,
// Turnstile, or another provider without importing identity internals.
type HumanChallengeProvider interface {
	Name() string
	PublicConfig() HumanChallengeConfig
	Create(context.Context, RequestMeta) (*HumanChallenge, error)
	Verify(context.Context, HumanChallengeResponse, RequestMeta) error
}

var (
	ErrHumanChallengeInvalid       = errors.New("invalid human challenge")
	ErrHumanChallengeUnsupported   = errors.New("human challenge provider unsupported")
	ErrHumanChallengeLimitExceeded = errors.New("human challenge limit exceeded")
)
