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

// HumanChallengeVerifier is the host-extensible verification contract.
type HumanChallengeVerifier interface {
	Name() string
	PublicConfig() HumanChallengeConfig
	Verify(context.Context, HumanChallengeResponse, RequestMeta) error
}

// HumanChallengeCreator is implemented by providers that issue a challenge
// instance (for example the built-in image provider).
type HumanChallengeCreator interface {
	Name() string
	PublicConfig() HumanChallengeConfig
	Create(context.Context, RequestMeta) (*HumanChallenge, error)
}

// HumanChallengeProvider combines verification and creation for providers
// that support both operations.
type HumanChallengeProvider interface {
	HumanChallengeVerifier
	HumanChallengeCreator
}

var (
	ErrHumanChallengeInvalid       = errors.New("invalid human challenge")
	ErrHumanChallengeUnsupported   = errors.New("human challenge provider unsupported")
	ErrHumanChallengeLimitExceeded = errors.New("human challenge limit exceeded")
)
