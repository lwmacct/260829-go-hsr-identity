package handler

import (
	"time"

	"github.com/lwmacct/260829-go-hsr-identity/pkg/identity/domain"
)

type humanChallengeConfigView struct {
	Provider              string `json:"provider"`
	SiteKey               string `json:"sitekey,omitempty"`
	RequireOnLogin        bool   `json:"requireOnLogin"`
	RequireOnRegistration bool   `json:"requireOnRegistration"`
}

type configView struct {
	LoginEnabled        bool                      `json:"loginEnabled"`
	RegistrationEnabled bool                      `json:"registrationEnabled"`
	Challenge           *humanChallengeConfigView `json:"challenge,omitempty"`
}

type challengeBody struct {
	Provider    string `json:"provider" minLength:"1"`
	ChallengeID string `json:"challengeId,omitempty"`
	Answer      string `json:"answer,omitempty"`
	Token       string `json:"token,omitempty"`
}

func (c *challengeBody) domain() domain.HumanChallengeResponse {
	if c == nil {
		return domain.HumanChallengeResponse{}
	}
	return domain.HumanChallengeResponse{Provider: c.Provider, ChallengeID: c.ChallengeID, Answer: c.Answer, Token: c.Token}
}

type challengeView struct {
	Provider    string    `json:"provider"`
	ChallengeID string    `json:"challengeId,omitempty"`
	Image       string    `json:"image,omitempty"`
	ExpiresAt   time.Time `json:"expiresAt,omitempty"`
}

func challengeViewFromDomain(challenge *domain.HumanChallenge) challengeView {
	if challenge == nil {
		return challengeView{}
	}
	return challengeView{Provider: challenge.Provider, ChallengeID: challenge.ChallengeID, Image: challenge.Image, ExpiresAt: challenge.ExpiresAt}
}
