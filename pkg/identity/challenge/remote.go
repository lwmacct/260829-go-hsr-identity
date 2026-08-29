package challenge

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/lwmacct/260829-go-hsr-identity/pkg/identity/domain"
)

// RemoteTokenOptions configures a provider that verifies a browser token by
// POSTing it to a compatible remote site-verification endpoint.
type RemoteTokenOptions struct {
	Provider  string
	SiteKey   string
	Secret    string
	VerifyURL string
	Client    *http.Client
}

// RemoteTokenProvider verifies hCaptcha, Turnstile, or another compatible
// remote token challenge. It never exposes the server secret to clients.
type RemoteTokenProvider struct {
	provider  string
	siteKey   string
	secret    string
	verifyURL string
	client    *http.Client
}

// NewRemoteTokenProvider constructs a remote token provider. Provider, site
// key, secret, and verification URL are all required.
func NewRemoteTokenProvider(options RemoteTokenOptions) (*RemoteTokenProvider, error) {
	provider := strings.TrimSpace(options.Provider)
	siteKey := strings.TrimSpace(options.SiteKey)
	secret := strings.TrimSpace(options.Secret)
	verifyURL := strings.TrimSpace(options.VerifyURL)
	if provider == "" || siteKey == "" || secret == "" || verifyURL == "" {
		return nil, domain.ErrHumanChallengeUnsupported
	}
	client := options.Client
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	return &RemoteTokenProvider{
		provider:  provider,
		siteKey:   siteKey,
		secret:    secret,
		verifyURL: verifyURL,
		client:    client,
	}, nil
}

func (p *RemoteTokenProvider) Name() string {
	if p == nil {
		return ""
	}
	return p.provider
}

func (p *RemoteTokenProvider) PublicConfig() domain.HumanChallengeConfig {
	if p == nil {
		return domain.HumanChallengeConfig{}
	}
	return domain.HumanChallengeConfig{Provider: p.provider, SiteKey: p.siteKey}
}

func (p *RemoteTokenProvider) Create(context.Context, domain.RequestMeta) (*domain.HumanChallenge, error) {
	return nil, domain.ErrHumanChallengeUnsupported
}

func (p *RemoteTokenProvider) Verify(ctx context.Context, response domain.HumanChallengeResponse, request domain.RequestMeta) error {
	if p == nil || strings.TrimSpace(response.Token) == "" {
		return domain.ErrHumanChallengeInvalid
	}
	form := url.Values{}
	form.Set("secret", p.secret)
	form.Set("response", response.Token)
	if request.ClientIP != "" {
		form.Set("remoteip", request.ClientIP)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.verifyURL, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return domain.ErrHumanChallengeInvalid
	}
	var body struct {
		Success bool `json:"success"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return err
	}
	if !body.Success {
		return domain.ErrHumanChallengeInvalid
	}
	return nil
}
