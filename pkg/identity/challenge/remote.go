package challenge

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
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
	// AllowedHostnames and ExpectedAction are optional provider response
	// assertions supported by hCaptcha/Turnstile-compatible endpoints.
	AllowedHostnames []string
	ExpectedAction   string
	MaxResponseBytes int64
}

// RemoteTokenProvider verifies hCaptcha, Turnstile, or another compatible
// remote token challenge. It never exposes the server secret to clients.
type RemoteTokenProvider struct {
	provider  string
	siteKey   string
	secret    string
	verifyURL string
	client    *http.Client
	allowed   map[string]struct{}
	action    string
	maxBytes  int64
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
	allowed := make(map[string]struct{}, len(options.AllowedHostnames))
	for _, hostname := range options.AllowedHostnames {
		if hostname = normalizeHostname(hostname); hostname != "" {
			allowed[hostname] = struct{}{}
		}
	}
	maxBytes := options.MaxResponseBytes
	if maxBytes <= 0 {
		maxBytes = 64 * 1024
	}
	return &RemoteTokenProvider{
		provider:  provider,
		siteKey:   siteKey,
		secret:    secret,
		verifyURL: verifyURL,
		client:    client,
		allowed:   allowed,
		action:    strings.TrimSpace(options.ExpectedAction),
		maxBytes:  maxBytes,
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
		return fmt.Errorf("%w: %v", domain.ErrHumanChallengeUnsupported, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", domain.ErrHumanChallengeUnavailable, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= http.StatusInternalServerError {
			return domain.ErrHumanChallengeUnavailable
		}
		return domain.ErrHumanChallengeInvalid
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, p.maxBytes+1))
	if err != nil {
		return fmt.Errorf("%w: %v", domain.ErrHumanChallengeUnavailable, err)
	}
	if int64(len(data)) > p.maxBytes {
		return domain.ErrHumanChallengeInvalid
	}
	var body struct {
		Success  bool   `json:"success"`
		Hostname string `json:"hostname"`
		Action   string `json:"action"`
	}
	if err := json.Unmarshal(data, &body); err != nil {
		return fmt.Errorf("%w: %v", domain.ErrHumanChallengeUnavailable, err)
	}
	if !body.Success {
		return domain.ErrHumanChallengeInvalid
	}
	if len(p.allowed) > 0 {
		if _, ok := p.allowed[normalizeHostname(body.Hostname)]; !ok {
			return domain.ErrHumanChallengeInvalid
		}
	}
	if p.action != "" && strings.TrimSpace(body.Action) != p.action {
		return domain.ErrHumanChallengeInvalid
	}
	return nil
}

func normalizeHostname(value string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
}
