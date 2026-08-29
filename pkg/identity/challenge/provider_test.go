package challenge

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/lwmacct/260829-go-hsr-identity/pkg/identity/domain"
)

func TestImageProviderCreatesAndVerifiesChallenges(t *testing.T) {
	provider := NewImageProvider(2)
	created, err := provider.Create(context.Background(), domain.RequestMeta{})
	if err != nil {
		t.Fatalf("create challenge: %v", err)
	}
	if created.Provider != "image" || created.ChallengeID == "" || !strings.HasPrefix(created.Image, "data:image/") {
		t.Fatalf("unexpected challenge: %#v", created)
	}

	id, _, err := provider.put("Ab12")
	if err != nil {
		t.Fatalf("put challenge: %v", err)
	}
	response := domain.HumanChallengeResponse{Provider: "image", ChallengeID: id, Answer: "ab12"}
	if err := provider.Verify(context.Background(), response, domain.RequestMeta{}); err != nil {
		t.Fatalf("verify challenge: %v", err)
	}
	if err := provider.Verify(context.Background(), response, domain.RequestMeta{}); !errors.Is(err, domain.ErrHumanChallengeInvalid) {
		t.Fatalf("replay error = %v, want invalid challenge", err)
	}
}

func TestImageProviderEnforcesItemLimit(t *testing.T) {
	provider := NewImageProvider(1)
	if _, err := provider.Create(context.Background(), domain.RequestMeta{}); err != nil {
		t.Fatalf("first challenge: %v", err)
	}
	if _, err := provider.Create(context.Background(), domain.RequestMeta{}); !errors.Is(err, domain.ErrHumanChallengeLimitExceeded) {
		t.Fatalf("second challenge error = %v, want limit exceeded", err)
	}
}

func TestRemoteTokenProviderVerifiesForm(t *testing.T) {
	requests := make(chan url.Values, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if got := r.Header.Get("Content-Type"); got != "application/x-www-form-urlencoded" {
			t.Errorf("content type = %q", got)
		}
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse form: %v", err)
			return
		}
		requests <- r.PostForm
		_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
	}))
	defer server.Close()

	provider, err := NewRemoteTokenProvider(RemoteTokenOptions{
		Provider:  "hcaptcha",
		SiteKey:   "site-key",
		Secret:    "secret",
		VerifyURL: server.URL,
		Client:    server.Client(),
	})
	if err != nil {
		t.Fatalf("new remote provider: %v", err)
	}
	if got := provider.Name(); got != "hcaptcha" {
		t.Fatalf("provider name = %q", got)
	}
	if got := provider.PublicConfig(); got.Provider != "hcaptcha" || got.SiteKey != "site-key" {
		t.Fatalf("public config = %#v", got)
	}
	if err := provider.Verify(context.Background(), domain.HumanChallengeResponse{Token: "token"}, domain.RequestMeta{ClientIP: "203.0.113.10"}); err != nil {
		t.Fatalf("verify remote token: %v", err)
	}
	form := <-requests
	if form.Get("secret") != "secret" || form.Get("response") != "token" || form.Get("remoteip") != "203.0.113.10" {
		t.Fatalf("verification form = %v", form)
	}
}

func TestRemoteTokenProviderRejectsInvalidConfigurationAndResponses(t *testing.T) {
	if _, err := NewRemoteTokenProvider(RemoteTokenOptions{Provider: "hcaptcha"}); !errors.Is(err, domain.ErrHumanChallengeUnsupported) {
		t.Fatalf("missing configuration error = %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer server.Close()
	provider, err := NewRemoteTokenProvider(RemoteTokenOptions{
		Provider:  "turnstile",
		SiteKey:   "site-key",
		Secret:    "secret",
		VerifyURL: server.URL,
		Client:    server.Client(),
	})
	if err != nil {
		t.Fatalf("new remote provider: %v", err)
	}
	if err := provider.Verify(context.Background(), domain.HumanChallengeResponse{}, domain.RequestMeta{}); !errors.Is(err, domain.ErrHumanChallengeInvalid) {
		t.Fatalf("empty token error = %v, want invalid challenge", err)
	}
	if err := provider.Verify(context.Background(), domain.HumanChallengeResponse{Token: "token"}, domain.RequestMeta{}); !errors.Is(err, domain.ErrHumanChallengeInvalid) {
		t.Fatalf("bad gateway error = %v, want invalid challenge", err)
	}
}
