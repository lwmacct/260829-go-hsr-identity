package challenge

import (
	"context"
	"crypto/sha256"
	"errors"
	"image/color"
	"strings"
	"sync"
	"time"

	"github.com/golang-module/base64Captcha/driver"
	"github.com/lwmacct/260822-go-pkg-base62/pkg/base62"

	"github.com/lwmacct/260829-go-hsr-identity/pkg/identity/domain"
)

const imageDefaultTTL = 2 * time.Minute
const imageDefaultMaxItems = 4096

var errImageChallengeLimitExceeded = errors.New("image challenge limit exceeded")

// ImageProvider generates short-lived image challenges and keeps only their
// answer digests in memory. A non-positive maxItems uses a bounded default;
// in-memory challenges are suitable for a single process only.
type ImageProvider struct {
	mu         sync.Mutex
	challenges map[string]imageChallenge
	driver     driver.Driver
	ttl        time.Duration
	maxItems   int
}

type imageChallenge struct {
	answerHash [32]byte
	expiresAt  time.Time
}

// NewImageProvider constructs an in-memory image challenge provider.
func NewImageProvider(maxItems int) *ImageProvider {
	if maxItems <= 0 {
		maxItems = imageDefaultMaxItems
	}
	return &ImageProvider{
		challenges: make(map[string]imageChallenge),
		driver: driver.NewDriverString(driver.DriverString{
			Width:           180,
			Height:          56,
			Length:          4,
			NoiseCount:      12,
			ShowLineOptions: driver.OptionShowHollowLine | driver.OptionShowSlimeLine,
			Source:          "23456789ABCDEFGHJKLMNPQRSTUVWXYZ",
			BgColor:         &color.RGBA{R: 248, G: 250, B: 252, A: 255},
		}),
		ttl:      imageDefaultTTL,
		maxItems: maxItems,
	}
}

func (p *ImageProvider) Name() string {
	return "image"
}

func (p *ImageProvider) PublicConfig() domain.HumanChallengeConfig {
	return domain.HumanChallengeConfig{Provider: p.Name()}
}

func (p *ImageProvider) Create(context.Context, domain.RequestMeta) (*domain.HumanChallenge, error) {
	if p == nil || p.driver == nil {
		return nil, domain.ErrHumanChallengeUnsupported
	}
	_, content, answer := p.driver.GenerateCaptcha()
	image, err := p.driver.DrawCaptcha(content)
	if err != nil {
		return nil, err
	}
	id, expiresAt, err := p.put(answer)
	if err != nil {
		if errors.Is(err, errImageChallengeLimitExceeded) {
			return nil, domain.ErrHumanChallengeLimitExceeded
		}
		return nil, err
	}
	return &domain.HumanChallenge{
		Provider:    p.Name(),
		ChallengeID: id,
		Image:       image.Encoder(),
		ExpiresAt:   expiresAt,
	}, nil
}

func (p *ImageProvider) Verify(_ context.Context, response domain.HumanChallengeResponse, _ domain.RequestMeta) error {
	if p == nil || !p.verifyAndDelete(response.ChallengeID, response.Answer) {
		return domain.ErrHumanChallengeInvalid
	}
	return nil
}

func (p *ImageProvider) put(answer string) (string, time.Time, error) {
	random, err := base62.RandomString(40)
	if err != nil {
		return "", time.Time{}, err
	}
	now := time.Now().UTC()
	expiresAt := now.Add(p.ttl)
	p.mu.Lock()
	defer p.mu.Unlock()
	p.cleanupLocked(now)
	if p.maxItems > 0 && len(p.challenges) >= p.maxItems {
		return "", time.Time{}, errImageChallengeLimitExceeded
	}
	id := "cap_" + random
	p.challenges[id] = imageChallenge{answerHash: imageAnswerHash(answer), expiresAt: expiresAt}
	return id, expiresAt, nil
}

func (p *ImageProvider) verifyAndDelete(id string, answer string) bool {
	id = strings.TrimSpace(id)
	if id == "" || strings.TrimSpace(answer) == "" {
		return false
	}
	now := time.Now().UTC()
	p.mu.Lock()
	defer p.mu.Unlock()
	challenge, ok := p.challenges[id]
	if !ok {
		return false
	}
	delete(p.challenges, id)
	if !challenge.expiresAt.After(now) {
		return false
	}
	return challenge.answerHash == imageAnswerHash(answer)
}

func (p *ImageProvider) cleanupLocked(now time.Time) {
	for id, challenge := range p.challenges {
		if !challenge.expiresAt.After(now) {
			delete(p.challenges, id)
		}
	}
}

func imageAnswerHash(answer string) [32]byte {
	return sha256.Sum256([]byte(strings.ToUpper(strings.TrimSpace(answer))))
}
