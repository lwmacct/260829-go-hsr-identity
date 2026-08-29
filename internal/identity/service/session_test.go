package service

import (
	"context"
	"testing"
	"time"

	"github.com/lwmacct/260829-go-hsr-identity/pkg/identity/domain"
)

type nilSessionRepository struct{}

func (nilSessionRepository) CreateSession(context.Context, domain.SessionRecord) error { return nil }
func (nilSessionRepository) GetSessionByTokenHash(context.Context, []byte) (*domain.SessionRecord, error) {
	return nil, nil
}
func (nilSessionRepository) TouchSession(context.Context, domain.SessionID, string, time.Time) error {
	return nil
}
func (nilSessionRepository) RevokeSession(context.Context, domain.SessionID, string, string, time.Time) error {
	return nil
}
func (nilSessionRepository) DeleteSession(context.Context, domain.SessionID) error { return nil }
func (nilSessionRepository) RevokeSessionsForUsers(context.Context, []domain.UserID, string, time.Time) error {
	return nil
}
func (nilSessionRepository) DeleteSessionsForUsers(context.Context, []domain.UserID) error {
	return nil
}

func TestSessionResolveTreatsNilRecordAsUnauthenticated(t *testing.T) {
	sessions, err := NewSessionService(nilSessionRepository{}, nil, SessionOptions{}, func() time.Time {
		return time.Unix(100, 0).UTC()
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sessions.Resolve(context.Background(), "opaque-token", domain.RequestMeta{}); err != domain.ErrUnauthenticated {
		t.Fatalf("nil record error = %v", err)
	}
}
