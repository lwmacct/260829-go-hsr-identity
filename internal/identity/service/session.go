package service

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
	"time"
	"uuid"

	"github.com/lwmacct/260829-go-hsr-identity/pkg/identity/domain"
)

type SessionService struct {
	repo             domain.SessionRepository
	users            domain.UserDirectory
	ttl, idle, touch time.Duration
	tokenBytes       int
	binding          BindingPolicy
	now              domain.Clock
	claims           domain.ClaimsResolver
	events           domain.EventSink
}

func (s *SessionService) withRepositories(repo domain.SessionRepository, users domain.UserDirectory) *SessionService {
	clone := *s
	clone.repo = repo
	clone.users = users
	clone.events = nil
	return &clone
}

func (s *SessionService) SetEventSink(sink domain.EventSink) {
	if s != nil {
		s.events = sink
	}
}

func NewSessionService(repo domain.SessionRepository, users domain.UserDirectory, o SessionOptions, now domain.Clock) (*SessionService, error) {
	if repo == nil {
		return nil, errors.New("identity: session repository is required")
	}
	if o.TTL == 0 {
		o.TTL = 30 * 24 * time.Hour
	}
	if o.TTL <= 0 {
		return nil, errors.New("identity: session ttl must be positive")
	}
	if o.TouchInterval == 0 {
		o.TouchInterval = 5 * time.Minute
	}
	if o.TokenBytes == 0 {
		o.TokenBytes = 32
	}
	if o.TokenBytes < 16 {
		return nil, errors.New("identity: session token entropy is too short")
	}
	if o.Binding == nil {
		o.Binding = NoBinding{}
	}
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &SessionService{repo: repo, users: users, ttl: o.TTL, idle: o.IdleTimeout, touch: o.TouchInterval, tokenBytes: o.TokenBytes, binding: o.Binding, now: now, claims: o.Claims}, nil
}
func (s *SessionService) Create(ctx context.Context, id domain.UserID, meta domain.RequestMeta) (*IssuedSession, error) {
	var err error
	if id, err = domain.NormalizeUserID(id); err != nil {
		return nil, err
	}
	meta, e := domain.NormalizeRequestMeta(meta)
	if e != nil {
		return nil, e
	}
	if s.users != nil {
		u, e := s.users.UserByID(ctx, id)
		if e != nil {
			return nil, e
		}
		if u == nil {
			return nil, domain.ErrNotFound
		}
		if normalized, e := domain.NormalizeUserID(u.ID); e != nil || normalized != id {
			return nil, domain.ErrNotFound
		}
		if !u.Active() {
			return nil, domain.ErrDisabled
		}
	}
	raw := make([]byte, s.tokenBytes)
	if _, e := rand.Read(raw); e != nil {
		return nil, e
	}
	token := "sess_" + base64.RawURLEncoding.EncodeToString(raw)
	now := s.now().UTC()
	binding, e := s.binding.Bind(meta)
	if e != nil {
		return nil, e
	}
	sid := uuid.NewV7()
	r := &domain.SessionRecord{ID: sid, TokenHash: domain.HashBytes(token), UserID: id, LoginIP: meta.ClientIP, LastIP: meta.ClientIP, BindingHash: binding, ExpiresAt: now.Add(s.ttl), CreatedAt: now, LastSeenAt: now}
	if e = s.repo.CreateSession(ctx, *r); e != nil {
		return nil, e
	}
	emitEvent(ctx, s.events, domain.Event{Type: domain.EventSessionCreated, At: now, UserID: id, SessionID: sid, RequestMeta: meta})
	return &IssuedSession{Session: sessionView(r), Token: token}, nil
}
func (s *SessionService) Resolve(ctx context.Context, token string, meta domain.RequestMeta) (*domain.Principal, error) {
	if strings.TrimSpace(token) == "" {
		return nil, domain.ErrUnauthenticated
	}
	meta, e := domain.NormalizeRequestMeta(meta)
	if e != nil {
		return nil, e
	}
	r, e := s.repo.GetSessionByTokenHash(ctx, domain.HashBytes(token))
	if e != nil {
		if errors.Is(e, domain.ErrNotFound) {
			return nil, domain.ErrUnauthenticated
		}
		return nil, e
	}
	if r == nil {
		return nil, domain.ErrUnauthenticated
	}
	if normalized, err := domain.NormalizeSessionID(r.ID); err != nil {
		return nil, domain.ErrUnauthenticated
	} else {
		r.ID = normalized
	}
	if normalized, err := domain.NormalizeUserID(r.UserID); err != nil {
		return nil, domain.ErrUnauthenticated
	} else {
		r.UserID = normalized
	}
	now := s.now().UTC()
	if r.RevokedAt != nil {
		return nil, domain.ErrRevoked
	}
	if !r.ExpiresAt.After(now) {
		return nil, domain.ErrExpired
	}
	if s.idle > 0 && now.Sub(r.LastSeenAt) >= s.idle {
		return nil, domain.ErrExpired
	}
	if e = s.binding.Validate(*r, meta); e != nil {
		return nil, e
	}
	if s.users == nil {
		return nil, errors.New("identity: user directory is required")
	}
	u, e := s.users.UserByID(ctx, r.UserID)
	if e != nil {
		if errors.Is(e, domain.ErrNotFound) {
			return nil, domain.ErrUnauthenticated
		}
		return nil, e
	}
	if u == nil || !u.Active() {
		return nil, domain.ErrUnauthenticated
	}
	if normalized, err := domain.NormalizeUserID(u.ID); err != nil || normalized != r.UserID {
		return nil, domain.ErrUnauthenticated
	}
	if s.touch == 0 || now.Sub(r.LastSeenAt) >= s.touch {
		if e = s.repo.TouchSession(ctx, r.ID, meta.ClientIP, now.Add(-s.touch), now); e != nil && !errors.Is(e, domain.ErrNotFound) {
			return nil, e
		}
	}
	claims := domain.Claims{}
	if s.claims != nil {
		claims, e = s.claims(ctx, u)
		if e != nil {
			return nil, e
		}
	}
	return &domain.Principal{Subject: u.ID, User: u, Claims: claims, AuthenticatedAt: r.CreatedAt, SessionID: r.ID, ExpiresAt: r.ExpiresAt}, nil
}
func (s *SessionService) ListForUser(ctx context.Context, id domain.UserID) ([]domain.Session, error) {
	if _, err := domain.NormalizeUserID(id); err != nil {
		return nil, err
	}
	records, err := s.repo.ListSessionsForUser(ctx, id)
	if err != nil {
		return nil, err
	}
	out := make([]domain.Session, len(records))
	for i := range records {
		out[i] = *sessionView(&records[i])
	}
	return out, nil
}
func (s *SessionService) RevokeByID(ctx context.Context, id domain.SessionID, reason string) error {
	if _, err := domain.NormalizeSessionID(id); err != nil {
		return err
	}
	reason = strings.TrimSpace(reason)
	now := s.now().UTC()
	if err := s.repo.RevokeSession(ctx, id, reason, "", now); err != nil {
		return err
	}
	emitEvent(ctx, s.events, domain.Event{Type: domain.EventSessionRevoked, At: now, SessionID: id, Attributes: map[string]string{"reason": reason}})
	return nil
}
func (s *SessionService) DeleteExpired(ctx context.Context) (int64, error) {
	now := s.now().UTC()
	count, err := s.repo.DeleteExpiredSessions(ctx, now)
	if err == nil && count > 0 {
		emitEvent(ctx, s.events, domain.Event{Type: domain.EventExpiredSessionsDeleted, At: now, Attributes: map[string]string{"count": strconv.FormatInt(count, 10)}})
	}
	return count, err
}
func sessionView(record *domain.SessionRecord) *domain.Session {
	if record == nil {
		return nil
	}
	return &domain.Session{ID: record.ID, UserID: record.UserID, LoginIP: record.LoginIP, LastIP: record.LastIP, ExpiresAt: record.ExpiresAt, CreatedAt: record.CreatedAt, LastSeenAt: record.LastSeenAt, RevokedAt: record.RevokedAt, RevokedReason: record.RevokedReason}
}
func (s *SessionService) Revoke(ctx context.Context, token, reason string, meta domain.RequestMeta) error {
	if strings.TrimSpace(token) == "" {
		return domain.ErrUnauthenticated
	}
	meta, e := domain.NormalizeRequestMeta(meta)
	if e != nil {
		return e
	}
	r, e := s.repo.GetSessionByTokenHash(ctx, domain.HashBytes(token))
	if e != nil {
		return e
	}
	if r == nil {
		return domain.ErrUnauthenticated
	}
	id, err := domain.NormalizeSessionID(r.ID)
	if err != nil {
		return domain.ErrUnauthenticated
	}
	reason = strings.TrimSpace(reason)
	now := s.now().UTC()
	if err := s.repo.RevokeSession(ctx, id, reason, meta.ClientIP, now); err != nil {
		return err
	}
	emitEvent(ctx, s.events, domain.Event{Type: domain.EventSessionRevoked, At: now, UserID: r.UserID, SessionID: id, RequestMeta: meta, Attributes: map[string]string{"reason": reason}})
	return nil
}
func (s *SessionService) RevokeForUsers(ctx context.Context, ids []domain.UserID, reason string) error {
	normalized, err := normalizeUserIDs(ids)
	if err != nil {
		return err
	}
	reason = strings.TrimSpace(reason)
	now := s.now().UTC()
	if err := s.repo.RevokeSessionsForUsers(ctx, normalized, reason, now); err != nil {
		return err
	}
	for _, id := range normalized {
		emitEvent(ctx, s.events, domain.Event{Type: domain.EventUserSessionsRevoked, At: now, UserID: id, Attributes: map[string]string{"reason": reason}})
	}
	return nil
}
func (s *SessionService) DeleteForUsers(ctx context.Context, ids []domain.UserID) error {
	normalized, err := normalizeUserIDs(ids)
	if err != nil {
		return err
	}
	return s.repo.DeleteSessionsForUsers(ctx, normalized)
}
