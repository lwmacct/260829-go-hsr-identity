package service

import (
	"context"
	"errors"
	"strings"
	"time"
	"uuid"

	"github.com/lwmacct/260829-go-hsr-identity/pkg/identity/domain"
)

type ContactService struct {
	repo          domain.ContactRepository
	users         *UserService
	tx            TxManager
	phoneProvider domain.ContactVerificationProvider
	emailProvider domain.ContactVerificationProvider
	ttl           time.Duration
	resend        time.Duration
	maxAttempts   int
	now           domain.Clock
	events        domain.EventSink
}

func NewContactService(repo domain.ContactRepository, users *UserService, tx TxManager, phoneProvider, emailProvider domain.ContactVerificationProvider, ttl, resend time.Duration, maxAttempts int, now domain.Clock) (*ContactService, error) {
	if repo == nil || users == nil || tx == nil {
		return nil, errors.New("identity: contact dependencies are required")
	}
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	if resend <= 0 {
		resend = time.Minute
	}
	if maxAttempts <= 0 {
		maxAttempts = 5
	}
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &ContactService{
		repo:          repo,
		users:         users,
		tx:            tx,
		phoneProvider: phoneProvider,
		emailProvider: emailProvider,
		ttl:           ttl,
		resend:        resend,
		maxAttempts:   maxAttempts,
		now:           now,
	}, nil
}

func (s *ContactService) SetEventSink(sink domain.EventSink) {
	if s != nil {
		s.events = sink
	}
}

func (s *ContactService) ResendInterval() time.Duration {
	if s == nil {
		return 0
	}
	return s.resend
}

func (s *ContactService) Enabled(kind domain.ContactKind) bool {
	_, err := s.provider(kind)
	return err == nil
}

func (s *ContactService) provider(kind domain.ContactKind) (domain.ContactVerificationProvider, error) {
	switch kind {
	case domain.ContactKindPhone:
		if s.phoneProvider == nil {
			return nil, domain.ErrVerificationUnsupported
		}
		return s.phoneProvider, nil
	case domain.ContactKindEmail:
		if s.emailProvider == nil {
			return nil, domain.ErrVerificationUnsupported
		}
		return s.emailProvider, nil
	default:
		return nil, domain.ErrInvalidContactKind
	}
}

func (s *ContactService) ListUserContacts(ctx context.Context, userID domain.UserID) ([]domain.UserContact, error) {
	if _, err := domain.NormalizeUserID(userID); err != nil {
		return nil, err
	}
	return s.repo.ListUserContacts(ctx, userID)
}

func (s *ContactService) StartVerification(ctx context.Context, userID domain.UserID, kind domain.ContactKind, rawValue string, meta domain.RequestMeta) (*domain.ContactVerification, error) {
	userID, err := domain.NormalizeUserID(userID)
	if err != nil {
		return nil, err
	}
	if err := s.validateActiveUser(ctx, userID); err != nil {
		return nil, err
	}
	value, err := normalizeContactValue(kind, rawValue)
	if err != nil {
		return nil, err
	}
	if meta, err = domain.NormalizeRequestMeta(meta); err != nil {
		return nil, err
	}
	if _, err := s.repo.GetUserByContact(ctx, kind, value); err == nil {
		return nil, domain.ErrContactTaken
	} else if !errors.Is(err, domain.ErrNotFound) {
		return nil, err
	}
	provider, err := s.provider(kind)
	if err != nil {
		return nil, err
	}
	now := s.now().UTC()
	if pending, pendingErr := s.repo.GetPendingContactVerification(ctx, userID, kind); pendingErr == nil {
		if pending.ExpiresAt.After(now) && pending.CreatedAt.Add(s.resend).After(now) {
			return nil, domain.ErrRateLimited
		}
		if pending.ExpiresAt.Before(now) {
			pending.Status = domain.ContactVerificationExpired
			_ = s.repo.UpdateContactVerification(ctx, *pending)
		}
	} else if !errors.Is(pendingErr, domain.ErrVerificationNotFound) {
		return nil, pendingErr
	}
	challenge, err := provider.Start(ctx, domain.ContactVerificationStart{UserID: userID, Kind: kind, Value: value, RequestMeta: meta})
	if err != nil {
		return nil, normalizeProviderError(err)
	}
	providerName := strings.TrimSpace(provider.Name())
	if providerName == "" || strings.TrimSpace(challenge.Provider) != providerName || strings.TrimSpace(challenge.ChallengeID) == "" {
		return nil, domain.ErrVerificationUnavailable
	}
	expiresAt := now.Add(s.ttl)
	if !challenge.ExpiresAt.IsZero() && challenge.ExpiresAt.Before(expiresAt) {
		expiresAt = challenge.ExpiresAt
	}
	if !expiresAt.After(now) {
		return nil, domain.ErrVerificationExpired
	}
	record := domain.ContactVerification{
		ID:                  domain.ContactVerificationID(uuid.NewV7()),
		UserID:              userID,
		Kind:                kind,
		Value:               value,
		Provider:            providerName,
		ProviderChallengeID: strings.TrimSpace(challenge.ChallengeID),
		Status:              domain.ContactVerificationPending,
		ExpiresAt:           expiresAt,
		CreatedAt:           now,
	}
	if err := s.tx.WithinTx(ctx, func(c context.Context, uow UnitOfWork) error {
		if err := uow.Contacts().CancelPendingContactVerifications(c, userID, kind, record.ID); err != nil {
			return err
		}
		return uow.Contacts().CreateContactVerification(c, record)
	}); err != nil {
		return nil, err
	}
	emitEvent(ctx, s.events, domain.Event{
		Type: domain.EventContactVerificationStarted,
		At:   now, UserID: userID,
		Attributes: map[string]string{"kind": string(kind), "provider": providerName},
	})
	return &record, nil
}

func (s *ContactService) ConfirmVerification(ctx context.Context, userID domain.UserID, kind domain.ContactKind, verificationID domain.ContactVerificationID, code string, meta domain.RequestMeta) (*domain.UserContact, error) {
	userID, err := domain.NormalizeUserID(userID)
	if err != nil {
		return nil, err
	}
	if !kind.Valid() {
		return nil, domain.ErrInvalidContactKind
	}
	if strings.TrimSpace(code) == "" {
		return nil, domain.ErrVerificationInvalid
	}
	if meta, err = domain.NormalizeRequestMeta(meta); err != nil {
		return nil, err
	}
	record, err := s.repo.GetContactVerification(ctx, verificationID)
	if err != nil {
		return nil, err
	}
	if record.UserID != userID || record.Kind != kind {
		return nil, domain.ErrVerificationNotFound
	}
	now := s.now().UTC()
	if record.Status != domain.ContactVerificationPending {
		return nil, verificationStatusError(record.Status)
	}
	if !record.ExpiresAt.After(now) {
		record.Status = domain.ContactVerificationExpired
		_ = s.repo.UpdateContactVerification(ctx, *record)
		return nil, domain.ErrVerificationExpired
	}
	provider, err := s.provider(kind)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(provider.Name()) != record.Provider {
		return nil, domain.ErrVerificationUnavailable
	}
	err = provider.Verify(ctx, domain.ContactVerificationVerify{
		UserID: userID, Kind: kind, ChallengeID: record.ProviderChallengeID, Code: code, RequestMeta: meta,
	})
	if err != nil {
		err = normalizeProviderError(err)
		if errors.Is(err, domain.ErrVerificationInvalid) {
			updated, updateErr := s.repo.RecordContactVerificationFailure(ctx, verificationID, s.maxAttempts, now)
			if updateErr != nil {
				return nil, updateErr
			}
			if updated.Status != domain.ContactVerificationPending && updated.Status != domain.ContactVerificationFailed {
				return nil, verificationStatusError(updated.Status)
			}
			emitEvent(ctx, s.events, domain.Event{
				Type: domain.EventContactVerificationFailed,
				At:   now, UserID: userID,
				Attributes: map[string]string{"kind": string(kind)},
			})
		}
		return nil, err
	}
	var contact *domain.UserContact
	if err := s.tx.WithinTx(ctx, func(c context.Context, uow UnitOfWork) error {
		current, err := uow.Contacts().GetContactVerification(c, verificationID)
		if err != nil {
			return err
		}
		if current.UserID != userID || current.Kind != kind || current.Status != domain.ContactVerificationPending {
			return verificationStatusError(current.Status)
		}
		if !current.ExpiresAt.After(s.now().UTC()) {
			current.Status = domain.ContactVerificationExpired
			_ = uow.Contacts().UpdateContactVerification(c, *current)
			return domain.ErrVerificationExpired
		}
		verifiedAt := s.now().UTC()
		item := &domain.UserContact{
			ID:         domain.ContactID(uuid.NewV7()),
			UserID:     userID,
			Kind:       kind,
			Value:      current.Value,
			VerifiedAt: verifiedAt,
			CreatedAt:  verifiedAt,
			UpdatedAt:  verifiedAt,
		}
		if err := uow.Contacts().ReplaceUserContact(c, *item); err != nil {
			return err
		}
		current.Status = domain.ContactVerificationConsumed
		current.ConsumedAt = &verifiedAt
		if err := uow.Contacts().UpdateContactVerification(c, *current); err != nil {
			return err
		}
		if err := uow.Contacts().CancelPendingContactVerifications(c, userID, kind, verificationID); err != nil {
			return err
		}
		contact = item
		return nil
	}); err != nil {
		return nil, err
	}
	emitEvent(ctx, s.events, domain.Event{
		Type: domain.EventContactVerificationSucceeded,
		At:   contact.VerifiedAt, UserID: userID,
		Attributes: map[string]string{"kind": string(kind)},
	})
	emitEvent(ctx, s.events, domain.Event{
		Type: domain.EventContactBound,
		At:   contact.VerifiedAt, UserID: userID,
		Attributes: map[string]string{"kind": string(kind)},
	})
	return contact, nil
}

func (s *ContactService) Unbind(ctx context.Context, userID domain.UserID, kind domain.ContactKind) error {
	userID, err := domain.NormalizeUserID(userID)
	if err != nil {
		return err
	}
	if !kind.Valid() {
		return domain.ErrInvalidContactKind
	}
	now := s.now().UTC()
	if err := s.tx.WithinTx(ctx, func(c context.Context, uow UnitOfWork) error {
		if err := uow.Contacts().DeleteUserContact(c, userID, kind); err != nil {
			return err
		}
		return uow.Contacts().CancelPendingContactVerifications(c, userID, kind, domain.ContactVerificationID{})
	}); err != nil {
		return err
	}
	emitEvent(ctx, s.events, domain.Event{
		Type: domain.EventContactUnbound,
		At:   now, UserID: userID,
		Attributes: map[string]string{"kind": string(kind)},
	})
	return nil
}

func (s *ContactService) validateActiveUser(ctx context.Context, userID domain.UserID) error {
	user, err := s.users.UserByID(ctx, userID)
	if err != nil {
		return err
	}
	return s.users.EnsureActive(user)
}

func normalizeContactValue(kind domain.ContactKind, value string) (string, error) {
	switch kind {
	case domain.ContactKindPhone:
		normalized, err := domain.NormalizePhone(value)
		if err != nil || normalized == "" {
			if err != nil {
				return "", err
			}
			return "", domain.ErrInvalidPhone
		}
		return normalized, nil
	case domain.ContactKindEmail:
		normalized, err := domain.NormalizeEmail(value)
		if err != nil || normalized == "" {
			if err != nil {
				return "", err
			}
			return "", domain.ErrInvalidEmail
		}
		return normalized, nil
	default:
		return "", domain.ErrInvalidContactKind
	}
}

func verificationStatusError(status domain.ContactVerificationStatus) error {
	switch status {
	case domain.ContactVerificationExpired:
		return domain.ErrVerificationExpired
	case domain.ContactVerificationPending:
		return nil
	default:
		return domain.ErrVerificationInvalid
	}
}

func normalizeProviderError(err error) error {
	switch {
	case errors.Is(err, domain.ErrVerificationInvalid):
		return domain.ErrVerificationInvalid
	case errors.Is(err, domain.ErrVerificationExpired):
		return domain.ErrVerificationExpired
	case errors.Is(err, domain.ErrRateLimited):
		return domain.ErrRateLimited
	case errors.Is(err, domain.ErrVerificationUnsupported):
		return domain.ErrVerificationUnsupported
	case errors.Is(err, domain.ErrVerificationUnavailable):
		return domain.ErrVerificationUnavailable
	default:
		return domain.ErrVerificationUnavailable
	}
}
