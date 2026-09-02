package repository

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
	"uuid"

	"github.com/lwmacct/260829-go-hsr-identity/pkg/identity/domain"
)

func (s *Store) ListUserContacts(ctx context.Context, userID domain.UserID) ([]domain.UserContact, error) {
	if _, err := domain.NormalizeUserID(userID); err != nil {
		return nil, err
	}
	rows := make([]UserContactModel, 0, 2)
	if err := s.db.NewSelect().Model(&rows).
		Where("uc.user_id = ?", userID.String()).
		OrderExpr("uc.kind ASC").
		Scan(ctx); err != nil {
		return nil, mapReadError(err)
	}
	out := make([]domain.UserContact, len(rows))
	for i := range rows {
		out[i] = *contactFrom(&rows[i])
	}
	return out, nil
}

func (s *Store) GetUserContact(ctx context.Context, userID domain.UserID, kind domain.ContactKind) (*domain.UserContact, error) {
	if _, err := domain.NormalizeUserID(userID); err != nil {
		return nil, err
	}
	if !kind.Valid() {
		return nil, domain.ErrInvalidContactKind
	}
	row := new(UserContactModel)
	if err := s.db.NewSelect().Model(row).
		Where("uc.user_id = ?", userID.String()).
		Where("uc.kind = ?", string(kind)).
		Scan(ctx); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, domain.ErrContactNotFound
		}
		return nil, err
	}
	return contactFrom(row), nil
}

func (s *Store) GetUserByContact(ctx context.Context, kind domain.ContactKind, value string) (*domain.User, error) {
	if !kind.Valid() {
		return nil, domain.ErrInvalidContactKind
	}
	row := new(UserModel)
	if err := s.db.NewSelect().Model(row).
		Join("JOIN identity_user_contacts AS uc ON uc.user_id = u.id").
		Where("uc.kind = ?", string(kind)).
		Where("uc.normalized_value = ?", value).
		Where("uc.verified_at IS NOT NULL").
		Scan(ctx); err != nil {
		return nil, mapReadError(err)
	}
	return userFrom(row), nil
}

func (s *Store) ReplaceUserContact(ctx context.Context, contact domain.UserContact) error {
	if _, err := domain.NormalizeContactID(contact.ID); err != nil {
		return err
	}
	if _, err := domain.NormalizeUserID(contact.UserID); err != nil {
		return err
	}
	if !contact.Kind.Valid() || strings.TrimSpace(contact.Value) == "" || contact.VerifiedAt.IsZero() {
		return domain.ErrInvalid
	}
	if _, err := s.db.NewDelete().Model((*UserContactModel)(nil)).
		Where("user_id = ?", contact.UserID.String()).
		Where("kind = ?", string(contact.Kind)).
		Exec(ctx); err != nil {
		return mapContactWriteError(err)
	}
	row := &UserContactModel{
		ID:         contact.ID.String(),
		UserID:     contact.UserID.String(),
		Kind:       string(contact.Kind),
		Value:      contact.Value,
		VerifiedAt: contact.VerifiedAt,
		CreatedAt:  contact.CreatedAt,
		UpdatedAt:  contact.UpdatedAt,
	}
	if _, err := s.db.NewInsert().Model(row).Exec(ctx); err != nil {
		return mapContactWriteError(err)
	}
	return nil
}

func (s *Store) DeleteUserContact(ctx context.Context, userID domain.UserID, kind domain.ContactKind) error {
	if _, err := domain.NormalizeUserID(userID); err != nil {
		return err
	}
	if !kind.Valid() {
		return domain.ErrInvalidContactKind
	}
	res, err := s.db.NewDelete().Model((*UserContactModel)(nil)).
		Where("user_id = ?", userID.String()).
		Where("kind = ?", string(kind)).
		Exec(ctx)
	if err != nil {
		return mapContactWriteError(err)
	}
	affected, _ := res.RowsAffected()
	if affected == 0 {
		return domain.ErrContactNotFound
	}
	return nil
}

func (s *Store) GetContactVerification(ctx context.Context, id domain.ContactVerificationID) (*domain.ContactVerification, error) {
	if _, err := domain.NormalizeContactVerificationID(id); err != nil {
		return nil, err
	}
	row := new(ContactVerificationModel)
	if err := s.db.NewSelect().Model(row).Where("cv.id = ?", id.String()).Scan(ctx); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, domain.ErrVerificationNotFound
		}
		return nil, err
	}
	return verificationFrom(row), nil
}

func (s *Store) GetPendingContactVerification(ctx context.Context, userID domain.UserID, kind domain.ContactKind) (*domain.ContactVerification, error) {
	if _, err := domain.NormalizeUserID(userID); err != nil {
		return nil, err
	}
	if !kind.Valid() {
		return nil, domain.ErrInvalidContactKind
	}
	row := new(ContactVerificationModel)
	if err := s.db.NewSelect().Model(row).
		Where("cv.user_id = ?", userID.String()).
		Where("cv.kind = ?", string(kind)).
		Where("cv.status = ?", string(domain.ContactVerificationPending)).
		OrderExpr("cv.created_at DESC").
		Limit(1).
		Scan(ctx); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, domain.ErrVerificationNotFound
		}
		return nil, err
	}
	return verificationFrom(row), nil
}

func (s *Store) CreateContactVerification(ctx context.Context, verification domain.ContactVerification) error {
	if _, err := domain.NormalizeContactVerificationID(verification.ID); err != nil {
		return err
	}
	if _, err := domain.NormalizeUserID(verification.UserID); err != nil {
		return err
	}
	if !verification.Kind.Valid() || verification.Status == "" || strings.TrimSpace(verification.Provider) == "" || strings.TrimSpace(verification.ProviderChallengeID) == "" {
		return domain.ErrInvalid
	}
	row := &ContactVerificationModel{
		ID:                  verification.ID.String(),
		UserID:              verification.UserID.String(),
		Kind:                string(verification.Kind),
		Value:               verification.Value,
		Provider:            verification.Provider,
		ProviderChallengeID: verification.ProviderChallengeID,
		Status:              string(verification.Status),
		AttemptCount:        verification.AttemptCount,
		ExpiresAt:           verification.ExpiresAt,
		CreatedAt:           verification.CreatedAt,
		ConsumedAt:          verification.ConsumedAt,
	}
	if _, err := s.db.NewInsert().Model(row).Exec(ctx); err != nil {
		return mapContactWriteError(err)
	}
	return nil
}

func (s *Store) UpdateContactVerification(ctx context.Context, verification domain.ContactVerification) error {
	if _, err := domain.NormalizeContactVerificationID(verification.ID); err != nil {
		return err
	}
	query := s.db.NewUpdate().Model((*ContactVerificationModel)(nil)).
		Set("status = ?", string(verification.Status)).
		Set("attempt_count = ?", verification.AttemptCount).
		Set("consumed_at = ?", verification.ConsumedAt).
		Where("id = ?", verification.ID.String())
	res, err := query.Exec(ctx)
	if err != nil {
		return mapContactWriteError(err)
	}
	if affected, _ := res.RowsAffected(); affected == 0 {
		return domain.ErrVerificationNotFound
	}
	return nil
}

func (s *Store) RecordContactVerificationFailure(ctx context.Context, id domain.ContactVerificationID, maxAttempts int, now time.Time) (*domain.ContactVerification, error) {
	if _, err := domain.NormalizeContactVerificationID(id); err != nil {
		return nil, err
	}
	if maxAttempts < 1 {
		maxAttempts = 1
	}
	_, err := s.db.NewRaw(`
		UPDATE identity_contact_verifications
		SET attempt_count = attempt_count + 1,
		    status = CASE
		        WHEN attempt_count + 1 >= ? THEN ?
		        ELSE status
		    END
		WHERE id = ?
		  AND status = ?
		  AND expires_at > ?
	`, maxAttempts, string(domain.ContactVerificationFailed), id.String(), string(domain.ContactVerificationPending), now).Exec(ctx)
	if err != nil {
		return nil, mapContactWriteError(err)
	}
	return s.GetContactVerification(ctx, id)
}

func (s *Store) CancelPendingContactVerifications(ctx context.Context, userID domain.UserID, kind domain.ContactKind, exceptID domain.ContactVerificationID) error {
	if _, err := domain.NormalizeUserID(userID); err != nil {
		return err
	}
	if !kind.Valid() {
		return domain.ErrInvalidContactKind
	}
	query := s.db.NewUpdate().Model((*ContactVerificationModel)(nil)).
		Set("status = ?", string(domain.ContactVerificationCancelled)).
		Where("user_id = ?", userID.String()).
		Where("kind = ?", string(kind)).
		Where("status = ?", string(domain.ContactVerificationPending))
	if exceptID != (domain.ContactVerificationID{}) {
		if _, err := domain.NormalizeContactVerificationID(exceptID); err != nil {
			return err
		}
		query = query.Where("id <> ?", exceptID.String())
	}
	_, err := query.Exec(ctx)
	return mapContactWriteError(err)
}

func contactFrom(row *UserContactModel) *domain.UserContact {
	id, _ := uuid.Parse(row.ID)
	userID, _ := uuid.Parse(row.UserID)
	return &domain.UserContact{
		ID:         domain.ContactID(id),
		UserID:     domain.UserID(userID),
		Kind:       domain.ContactKind(row.Kind),
		Value:      row.Value,
		VerifiedAt: row.VerifiedAt,
		CreatedAt:  row.CreatedAt,
		UpdatedAt:  row.UpdatedAt,
	}
}

func verificationFrom(row *ContactVerificationModel) *domain.ContactVerification {
	id, _ := uuid.Parse(row.ID)
	userID, _ := uuid.Parse(row.UserID)
	return &domain.ContactVerification{
		ID:                  domain.ContactVerificationID(id),
		UserID:              domain.UserID(userID),
		Kind:                domain.ContactKind(row.Kind),
		Value:               row.Value,
		Provider:            row.Provider,
		ProviderChallengeID: row.ProviderChallengeID,
		Status:              domain.ContactVerificationStatus(row.Status),
		AttemptCount:        row.AttemptCount,
		ExpiresAt:           row.ExpiresAt,
		CreatedAt:           row.CreatedAt,
		ConsumedAt:          row.ConsumedAt,
	}
}

func mapContactWriteError(err error) error {
	if err == nil {
		return nil
	}
	if code, constraint, ok := postgresErrorFields(err); ok {
		switch code {
		case "23505":
			switch constraint {
			case "identity_user_contacts_user_kind_uq", "identity_user_contacts_kind_value_uq":
				return domain.ErrContactTaken
			default:
				return domain.ErrConflict
			}
		case "23502", "23503", "23514", "23P01":
			return domain.ErrConflict
		}
	}
	lower := strings.ToLower(err.Error())
	if strings.Contains(lower, "identity_user_contacts_user_kind_uq") ||
		strings.Contains(lower, "identity_user_contacts_kind_value_uq") ||
		strings.Contains(lower, "identity_user_contacts") && strings.Contains(lower, "unique") {
		return domain.ErrContactTaken
	}
	if strings.Contains(lower, "unique") || strings.Contains(lower, "duplicate") || strings.Contains(lower, "constraint") || strings.Contains(lower, "foreign key") {
		return domain.ErrConflict
	}
	return err
}

var _ domain.ContactRepository = (*Store)(nil)
