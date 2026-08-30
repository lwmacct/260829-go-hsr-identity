package service

import (
	"context"
	"strings"
	"testing"
	"time"
	"uuid"

	"github.com/lwmacct/260829-go-hsr-identity/pkg/identity/domain"
	"golang.org/x/crypto/bcrypt"
)

func TestArgon2VerifyRejectsMalformedAndUnsafeParameters(t *testing.T) {
	h, err := NewArgon2id(Argon2idParams{Memory: 8 * 1024, Iterations: 1, Parallelism: 1, SaltLength: 8, KeyLength: 16})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := h.Hash("correct horse")
	if err != nil {
		t.Fatal(err)
	}
	cases := []string{
		encoded,
		strings.Replace(encoded, "m=8192", "m=1", 1),
		strings.Replace(encoded, "m=8192", "m=4294967295", 1),
		strings.Replace(encoded, "p=1", "p=0", 1),
		strings.Replace(encoded, "p=1", "p=255", 1),
		strings.Replace(encoded, "t=1", "t=21", 1),
		strings.Replace(encoded, "m=8192,t=1,p=1", "m=8192,t=1,p=1,x=1", 1),
		"$argon2id$v=19$m=8192,t=1,p=1$%%%$%%%",
	}
	for i, value := range cases {
		got := h.Verify(value, "correct horse")
		if i == 0 && !got {
			t.Fatal("valid hash did not verify")
		}
		if i > 0 && got {
			t.Fatalf("malformed hash case %d verified", i)
		}
	}
}

func TestArgon2NeedsRehash(t *testing.T) {
	old, err := NewArgon2id(Argon2idParams{Memory: 8 * 1024, Iterations: 1, Parallelism: 1, SaltLength: 8, KeyLength: 16})
	if err != nil {
		t.Fatal(err)
	}
	current, err := NewArgon2id(Argon2idParams{Memory: 8 * 1024, Iterations: 2, Parallelism: 1, SaltLength: 8, KeyLength: 16})
	if err != nil {
		t.Fatal(err)
	}
	hash, err := old.Hash("correct horse")
	if err != nil {
		t.Fatal(err)
	}
	if !current.NeedsRehash(hash) {
		t.Fatal("stale parameters were not detected")
	}
	if current.NeedsRehash(hash) && !current.Verify(hash, "correct horse") {
		t.Fatal("stale but valid hash did not verify")
	}
}

func TestPasswordHasherChainVerifiesAndUpgradesFallback(t *testing.T) {
	primary, err := NewArgon2id(Argon2idParams{Memory: 8 * 1024, Iterations: 1, Parallelism: 1, SaltLength: 8, KeyLength: 16})
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := NewBcrypt(bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	chain, err := NewPasswordHasherChain(primary, legacy)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := legacy.Hash("correct horse")
	if err != nil {
		t.Fatal(err)
	}
	if !chain.VerifyScheme(legacy.Scheme(), hash, "correct horse") {
		t.Fatal("legacy hash did not verify")
	}
	if !chain.NeedsRehashScheme(legacy.Scheme(), hash) {
		t.Fatal("legacy hash was not marked for upgrade")
	}
}

type passwordCASRepository struct {
	credential domain.PasswordCredential
	concurrent domain.PasswordCredential
	updated    bool
}

func (r *passwordCASRepository) GetPasswordCredential(context.Context, domain.UserID) (*domain.PasswordCredential, error) {
	credential := r.credential
	return &credential, nil
}

func (*passwordCASRepository) UpsertPasswordCredential(context.Context, domain.PasswordCredential) error {
	return nil
}

func (r *passwordCASRepository) UpdatePasswordCredentialIfMatch(_ context.Context, _ domain.UserID, expectedScheme, expectedHash string, next domain.PasswordCredential) (bool, error) {
	r.credential = r.concurrent
	if r.credential.Scheme != expectedScheme || r.credential.Hash != expectedHash {
		return false, nil
	}
	r.credential = next
	r.updated = true
	return true, nil
}

func (*passwordCASRepository) DeletePasswordCredentials(context.Context, []domain.UserID) error {
	return nil
}

func TestPasswordUpgradeDoesNotOverwriteConcurrentReset(t *testing.T) {
	legacy, err := NewBcrypt(bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	primary, err := NewArgon2id(Argon2idParams{Memory: 8 * 1024, Iterations: 1, Parallelism: 1, SaltLength: 8, KeyLength: 16})
	if err != nil {
		t.Fatal(err)
	}
	chain, err := NewPasswordHasherChain(primary, legacy)
	if err != nil {
		t.Fatal(err)
	}
	oldHash, err := legacy.Hash("correct horse")
	if err != nil {
		t.Fatal(err)
	}
	resetHash, err := primary.Hash("new password")
	if err != nil {
		t.Fatal(err)
	}
	userID := uuid.NewV7()
	now := time.Unix(100, 0).UTC()
	repository := &passwordCASRepository{
		credential: domain.PasswordCredential{UserID: userID, Scheme: legacy.Scheme(), Hash: oldHash, PasswordChangedAt: now, CreatedAt: now, UpdatedAt: now},
		concurrent: domain.PasswordCredential{UserID: userID, Scheme: primary.Scheme(), Hash: resetHash, PasswordChangedAt: now.Add(time.Minute), CreatedAt: now, UpdatedAt: now.Add(time.Minute)},
	}
	passwords, err := NewPasswordService(repository, nil, PasswordOptions{Hasher: chain, Policy: PasswordPolicy{MinLength: 8}}, func() time.Time {
		return now.Add(2 * time.Minute)
	}, domain.UsernamePolicyFunc(domain.LowerASCIIUsernamePolicy))
	if err != nil {
		t.Fatal(err)
	}
	if err := passwords.AuthenticateUser(context.Background(), userID, "correct horse"); err != nil {
		t.Fatal(err)
	}
	if repository.updated || repository.credential.Hash != resetHash {
		t.Fatalf("concurrent reset was overwritten: %#v", repository.credential)
	}
}
