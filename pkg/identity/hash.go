package identity

import (
	"github.com/lwmacct/260829-go-hsr-identity/internal/identity/service"
	"github.com/lwmacct/260829-go-hsr-identity/pkg/identity/domain"
)

// HashBytes returns the SHA-256 digest used for opaque tokens and sensitive
// lookup keys. Callers should treat the returned bytes as immutable.
func HashBytes(value string) []byte {
	return domain.HashBytes(value)
}

// Argon2id is the module's password hasher. It is exposed so host-owned
// workflows (for example an application-specific admin form) can provision a
// credential without reimplementing the password format or parameters.
type Argon2id = service.Argon2id

// NewArgon2id constructs an Argon2id hasher using the module's validated
// defaults when params is zero-valued.
func NewArgon2id(params Argon2idParams) (Argon2id, error) {
	return service.NewArgon2id(service.Argon2idParams{
		Memory:      params.Memory,
		Iterations:  params.Iterations,
		Parallelism: params.Parallelism,
		SaltLength:  params.SaltLength,
		KeyLength:   params.KeyLength,
	})
}
