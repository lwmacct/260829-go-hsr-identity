package identity

import "github.com/lwmacct/260829-go-hsr-identity/pkg/identity/domain"

// HashBytes returns the SHA-256 digest used for opaque tokens and sensitive
// lookup keys. Callers should treat the returned bytes as immutable.
func HashBytes(value string) []byte {
	return domain.HashBytes(value)
}
