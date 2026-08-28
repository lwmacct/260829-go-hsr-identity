package identity

import "crypto/sha256"

// HashBytes returns the SHA-256 digest used for opaque tokens and sensitive
// lookup keys. Callers should treat the returned bytes as immutable.
func HashBytes(value string) []byte {
	result := sha256.Sum256([]byte(value))
	return result[:]
}
