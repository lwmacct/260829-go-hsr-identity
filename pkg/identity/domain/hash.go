package domain

import "crypto/sha256"

func HashBytes(value string) []byte {
	result := sha256.Sum256([]byte(value))
	return result[:]
}
