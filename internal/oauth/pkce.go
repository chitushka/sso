package oauth

import (
	"crypto/sha256"
	"encoding/base64"
)

func VerifyPKCES256(verifier, challenge string) bool {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:]) == challenge
}
