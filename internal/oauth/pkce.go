package oauth

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
)

var ErrInvalidPKCE = errors.New("invalid pkce verifier")

func VerifyPKCES256(verifier, challenge string) error {
	if verifier == "" || challenge == "" {
		return ErrInvalidPKCE
	}
	sum := sha256.Sum256([]byte(verifier))
	computed := base64.RawURLEncoding.EncodeToString(sum[:])
	if computed != challenge {
		return ErrInvalidPKCE
	}
	return nil
}
