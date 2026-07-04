package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
)

// Encryptor encrypts and decrypts short secrets (e.g. LDAP bind passwords) for storage at rest.
type Encryptor interface {
	Encrypt(plaintext string) (string, error)
	Decrypt(stored string) (string, error)
}

const prefix = "enc:v1:"

// AESGCM is an AES-256-GCM Encryptor. The key is derived from the configured
// SSO_ENCRYPTION_KEY via SHA-256, so any string of sufficient entropy works.
type AESGCM struct {
	key [32]byte
}

func NewAESGCM(key string) *AESGCM {
	return &AESGCM{key: sha256.Sum256([]byte(key))}
}

func (e *AESGCM) Encrypt(plaintext string) (string, error) {
	block, err := aes.NewCipher(e.key[:])
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	sealed := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return prefix + base64.RawStdEncoding.EncodeToString(sealed), nil
}

// Decrypt returns values without the enc:v1: prefix unchanged, so rows written
// before encryption was introduced keep working and are re-encrypted on next update.
func (e *AESGCM) Decrypt(stored string) (string, error) {
	if !strings.HasPrefix(stored, prefix) {
		return stored, nil
	}
	raw, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(stored, prefix))
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(e.key[:])
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(raw) < gcm.NonceSize() {
		return "", errors.New("ciphertext too short")
	}
	plain, err := gcm.Open(nil, raw[:gcm.NonceSize()], raw[gcm.NonceSize():], nil)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}
