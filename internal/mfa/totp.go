package mfa

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"time"
)

// TOTP per RFC 6238: SHA-1, 6 digits, 30-second period — the parameters
// every authenticator app supports.
const (
	period = 30
	digits = 6
)

func GenerateSecret() (string, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b), nil
}

// OTPAuthURL builds the otpauth:// URI encoded into the enrollment QR code.
func OTPAuthURL(issuer, account, secret string) string {
	return fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=%d&period=%d",
		url.PathEscape(issuer), url.PathEscape(account), secret, url.QueryEscape(issuer), digits, period)
}

func code(secret string, counter uint64) (string, error) {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		return "", err
	}
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)
	mac := hmac.New(sha1.New, key)
	mac.Write(buf[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	value := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", value%1000000), nil
}

// Verify accepts the code for the current period and one period either side
// to tolerate clock drift.
func Verify(secret, otp string, at time.Time) bool {
	ok, _ := VerifyWithCounter(secret, otp, at)
	return ok
}

// VerifyWithCounter is like Verify but also returns the matched time-step, so
// the caller can persist it and reject replays of that step within its window.
func VerifyWithCounter(secret, otp string, at time.Time) (bool, uint64) {
	if len(otp) != digits {
		return false, 0
	}
	counter := uint64(at.Unix()) / period
	for _, c := range []uint64{counter, counter - 1, counter + 1} {
		expected, err := code(secret, c)
		if err != nil {
			return false, 0
		}
		if subtle.ConstantTimeCompare([]byte(expected), []byte(otp)) == 1 {
			return true, c
		}
	}
	return false, 0
}
