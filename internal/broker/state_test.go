package broker

import (
	"strings"
	"testing"
	"time"
)

var secret = []byte("0123456789abcdef0123456789abcdef")

func TestStateRoundTrip(t *testing.T) {
	signed, err := signState(secret, state{Provider: "google", Nonce: "n", Continue: "/users", Exp: time.Now().Add(10 * time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	st, err := verifyState(secret, signed)
	if err != nil {
		t.Fatal(err)
	}
	if st.Provider != "google" || st.Continue != "/users" {
		t.Fatalf("unexpected state %+v", st)
	}
}

func TestStateTamperRejected(t *testing.T) {
	signed, _ := signState(secret, state{Provider: "google", Exp: time.Now().Add(time.Minute)})
	parts := strings.SplitN(signed, ".", 2)
	forged, _ := signState(secret, state{Provider: "github", Exp: time.Now().Add(time.Minute)})
	forgedPayload := strings.SplitN(forged, ".", 2)[0]
	if _, err := verifyState(secret, forgedPayload+"."+parts[1]); err == nil {
		t.Fatal("tampered payload must be rejected")
	}
	if _, err := verifyState([]byte("another-secret-another-secret-32"), signed); err == nil {
		t.Fatal("wrong key must be rejected")
	}
}

func TestStateExpiryRejected(t *testing.T) {
	signed, _ := signState(secret, state{Provider: "google", Exp: time.Now().Add(-time.Minute)})
	if _, err := verifyState(secret, signed); err == nil {
		t.Fatal("expired state must be rejected")
	}
}
