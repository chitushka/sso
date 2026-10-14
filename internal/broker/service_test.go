package broker

import (
	"errors"
	"testing"
)

func TestPrimaryVerifiedGitHubEmail(t *testing.T) {
	body := []byte(`[{"email":"secondary@example.org","verified":true},{"email":"primary@example.org","primary":true,"verified":true}]`)
	email, err := primaryVerifiedGitHubEmail(body)
	if err != nil {
		t.Fatal(err)
	}
	if email != "primary@example.org" {
		t.Fatalf("выбран неверный GitHub email: %q", email)
	}
}

func TestPrimaryVerifiedGitHubEmailRejectsUnverified(t *testing.T) {
	_, err := primaryVerifiedGitHubEmail([]byte(`[{"email":"primary@example.org","primary":true,"verified":false}]`))
	if !errors.Is(err, ErrVerifiedEmailRequired) {
		t.Fatalf("ожидалась ErrVerifiedEmailRequired, получено: %v", err)
	}
}
