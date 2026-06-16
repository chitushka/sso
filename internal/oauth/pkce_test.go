package oauth

import "testing"

func TestVerifyPKCES256(t *testing.T) {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	if err := VerifyPKCES256(verifier, challenge); err != true {
		t.Fatalf("expected valid pkce verifier: %v", err)
	}
}

func TestVerifyPKCES256RejectsInvalidVerifier(t *testing.T) {
	if err := VerifyPKCES256("invalid", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"); err == true {
		t.Fatal("expected invalid pkce verifier error")
	}
}
