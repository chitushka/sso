package auth

import "testing"

func TestArgon2idHasherRoundTrip(t *testing.T) {
	hasher := NewArgon2idHasher()
	hash, err := hasher.Hash("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	ok, err := hasher.Verify("correct horse battery staple", hash)
	if err != nil || !ok {
		t.Fatalf("verify: ok=%v err=%v", ok, err)
	}
}

func TestArgon2idHasherRejectsUnsafeEncoding(t *testing.T) {
	hasher := NewArgon2idHasher()
	hashes := []string{
		"$argon2id$v=19$m=4294967295,t=3,p=2$c2FsdHNhbHQ$a2V5a2V5a2V5a2V5a2V5aw",
		"$argon2id$v=19$m=65536,t=3,p=0$c2FsdHNhbHQ$a2V5a2V5a2V5a2V5a2V5aw",
		"$argon2i$v=19$m=65536,t=3,p=2$c2FsdHNhbHQ$a2V5a2V5a2V5a2V5a2V5aw",
	}
	for _, hash := range hashes {
		if _, err := hasher.Verify("password", hash); err == nil {
			t.Fatalf("expected unsafe hash to fail: %s", hash)
		}
	}
}
