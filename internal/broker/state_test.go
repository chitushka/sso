package broker

import (
	"bytes"
	"testing"
)

func TestLoginStateIsRandomAndHashed(t *testing.T) {
	first, firstHash, err := newLoginState()
	if err != nil {
		t.Fatal(err)
	}
	second, secondHash, err := newLoginState()
	if err != nil {
		t.Fatal(err)
	}
	if first == second || bytes.Equal(firstHash, secondHash) {
		t.Fatal("broker state должен быть уникальным")
	}
	if len(firstHash) != 32 || !bytes.Equal(firstHash, hashLoginState(first)) {
		t.Fatal("broker state должен храниться как SHA-256")
	}
}
