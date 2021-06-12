package pwnedpass

import (
	"crypto/rand"
	"testing"
)

func TestCompromised(t *testing.T) {
	matches, err := Compromised([]byte("12345678"))
	if err != nil {
		t.Fatal(err)
	}

	if matches <= 0 {
		t.Fatal("invalid match")
	}

	randomPass := make([]byte, 32)
	rand.Read(randomPass)

	matches, err = Compromised(randomPass)
	if err != nil {
		t.Fatal(err)
	}

	if matches > 0 {
		t.Fatal("invalid match")
	}
}

func TestIsCompromised(t *testing.T) {
	matched, err := IsCompromised([]byte("planetearth"))
	if err != nil {
		t.Fatal(err)
	}

	if !matched {
		t.Fatal("invalid match")
	}

	randomPass := make([]byte, 16)
	rand.Read(randomPass)

	matched, err = IsCompromised(randomPass)
	if err != nil {
		t.Fatal(err)
	}

	if matched {
		t.Fatal("invalid match")
	}
}
