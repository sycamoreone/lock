package minilock

import (
	"github.com/sycamoreone/base58"
	"testing"
)

func TestID(t *testing.T) {
	idBase58 := "radFxzH6yDYDyHiaZpvUr8UhqbpEzjQdfSF3XeZi9Py72"
	idBytes, err := base58.Decode(idBase58)
	if err != nil {
		t.Fatal(err)
	}
	if len(idBytes) != 33 {
		t.Logf("minilock ID should have 33 bytes, but has %d\n", len(idBytes))
		t.Fail()
	}

	publicKey := new([32]byte)
	copy(publicKey[:], idBytes[:32])

	id := ID(publicKey)
	if id != idBase58 {
		t.Fatalf("wrong ID: expected %s but got %s\n", idBase58, id)
	}
}

func TestDeriveKeys1(t *testing.T) {
	// passphrase and expectedID were generated with the minilock plugin for Chrome.
	mailaddr := []byte("mustermann@example.com")
	passphrase := []byte("enumeration snapped unwarily distempers lovemaking taciturn sociological")
	expectedID := "radFxzH6yDYDyHiaZpvUr8UhqbpEzjQdfSF3XeZi9Py72"
	pk, _, _ := DeriveKeys(passphrase, mailaddr)
	gotID := ID(pk)
	if gotID != expectedID {
		t.Fatalf("expected minilock ID %s, but got %s\n", expectedID, string(gotID))
	}
}
