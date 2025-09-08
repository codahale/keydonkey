package akd

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"filippo.io/torchwood/prefix"
)

func TestRoundTrip(t *testing.T) {
	storage := prefix.NewMemoryStorage()
	if err := prefix.InitStorage(t.Context(), sha256.Sum256, storage); err != nil {
		t.Fatal(err)
	}

	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	akd, err := NewDirectory(storage, privateKey)
	if err != nil {
		t.Fatal(err)
	}

	missing, err := akd.Lookup(t.Context(), "dingus")
	if err != nil {
		t.Fatal(err)
	}

	if !missing.Verify(akd.VerifyingKey()) {
		t.Error("did not verify")
	}

	publishRes, err := akd.Publish(t.Context(), "dingus", make(ed25519.PublicKey, 32), 22)
	if err != nil {
		t.Fatal(err)
	}

	if !publishRes.Verify(akd.VerifyingKey()) {
		t.Error("did not verify")
	}

	lookupRes, err := akd.Lookup(t.Context(), "dingus")
	if err != nil {
		t.Fatal(err)
	}

	if !lookupRes.Verify(akd.VerifyingKey()) {
		t.Error("did not verify")
	}
}
