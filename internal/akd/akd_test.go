package akd

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/codahale/keydonkey/internal/storage/storagetest"
)

func TestRoundTrip(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	store := storagetest.NewMemoryStore(t)
	akd, err := NewDirectory(privateKey, store, store, store)
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

	if got, want := len(store.LogEntries), 1; got != want {
		t.Errorf("got %d entries, want %d", got, want)
	}
}
