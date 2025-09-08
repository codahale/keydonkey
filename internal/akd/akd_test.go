package akd

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"filippo.io/torchwood/prefix"
	"github.com/transparency-dev/tessera"
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

	var entries []*tessera.Entry
	appender := tessera.Appender{Add: func(ctx context.Context, entry *tessera.Entry) tessera.IndexFuture {
		return func() (tessera.Index, error) {
			entries = append(entries, entry)
			return tessera.Index{
				Index: 1,
				IsDup: false,
			}, nil
		}
	}}

	akd, err := NewDirectory(storage, privateKey, &appender)
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

	if got, want := len(entries), 1; got != want {
		t.Errorf("got %d entries, want %d", got, want)
	}
}
