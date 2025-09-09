package akd

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"

	"filippo.io/torchwood/prefix"
	"github.com/codahale/keydonkey/internal/storage"
)

func TestRoundTrip(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}

	nodes, err := storage.NewFSNodeStore(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := nodes.Close(); err != nil {
			t.Log(err)
		}
	})
	if err := prefix.InitStorage(t.Context(), sha256.Sum256, nodes); err != nil {
		t.Fatal(err)
	}

	keys, err := storage.NewFSKeyStore(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := keys.Close(); err != nil {
			t.Log(err)
		}
	})

	signer, err := storage.NewSigner("KeyDonkey", privateKey)
	if err != nil {
		t.Fatal(err)
	}

	log, err := storage.NewFSLogStore(t.Context(), filepath.Join(dir, "logs"), signer)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := log.Shutdown(t.Context()); err != nil {
			t.Log(err)
		}
	})

	akd, err := NewDirectory(privateKey, keys, nodes, log)
	if err != nil {
		t.Fatal(err)
	}

	missing, err := akd.Lookup(t.Context(), "dingus", 1)
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

	lookupRes, err := akd.Lookup(t.Context(), "dingus", 20)
	if err != nil {
		t.Fatal(err)
	}

	if !lookupRes.Verify(akd.VerifyingKey()) {
		t.Error("did not verify")
	}
}
