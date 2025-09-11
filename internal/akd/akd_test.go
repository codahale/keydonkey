package akd

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"
	"time"

	"filippo.io/torchwood/prefix"
	"github.com/codahale/keydonkey/internal/storage"
	"github.com/transparency-dev/tessera"
	"github.com/transparency-dev/tessera/storage/posix"
)

func TestRoundTrip(t *testing.T) {
	pubKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
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

	driver, err := posix.New(t.Context(), posix.Config{Path: filepath.Join(dir, "log")})
	if err != nil {
		t.Fatal(err)
	}

	appender, shutdown, reader, err := tessera.NewAppender(t.Context(), driver, tessera.NewAppendOptions().
		WithCheckpointSigner(signer).
		WithCheckpointInterval(100*time.Millisecond).
		WithBatching(10, time.Second))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := shutdown(t.Context()); err != nil {
			t.Log(err)
		}
	})

	log := storage.NewTesseraLog(appender)

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

	entries, err := reader.NextIndex(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if got, want := entries, uint64(0); got != want {
		t.Errorf("entries = %v, want %v", got, want)
	}

	publishRes, err := akd.Publish(t.Context(), "dingus", pubKey, 22)
	if err != nil {
		t.Fatal(err)
	}

	if !publishRes.Verify(akd.VerifyingKey()) {
		t.Error("did not verify")
	}

	entries, err = reader.NextIndex(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if got, want := entries, uint64(1); got != want {
		t.Errorf("entries = %v, want %v", got, want)
	}

	lookupRes, err := akd.Lookup(t.Context(), "dingus", 20)
	if err != nil {
		t.Fatal(err)
	}

	if !lookupRes.Verify(akd.VerifyingKey()) {
		t.Error("did not verify")
	}
}
