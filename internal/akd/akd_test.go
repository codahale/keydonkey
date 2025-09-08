package akd

import (
	"context"
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

	store := newInMemoryStore(t)
	akd, err := NewDirectory(store, privateKey)
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

type inMemoryStore struct {
	Nodes      prefix.Storage
	Keys       map[string][]byte
	LogEntries [][]byte
}

func newInMemoryStore(t *testing.T) *inMemoryStore {
	t.Helper()
	nodes := prefix.NewMemoryStorage()
	if err := prefix.InitStorage(t.Context(), sha256.Sum256, nodes); err != nil {
		t.Fatal(err)
	}
	return &inMemoryStore{
		Keys:  make(map[string][]byte),
		Nodes: nodes,
	}
}

func (i *inMemoryStore) Load(ctx context.Context, label prefix.Label) (*prefix.Node, error) {
	return i.Nodes.Load(ctx, label)
}

func (i *inMemoryStore) Store(ctx context.Context, nodes ...*prefix.Node) error {
	return i.Nodes.Store(ctx, nodes...)
}

func (i *inMemoryStore) PutKey(_ context.Context, key, value []byte) error {
	i.Keys[string(key)] = value
	return nil
}

func (i *inMemoryStore) GetKey(_ context.Context, key []byte) (value []byte, found bool, err error) {
	key, ok := i.Keys[string(key)]
	return key, ok, nil
}

func (i *inMemoryStore) Log(_ context.Context, data []byte) error {
	i.LogEntries = append(i.LogEntries, data)
	return nil
}

var _ Store = (*inMemoryStore)(nil)
