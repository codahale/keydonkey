package storagetest

import (
	"context"
	"crypto/sha256"
	"testing"

	"filippo.io/torchwood/prefix"
	"github.com/codahale/keydonkey/internal/storage"
)

type MemoryStore struct {
	Nodes      prefix.Storage
	Keys       map[string]Key
	LogEntries []LogEntry
}

type Key struct {
	ID        string
	Version   uint64
	PublicKey []byte
}

type LogEntry struct {
	Label, Commitment []byte
}

func NewMemoryStore(t *testing.T) *MemoryStore {
	t.Helper()
	nodes := prefix.NewMemoryStorage()
	if err := prefix.InitStorage(t.Context(), sha256.Sum256, nodes); err != nil {
		t.Fatal(err)
	}
	return &MemoryStore{
		Keys:  make(map[string]Key),
		Nodes: nodes,
	}
}

func (i *MemoryStore) Load(ctx context.Context, label prefix.Label) (*prefix.Node, error) {
	return i.Nodes.Load(ctx, label)
}

func (i *MemoryStore) Store(ctx context.Context, nodes ...*prefix.Node) error {
	return i.Nodes.Store(ctx, nodes...)
}

func (i *MemoryStore) Put(_ context.Context, id string, pk []byte, version uint64) error {
	i.Keys[id] = Key{
		ID:        id,
		Version:   version,
		PublicKey: pk,
	}
	return nil
}

func (i *MemoryStore) Get(_ context.Context, id string) (found bool, pk []byte, version uint64, err error) {
	key, ok := i.Keys[id]
	if !ok {
		return false, nil, 0, nil
	}
	return true, key.PublicKey, key.Version, nil
}

func (i *MemoryStore) Add(_ context.Context, label, commitment []byte) error {
	i.LogEntries = append(i.LogEntries, LogEntry{
		Label:      label,
		Commitment: commitment,
	})
	return nil
}

var (
	_ storage.NodeStore = (*MemoryStore)(nil)
	_ storage.KeyStore  = (*MemoryStore)(nil)
	_ storage.LogStore  = (*MemoryStore)(nil)
)
