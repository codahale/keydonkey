package storage

import (
	"context"

	"filippo.io/torchwood/prefix"
)

type NodeStore interface {
	prefix.Storage
}

type KeyStore interface {
	Get(ctx context.Context, id string) (found bool, pk []byte, version uint64, err error)
	Put(ctx context.Context, id string, pk []byte, version uint64) error
}

type LogStore interface {
	Add(ctx context.Context, label, commitment []byte) error
}
