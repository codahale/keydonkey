package akd

import (
	"context"

	"filippo.io/torchwood/prefix"
)

type Store interface {
	prefix.Storage
	PutKey(ctx context.Context, key, value []byte) error
	GetKey(ctx context.Context, key []byte) (value []byte, found bool, err error)
	Log(ctx context.Context, data []byte) error
}
