package storage

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"slices"
	"time"

	"github.com/transparency-dev/tessera"
	"github.com/transparency-dev/tessera/storage/posix"
	"golang.org/x/mod/sumdb/note"
)

type FSLogStore struct {
	appender *tessera.Appender
	shutdown func(context.Context) error
	Reader   tessera.LogReader
}

func NewFSLogStore(ctx context.Context, path string, signer note.Signer) (*FSLogStore, error) {
	driver, err := posix.New(ctx, posix.Config{Path: path})
	if err != nil {
		return nil, err
	}

	appender, shutdown, r, err := tessera.NewAppender(ctx, driver, tessera.NewAppendOptions().
		WithCheckpointSigner(signer).
		WithCheckpointInterval(100*time.Millisecond).
		WithBatching(10, time.Second))
	if err != nil {
		return nil, err
	}

	return &FSLogStore{
		appender: appender,
		shutdown: shutdown,
		Reader:   r,
	}, nil
}

func (s *FSLogStore) Add(ctx context.Context, label, commitment []byte) error {
	_, err := s.appender.Add(ctx, tessera.NewEntry(slices.Concat(label, commitment)))()
	return err
}

func (s *FSLogStore) Shutdown(ctx context.Context) error {
	return s.shutdown(ctx)
}

func NewSigner(name string, privateKey ed25519.PrivateKey) (note.Signer, error) {
	keyHash := func(name string, key []byte) uint32 {
		h := sha256.New()
		h.Write([]byte(name))
		h.Write([]byte("\n"))
		h.Write(key)
		sum := h.Sum(nil)
		return binary.BigEndian.Uint32(sum)
	}

	pubkey := append([]byte{1}, privateKey.Public().(ed25519.PublicKey)...)
	privkey := append([]byte{1}, privateKey.Seed()...)
	h := keyHash(name, pubkey)
	skey := fmt.Sprintf("PRIVATE+KEY+%s+%08x+%s", name, h, base64.StdEncoding.EncodeToString(privkey))
	signer, err := note.NewSigner(skey)
	if err != nil {
		return nil, err
	}
	return signer, nil
}

var _ LogStore = (*FSLogStore)(nil)
