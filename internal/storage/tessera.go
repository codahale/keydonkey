package storage

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"slices"

	"github.com/transparency-dev/tessera"
	"golang.org/x/mod/sumdb/note"
)

type tesseraLog struct {
	appender *tessera.Appender
}

func NewTesseraLog(appender *tessera.Appender) LogStore {
	return &tesseraLog{
		appender: appender,
	}
}

func (l *tesseraLog) Add(ctx context.Context, label, commitment []byte) error {
	_, err := l.appender.Add(ctx, tessera.NewEntry(slices.Concat(label, commitment)))()
	return err
}

var _ LogStore = (*tesseraLog)(nil)

func NewSigner(name string, privateKey ed25519.PrivateKey) (note.Signer, error) {
	h := keyHash(name, append([]byte{1}, privateKey.Public().(ed25519.PublicKey)...))
	signer, err := note.NewSigner(fmt.Sprintf("PRIVATE+KEY+%s+%08x+%s",
		name, h, base64.StdEncoding.EncodeToString(append([]byte{1}, privateKey.Seed()...)),
	))
	if err != nil {
		return nil, err
	}
	return signer, nil
}

func keyHash(name string, key []byte) uint32 {
	h := sha256.New()
	h.Write([]byte(name))
	h.Write([]byte("\n"))
	h.Write(key)
	sum := h.Sum(nil)
	return binary.BigEndian.Uint32(sum)
}
