package storage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

type FSKeyStore struct {
	root *os.Root
}

func NewFSKeyStore(root *os.Root) (*FSKeyStore, error) {
	if err := root.Mkdir("keys", 0777); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, err
	}

	root, err := root.OpenRoot("keys")
	if err != nil {
		return nil, err
	}

	return &FSKeyStore{root: root}, nil
}

func (s *FSKeyStore) Get(_ context.Context, id string, minVersion uint64) (found bool, pk []byte, version uint64, err error) {
	_, glob, filename := keyPathGlobAndFilename(id, minVersion)

	matches, err := fs.Glob(s.root.FS(), glob)
	if err != nil {
		return false, nil, 0, err
	}
	for i := len(matches) - 1; i >= 0; i-- {
		if matches[i] > filename {
			filename = matches[i]
			break
		}
	}

	b, err := s.root.ReadFile(filename)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil, 0, nil
		}
		return false, nil, 0, err
	}

	var key keyData
	if err := json.Unmarshal(b, &key); err != nil {
		return false, nil, 0, err
	}

	return true, key.PK, key.Version, nil
}

func (s *FSKeyStore) Put(_ context.Context, id string, pk []byte, version uint64) error {
	b, err := json.Marshal(&keyData{ID: id, PK: pk, Version: version})
	if err != nil {
		return err
	}

	path, _, filename := keyPathGlobAndFilename(id, version)
	if path != "" {
		if err := s.root.MkdirAll(path, 0777); err != nil {
			return err
		}
	}

	if err := s.root.WriteFile(filename, b, 0666); err != nil {
		return err
	}

	return nil
}

func (s *FSKeyStore) Close() error {
	return s.root.Close()
}

type keyData struct {
	ID      string
	PK      []byte
	Version uint64
}

func keyPathGlobAndFilename(id string, version uint64) (path, glob, filename string) {
	hash := sha256.Sum256([]byte(id))
	hexLabel := hex.EncodeToString(hash[:])
	path = filepath.Join(hexLabel[:2], hexLabel[2:4])
	glob = filepath.Join(hexLabel[:2], hexLabel[2:4], fmt.Sprintf("%s-*.json", hexLabel))
	filename = filepath.Join(hexLabel[:2], hexLabel[2:4], fmt.Sprintf("%s-%016x.json", hexLabel, version))
	return path, glob, filename
}

var _ KeyStore = (*FSKeyStore)(nil)
