package storage

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"filippo.io/torchwood/prefix"
)

type FSNodeStore struct {
	root *os.Root
}

func NewFSNodeStore(root *os.Root) (*FSNodeStore, error) {
	if err := root.Mkdir("nodes", 0777); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, err
	}

	root, err := root.OpenRoot("nodes")
	if err != nil {
		return nil, err
	}
	return &FSNodeStore{root: root}, nil
}

func (s *FSNodeStore) Load(_ context.Context, label prefix.Label) (*prefix.Node, error) {
	_, filename := nodePathAndFilename(label)

	b, err := s.root.ReadFile(filename)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, prefix.ErrNodeNotFound
		}
		return nil, err
	}

	return bytesToNode(b)
}

func (s *FSNodeStore) Store(_ context.Context, nodes ...*prefix.Node) error {
	for _, node := range nodes {
		b := nodeToBytes(node)

		path, filename := nodePathAndFilename(node.Label)

		if path != "" {
			if err := s.root.MkdirAll(path, 0777); err != nil {
				return err
			}
		}

		if err := s.root.WriteFile(filename, b, 0666); err != nil {
			return err
		}
	}

	return nil
}

func (s *FSNodeStore) Close() error {
	return s.root.Close()
}

func nodePathAndFilename(label prefix.Label) (path, filename string) {
	switch label {
	case prefix.EmptyNodeLabel:
		return "", "empty.json"
	case prefix.RootLabel:
		return "", "root.json"
	default:
		hexLabel := hex.EncodeToString(label.Bytes())
		path = filepath.Join(hexLabel[:2], hexLabel[2:4])
		filename = filepath.Join(hexLabel[:2], hexLabel[2:4], hexLabel+".json")
		return path, filename
	}
}

func nodeToBytes(node *prefix.Node) []byte {
	data := nodeData{
		LabelBitLen: node.Label.BitLen(),
		LabelBytes:  node.Label.Bytes(),
		LeftBitLen:  node.Left.BitLen(),
		LeftBytes:   node.Left.Bytes(),
		RightBitLen: node.Right.BitLen(),
		RightBytes:  node.Right.Bytes(),
		Hash:        node.Hash,
	}
	b, err := json.Marshal(data)
	if err != nil {
		panic(err)
	}
	return b
}

func bytesToNode(b []byte) (*prefix.Node, error) {
	var data nodeData
	if err := json.Unmarshal(b, &data); err != nil {
		return nil, err
	}

	label, err := prefix.NewLabel(data.LabelBitLen, data.LabelBytes)
	if err != nil {
		return nil, err
	}

	left, err := prefix.NewLabel(data.LeftBitLen, data.LeftBytes)
	if err != nil {
		return nil, err
	}

	right, err := prefix.NewLabel(data.RightBitLen, data.RightBytes)
	if err != nil {
		return nil, err
	}

	return &prefix.Node{
		Label: label,
		Left:  left,
		Right: right,
		Hash:  data.Hash,
	}, nil
}

type nodeData struct {
	LabelBitLen uint32
	LabelBytes  []byte
	LeftBitLen  uint32
	LeftBytes   []byte
	RightBitLen uint32
	RightBytes  []byte
	Hash        [32]byte
}

var _ NodeStore = (*FSNodeStore)(nil)
