package s3

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path"
	"path/filepath"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/codahale/keydonkey/internal/storage"
)

type KeyStore struct {
	bucket string
	client *s3.Client
}

func NewKeyStore(bucket string, client *s3.Client) *KeyStore {
	return &KeyStore{bucket: bucket, client: client}
}

func (s *KeyStore) Get(ctx context.Context, id string, minVersion uint64) (found bool, pk []byte, version uint64, err error) {
	glob, filename := keyGlobAndFilename(id, version)

	getResp, err := s.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(filename),
	})
	if err != nil {
		if strings.Contains(err.Error(), "NoSuchKey") {
			listResp, err := s.client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
				Bucket: aws.String(s.bucket),
				Prefix: aws.String(glob),
			})
			if err != nil {
				return false, nil, 0, err
			}

			for i := len(listResp.Contents) - 1; i >= 0; i-- {
				if *listResp.Contents[i].Key > filename {
					getResp, err = s.client.GetObject(ctx, &s3.GetObjectInput{
						Bucket: aws.String(s.bucket),
						Key:    listResp.Contents[i].Key,
					})
					if err != nil {
						return false, nil, 0, err
					}
					goto Decode
				}
			}

			return false, nil, 0, nil
		}
		return false, nil, 0, err
	}

Decode:
	var key keyData
	if err := json.NewDecoder(getResp.Body).Decode(&key); err != nil {
		return false, nil, 0, err
	}

	return true, key.PK, key.Version, nil
}

func (s *KeyStore) Put(ctx context.Context, id string, pk []byte, version uint64) error {
	b, err := json.Marshal(&keyData{ID: id, PK: pk, Version: version})
	if err != nil {
		return err
	}

	_, filename := keyGlobAndFilename(id, version)
	_, err = s.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(filename),
		Body:   bytes.NewReader(b),
	})

	return err
}

type keyData struct {
	ID      string
	PK      []byte
	Version uint64
}

func keyGlobAndFilename(id string, version uint64) (glob, filename string) {
	hash := sha256.Sum256([]byte(id))
	hexLabel := hex.EncodeToString(hash[:])
	glob = path.Join(hexLabel[:2], hexLabel[2:4], hexLabel)
	filename = filepath.Join(hexLabel[:2], hexLabel[2:4], hexLabel, fmt.Sprintf("%s-%016x.json", hexLabel, version))
	return glob, filename
}

var _ storage.KeyStore = (*KeyStore)(nil)
