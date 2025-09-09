package akd

import (
	"context"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"

	"filippo.io/torchwood/prefix"
	"github.com/codahale/keydonkey/internal/storage"
	"github.com/codahale/keydonkey/internal/vrf"
)

type Directory struct {
	pk   *vrf.ProvingKey
	ck   []byte
	keys storage.KeyStore
	log  storage.LogStore
	tree *prefix.Tree
}

func NewDirectory(privateKey ed25519.PrivateKey, keys storage.KeyStore, nodes storage.NodeStore, log storage.LogStore) (*Directory, error) {
	// Create a new prefix tree with the given storage.
	tree := prefix.NewTree(sha256.Sum256, nodes)

	// Derive a VRF proving key from the seed.
	pk := vrf.NewProvingKey(privateKey)

	// Derive an HMAC commitment key from the seed.
	ck, _ := hkdf.Expand(sha256.New, privateKey.Seed(), "keydonkey commitment key derivation", 32)

	return &Directory{
		pk:   pk,
		ck:   ck,
		keys: keys,
		log:  log,
		tree: tree,
	}, nil
}

func (d *Directory) VerifyingKey() *vrf.VerifyingKey {
	return &d.pk.VerifyingKey
}

func (d *Directory) Publish(ctx context.Context, id string, pk ed25519.PublicKey, version uint64) (*PublishResult, error) {
	var label, commitment, opening [32]byte

	// Generate a VRF proof and hash from the key ID and version.
	vrfProof, vrfHash := d.pk.Prove(vrfInput(id, version))

	// Truncate the hash to 32 bytes to use as a prefix tree label.
	copy(label[:], vrfHash[:32])

	// Derive a commitment opening via HMAC(ck, label || version || pk).
	h := hmac.New(sha256.New, d.ck)
	h.Write(label[:])
	_ = binary.Write(h, binary.BigEndian, version)
	h.Write(pk)
	h.Sum(opening[:0])

	// Derive a commitment via HMAC(opening, pk).
	h = hmac.New(sha256.New, opening[:])
	h.Write(pk)
	h.Sum(commitment[:0])

	// Insert the label and the commitment into the prefix tree. Both are opaque values which do not reveal information
	// about the key ID, the key version, or the key itself.
	if err := d.tree.Insert(ctx, label, commitment); err != nil {
		return nil, err
	}

	// Append the label and commitment to the transparency log.
	if err := d.log.Add(ctx, label[:], commitment[:]); err != nil {
		return nil, err
	}

	// Insert the key into the shared database.
	if err := d.keys.Put(ctx, id, pk, version); err != nil {
		return nil, err
	}

	// Read the current root hash of the prefix tree. This may be a later root hash than the one in which the key was
	// added, but it'll still work.
	rootHash, err := d.tree.RootHash(ctx)
	if err != nil {
		return nil, err
	}

	// Look up the newly-inserted label to generate a membership proof.
	found, membershipProof, err := d.tree.Lookup(ctx, label)
	if err != nil {
		return nil, err
	}
	if !found {
		panic("akd: could not lookup inserted label")
	}

	return &PublishResult{
		ID:              id,
		Version:         version,
		PublicKey:       pk,
		MembershipProof: membershipProof,
		RootHash:        rootHash,
		IndexProof:      vrfProof,
		IndexOpening:    opening[:],
	}, nil
}

func (d *Directory) Lookup(ctx context.Context, id string, minVersion uint64) (*LookupResult, error) {
	var label, opening [32]byte

	// Find the current root hash of the prefix tree. It's used for verifying both membership and non-membership proofs.
	rootHash, err := d.tree.RootHash(ctx)
	if err != nil {
		return nil, err
	}

	// Lookup the key from the database by ID.
	found, pk, version, err := d.keys.Get(ctx, id, minVersion)
	if err != nil {
		return nil, err
	}
	if !found {
		// Generate a VRF proof and hash from the non-existent key ID and a version of 0.
		vrfProof, vrfHash := d.pk.Prove(vrfInput(id, 0))

		// Truncate the VRF hash and use as the prefix tree label.
		copy(label[:], vrfHash[:32])

		// Look up the missing label in the prefix tree to generate a non-membership proof.
		found, membershipProof, err := d.tree.Lookup(ctx, label)
		if err != nil {
			return nil, err
		}
		if found {
			panic("akd: key found in tree but not database")
		}

		// Return all the information required to verify the non-membership proof.
		return &LookupResult{
			ID:              id,
			Version:         0,
			PublicKey:       nil,
			MembershipProof: membershipProof,
			RootHash:        rootHash,
			Found:           false,
			IndexProof:      vrfProof,
			IndexOpening:    nil,
		}, nil
	}

	// Generate a VRF proof and hash from the key ID and version.
	vrfProof, vrfHash := d.pk.Prove(vrfInput(id, version))

	// Truncate the VRF hash and use as the prefix tree label.
	copy(label[:], vrfHash[:32])

	// Lookup the label in the prefix tree and generate a membership proof.
	found, membershipProof, err := d.tree.Lookup(ctx, label)
	if err != nil {
		return nil, err
	}
	if !found {
		panic("akd: key found in database but not tree")
	}

	// Re-derive the commitment opening via HMAC(ck, label || version || pk).
	h := hmac.New(sha256.New, d.ck)
	h.Write(label[:])
	_ = binary.Write(h, binary.BigEndian, version)
	h.Write(pk)
	h.Sum(opening[:0])

	// Return the key and all information required to verify the index proof and the membership proof.
	return &LookupResult{
		ID:              id,
		Version:         version,
		PublicKey:       pk,
		MembershipProof: membershipProof,
		RootHash:        rootHash,
		Found:           true,
		IndexProof:      vrfProof,
		IndexOpening:    opening[:],
	}, nil
}

type PublishResult struct {
	ID              string
	Version         uint64
	PublicKey       ed25519.PublicKey
	MembershipProof []prefix.ProofNode
	RootHash        [32]byte
	IndexProof      []byte
	IndexOpening    []byte
}

func (r *PublishResult) Verify(vk *vrf.VerifyingKey) bool {
	var label, commitment [32]byte

	// Verify the index proof and calculate the VRF proof hash.
	vrfHash, err := vk.Verify(vrfInput(r.ID, r.Version), r.IndexProof)
	if err != nil {
		return false
	}

	// Truncate the VRF hash to use as the label.
	copy(label[:], vrfHash[:32])

	// Re-derive the index commitment for the public key using the given opening.
	h := hmac.New(sha256.New, r.IndexOpening[:])
	h.Write(r.PublicKey)
	h.Sum(commitment[:0])

	// Verify the membership proof of the commitment.
	if err := prefix.VerifyMembershipProof(sha256.Sum256, label, commitment, r.MembershipProof, r.RootHash); err != nil {
		return false
	}
	return true
}

type LookupResult struct {
	ID              string
	Version         uint64
	PublicKey       ed25519.PublicKey
	MembershipProof []prefix.ProofNode
	RootHash        [32]byte
	Found           bool
	IndexProof      []byte
	IndexOpening    []byte
}

func (r *LookupResult) Verify(vk *vrf.VerifyingKey) bool {
	var label, commitment [32]byte

	// Verify the index proof and calculate the VRF proof hash.
	vrfHash, err := vk.Verify(vrfInput(r.ID, r.Version), r.IndexProof)
	if err != nil {
		return false
	}

	// Truncate the VRF hash to use as the label.
	copy(label[:], vrfHash[:32])

	if !r.Found {
		// If the key was not found, verify the non-membership proof.
		if err := prefix.VerifyNonMembershipProof(sha256.Sum256, label, r.MembershipProof, r.RootHash); err != nil {
			return false
		}
		return true
	}

	// Re-derive the index commitment for the public key using the given opening.
	h := hmac.New(sha256.New, r.IndexOpening[:])
	h.Write(r.PublicKey)
	h.Sum(commitment[:0])

	// Verify the membership proof of the commitment.
	if err := prefix.VerifyMembershipProof(sha256.Sum256, label, commitment, r.MembershipProof, r.RootHash); err != nil {
		return false
	}
	return true
}

func vrfInput(id string, version uint64) ed25519.PublicKey {
	input := make([]byte, len(id)+8)
	copy(input, id)
	binary.LittleEndian.PutUint64(input[len(id):], version)
	return input
}
