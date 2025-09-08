// Package vrf provides an implementation of RFC 9381's ECVRF-EDWARDS25519-SHA512-ELL2.
package vrf

import (
	"crypto/ed25519"
	"crypto/sha512"
	"encoding"
	"errors"

	"filippo.io/edwards25519"
	h2c "github.com/bytemare/hash2curve/edwards25519"
)

// ErrInvalidProof is returned when a proof is invalid.
var ErrInvalidProof = errors.New("vrf: invalid proof")

// VerifyingKey is a public key which is used to verify proofs created by the corresponding ProvingKey.
type VerifyingKey struct {
	y       *edwards25519.Point
	encoded []byte
}

// NewVerifyingKey deserializes the given byte slice into a VerifyingKey. Returns an error if the byte slice is not a
// valid Ed25519 point.
func NewVerifyingKey(publicKey ed25519.PublicKey) (*VerifyingKey, error) {
	q, err := new(edwards25519.Point).SetBytes(publicKey)
	if err != nil {
		return nil, err
	}
	return &VerifyingKey{y: q, encoded: publicKey}, nil
}

// Verify the given input and proof. Returns a hash of the proof if valid, ErrInvalidProof if invalid.
func (vk *VerifyingKey) Verify(alpha, proof []byte) (hash []byte, err error) {
	gamma, err := new(edwards25519.Point).SetBytes(proof[:32])
	if err != nil {
		return nil, ErrInvalidProof
	}

	var buf [32]byte
	copy(buf[:], proof[32:48])
	c, err := new(edwards25519.Scalar).SetCanonicalBytes(buf[:])
	if err != nil {
		return nil, ErrInvalidProof
	}

	s, err := new(edwards25519.Scalar).SetCanonicalBytes(proof[48:])
	if err != nil {
		return nil, ErrInvalidProof
	}

	h := encodeToCurve(vk.encoded, alpha)
	u := new(edwards25519.Point).ScalarBaseMult(s)
	u.Subtract(u, new(edwards25519.Point).ScalarMult(c, vk.y))
	v := new(edwards25519.Point).ScalarMult(s, h)
	v.Subtract(v, new(edwards25519.Point).ScalarMult(c, gamma))

	cP := generateChallenge(vk.y, h, gamma, u, v)
	if c.Equal(cP) == 1 {
		return hashProof(gamma), nil
	}

	return nil, ErrInvalidProof
}

func (vk *VerifyingKey) MarshalBinary() (data []byte, err error) {
	return vk.encoded, nil
}

func (vk *VerifyingKey) UnmarshalBinary(data []byte) (err error) {
	x, err := NewVerifyingKey(data)
	if err != nil {
		return err
	}

	*vk = *x
	return nil
}

var (
	_ encoding.BinaryMarshaler   = &VerifyingKey{}
	_ encoding.BinaryUnmarshaler = &VerifyingKey{}
)

// ProvingKey is a secret key which is used to create proofs which can be verified by the corresponding VerifyingKey.
type ProvingKey struct {
	x      *edwards25519.Scalar
	prefix []byte

	// VerifyingKey contains the VerifyingKey which corresponds to this ProvingKey.
	VerifyingKey VerifyingKey
}

// NewProvingKey derives a ProvingKey and VerifyingKey pair from the given seed value. It will panic if len(seed) is not
// ed25519.SeedSize.
func NewProvingKey(key ed25519.PrivateKey) *ProvingKey {
	hs := sha512.New()
	hs.Write(key.Seed())
	h := hs.Sum(nil)

	x, err := edwards25519.NewScalar().SetBytesWithClamping(h[:32])
	if err != nil {
		panic("vrf: internal error: setting scalar failed")
	}

	q := new(edwards25519.Point).ScalarBaseMult(x)
	return &ProvingKey{
		x:      x,
		prefix: h[32:],
		VerifyingKey: VerifyingKey{
			y:       q,
			encoded: key.Public().(ed25519.PublicKey),
		},
	}
}

// Prove returns a deterministic proof of the given byte slice and a hash of the proof. The proof can be verified but
// offers no privacy guarantees with regard to the input; the hash cannot be verified but offers full privacy with
// regard to the input.
func (pk *ProvingKey) Prove(alpha []byte) (proof, hash []byte) {
	h := encodeToCurve(pk.VerifyingKey.encoded, alpha)
	gamma := new(edwards25519.Point).ScalarMult(pk.x, h)
	k := generateNonce(pk.prefix, h.Bytes())
	c := generateChallenge(pk.VerifyingKey.y, h, gamma, new(edwards25519.Point).ScalarBaseMult(k), new(edwards25519.Point).ScalarMult(k, h))
	s := new(edwards25519.Scalar).MultiplyAdd(c, pk.x, k)
	pi := gamma.Bytes()
	pi = append(pi, c.Bytes()[:16]...)
	pi = append(pi, s.Bytes()...)
	return pi, hashProof(gamma)
}

func hashProof(gamma *edwards25519.Point) []byte {
	h := sha512.New()
	h.Write([]byte{suite, proofDomainSeparatorFront})
	h.Write(new(edwards25519.Point).MultByCofactor(gamma).Bytes())
	h.Write([]byte{proofDomainSeparatorBack})
	return h.Sum(nil)
}

func generateChallenge(p1, p2, p3, p4, p5 *edwards25519.Point) *edwards25519.Scalar {
	h := sha512.New()
	h.Write([]byte{suite, challengeDomainSeparatorFront})
	h.Write(p1.Bytes())
	h.Write(p2.Bytes())
	h.Write(p3.Bytes())
	h.Write(p4.Bytes())
	h.Write(p5.Bytes())
	h.Write([]byte{challengeDomainSeparatorBack})

	cStr := append(h.Sum(nil)[:16], make([]byte, 16)...)
	c, err := new(edwards25519.Scalar).SetCanonicalBytes(cStr)
	if err != nil {
		panic(err)
	}
	return c
}

func generateNonce(prefix, hash []byte) *edwards25519.Scalar {
	h := sha512.New()
	h.Write(prefix)
	h.Write(hash)
	k, err := new(edwards25519.Scalar).SetUniformBytes(h.Sum(nil))
	if err != nil {
		panic(err)
	}
	return k
}

func encodeToCurve(salt, alpha []byte) *edwards25519.Point {
	input := append(salt, alpha...)
	return h2c.EncodeToCurve(input, []byte("ECVRF_edwards25519_XMD:SHA-512_ELL2_NU_\004"))
}

const (
	suite                         = 0x04
	challengeDomainSeparatorFront = 0x02
	challengeDomainSeparatorBack  = 0x00
	proofDomainSeparatorFront     = 0x03
	proofDomainSeparatorBack      = 0x00
)
