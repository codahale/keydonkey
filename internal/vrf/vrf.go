// Package vrf provides an implementation of RFC9381 ECVRF-EDWARDS25519-SHA512-TAI.
//
// https://www.ietf.org/rfc/rfc9381.html
package vrf

import (
	"crypto/ed25519"
	"crypto/sha512"
	"encoding"
	"errors"

	"filippo.io/edwards25519"
)

// ErrInvalidProof is returned when a proof is invalid.
var ErrInvalidProof = errors.New("vrf: invalid proof")

type PublicKey struct {
	y   *edwards25519.Point
	pub []byte
}

func NewPublicKey(b []byte) (*PublicKey, error) {
	q, err := new(edwards25519.Point).SetBytes(b)
	if err != nil {
		return nil, err
	}
	return &PublicKey{y: q, pub: b}, nil
}

func (pk *PublicKey) Verify(alpha, proof []byte) (hash []byte, err error) {
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

	h := encodeToCurve(pk.pub, alpha)
	u := new(edwards25519.Point).ScalarBaseMult(s)
	u.Subtract(u, new(edwards25519.Point).ScalarMult(c, pk.y))
	v := new(edwards25519.Point).ScalarMult(s, h)
	v.Subtract(v, new(edwards25519.Point).ScalarMult(c, gamma))

	cP := generateChallenge(pk.y, h, gamma, u, v)
	if c.Equal(cP) == 1 {
		return hashProof(gamma), nil
	}

	return nil, ErrInvalidProof
}

func (pk *PublicKey) MarshalBinary() (data []byte, err error) {
	return pk.pub, nil
}

func (pk *PublicKey) UnmarshalBinary(data []byte) (err error) {
	x, err := NewPublicKey(data)
	if err != nil {
		return err
	}

	*pk = *x
	return nil
}

var (
	_ encoding.BinaryMarshaler   = &PublicKey{}
	_ encoding.BinaryUnmarshaler = &PublicKey{}
)

type SecretKey struct {
	x         *edwards25519.Scalar
	prefix    []byte
	PublicKey PublicKey
}

func NewSecretKey(seed []byte) *SecretKey {
	hs := sha512.New()
	hs.Write(seed)
	h := hs.Sum(nil)

	x, err := edwards25519.NewScalar().SetBytesWithClamping(h[:32])
	if err != nil {
		panic("vrf: internal error: setting scalar failed")
	}

	q := new(edwards25519.Point).ScalarBaseMult(x)
	return &SecretKey{
		x:      x,
		prefix: h[32:],
		PublicKey: PublicKey{
			y:   q,
			pub: q.Bytes(),
		},
	}
}

func (sk *SecretKey) Prove(alpha []byte) (proof, hash []byte) {
	h := encodeToCurve(sk.PublicKey.pub, alpha)
	gamma := new(edwards25519.Point).ScalarMult(sk.x, h)
	k := generateNonce(sk.prefix, h.Bytes())
	c := generateChallenge(sk.PublicKey.y, h, gamma, new(edwards25519.Point).ScalarBaseMult(k), new(edwards25519.Point).ScalarMult(k, h))
	s := new(edwards25519.Scalar).MultiplyAdd(c, sk.x, k)
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
	var q edwards25519.Point

	for ctr := byte(0); ctr < 255; ctr++ {
		hs := sha512.New()
		hs.Write([]byte{suite, encodeDomainSeparatorFront})
		hs.Write(salt)
		hs.Write(alpha)
		hs.Write([]byte{ctr, encodeDomainSeparatorBack})
		if _, err := q.SetBytes(hs.Sum(nil)[:ed25519.SeedSize]); err == nil {
			q.MultByCofactor(&q)
			return &q
		}
	}

	panic("vrf: unable to encode to curve")
}

const (
	suite                         = 0x03
	encodeDomainSeparatorFront    = 0x01
	encodeDomainSeparatorBack     = 0x00
	challengeDomainSeparatorFront = 0x02
	challengeDomainSeparatorBack  = 0x00
	proofDomainSeparatorFront     = 0x03
	proofDomainSeparatorBack      = 0x00
)
