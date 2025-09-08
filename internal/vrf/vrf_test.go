package vrf

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"testing"
)

func TestExamples(t *testing.T) {
	for _, tv := range testVectors {
		t.Run(tv.Name, func(t *testing.T) {
			privateKey := ed25519.NewKeyFromSeed(tv.SK)

			sk := NewProvingKey(privateKey)
			if got, want := sk.VerifyingKey.encoded, tv.PK; !bytes.Equal(got, want) {
				t.Errorf("NewProvingKey(%x) = %x, want = %x", tv.SK, got, want)
			}

			pk, err := NewVerifyingKey(tv.PK)
			if err != nil {
				t.Fatal(err)
			}

			pi, beta := sk.Prove(tv.Alpha)
			if !bytes.Equal(pi, tv.Pi) || !bytes.Equal(beta, tv.Beta) {
				t.Errorf("Prove(%x) = (%x, %x), want = (%x, %x)", tv.Alpha, pi, beta, tv.Pi, tv.Beta)
			}

			beta, err = pk.Verify(tv.Alpha, pi)
			if err != nil || !bytes.Equal(beta, tv.Beta) {
				t.Errorf("Verify(%x, %x) = %x, %v, want = %x", tv.Alpha, pi, beta, err, tv.Beta)
			}

			beta, err = pk.Verify([]byte("something else"), pi)
			if !errors.Is(err, ErrInvalidProof) {
				t.Errorf("Verify(\"something else\", %x) = %x, %v, want ErrInvalidProof", pi, beta, err)
			}

			pi[0] ^= 1
			beta, err = pk.Verify(tv.Alpha, pi)
			if !errors.Is(err, ErrInvalidProof) {
				t.Errorf("Verify(%x, %x) = %x, %v, want ErrInvalidProof", tv.Alpha, pi, beta, err)
			}
		})
	}
}

func TestEncodeToCurve(t *testing.T) {
	for _, tv := range testVectors {
		t.Run(tv.Name, func(t *testing.T) {
			if got, want := encodeToCurve(tv.PK, tv.Alpha).Bytes(), tv.H; !bytes.Equal(got, want) {
				t.Errorf("encodeToCurve(%x, %x) = %x, want %x", tv.PK, tv.Alpha, got, want)
			}

		})
	}
}

// https://www.ietf.org/rfc/rfc9381.html#name-ecvrf-edwards25519-sha512-t
var testVectors = []struct {
	Name             string
	SK, PK, Alpha, X []byte
	H, Pi, Beta      []byte
}{
	{
		Name:  "Example 19",
		SK:    mustHexDecodeString("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"),
		PK:    mustHexDecodeString("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"),
		Alpha: nil,
		X:     mustHexDecodeString("307c83864f2833cb427a2ef1c00a013cfdff2768d980c0a3a520f006904de94f"),
		H:     mustHexDecodeString("b8066ebbb706c72b64390324e4a3276f129569eab100c26b9f05011200c1bad9"),
		Pi:    mustHexDecodeString("7d9c633ffeee27349264cf5c667579fc583b4bda63ab71d001f89c10003ab46f14adf9a3cd8b8412d9038531e865c341cafa73589b023d14311c331a9ad15ff2fb37831e00f0acaa6d73bc9997b06501"),
		Beta:  mustHexDecodeString("9d574bf9b8302ec0fc1e21c3ec5368269527b87b462ce36dab2d14ccf80c53cccf6758f058c5b1c856b116388152bbe509ee3b9ecfe63d93c3b4346c1fbc6c54"),
	},
	{
		Name:  "Example 20",
		SK:    mustHexDecodeString("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"),
		PK:    mustHexDecodeString("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"),
		Alpha: mustHexDecodeString("72"),
		X:     mustHexDecodeString("68bd9ed75882d52815a97585caf4790a7f6c6b3b7f821c5e259a24b02e502e51"),
		H:     mustHexDecodeString("76ac3ccb86158a9104dff819b1ca293426d305fd76b39b13c9356d9b58c08e57"),
		Pi:    mustHexDecodeString("47b327393ff2dd81336f8a2ef10339112401253b3c714eeda879f12c509072ef055b48372bb82efbdce8e10c8cb9a2f9d60e93908f93df1623ad78a86a028d6bc064dbfc75a6a57379ef855dc6733801"),
		Beta:  mustHexDecodeString("38561d6b77b71d30eb97a062168ae12b667ce5c28caccdf76bc88e093e4635987cd96814ce55b4689b3dd2947f80e59aac7b7675f8083865b46c89b2ce9cc735"),
	},

	{
		Name:  "Example 21",
		SK:    mustHexDecodeString("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7"),
		PK:    mustHexDecodeString("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025"),
		Alpha: mustHexDecodeString("af82"),
		X:     mustHexDecodeString("909a8b755ed902849023a55b15c23d11ba4d7f4ec5c2f51b1325a181991ea95c"),
		H:     mustHexDecodeString("13d2a8b5ca32db7e98094a61f656a08c6c964344e058879a386a947a4e189ed1"),
		Pi:    mustHexDecodeString("926e895d308f5e328e7aa159c06eddbe56d06846abf5d98c2512235eaa57fdce35b46edfc655bc828d44ad09d1150f31374e7ef73027e14760d42e77341fe05467bb286cc2c9d7fde29120a0b2320d04"),
		Beta:  mustHexDecodeString("121b7f9b9aaaa29099fc04a94ba52784d44eac976dd1a3cca458733be5cd090a7b5fbd148444f17f8daf1fb55cb04b1ae85a626e30a54b4b0f8abf4a43314a58"),
	},
}

func mustHexDecodeString(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}
