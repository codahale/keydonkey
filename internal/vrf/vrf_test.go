package vrf

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"
)

func TestExamples(t *testing.T) {
	for _, tv := range testVectors {
		t.Run(tv.Name, func(t *testing.T) {
			sk := NewProvingKey(tv.SK)
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
	Name                          string
	SK, PK, Alpha, X              []byte
	Ctr                           int
	H, KString, K, U, V, Pi, Beta []byte
}{
	{
		Name:    "Example 16",
		SK:      mustHexDecodeString("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"),
		PK:      mustHexDecodeString("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"),
		Alpha:   nil,
		X:       mustHexDecodeString("307c83864f2833cb427a2ef1c00a013cfdff2768d980c0a3a520f006904de94f"),
		Ctr:     0,
		H:       mustHexDecodeString("91bbed02a99461df1ad4c6564a5f5d829d0b90cfc7903e7a5797bd658abf3318"),
		KString: mustHexDecodeString("7100f3d9eadb6dc4743b029736ff283f5be494128df128df2817106f345b8594b6d6da2d6fb0b4c0257eb337675d96eab49cf39e66cc2c9547c2bf8b2a6afae4"),
		K:       mustHexDecodeString("8a49edbd1492a8ee09766befe50a7d563051bf3406cbffc20a88def030730f0f"),
		U:       mustHexDecodeString("aef27c725be964c6a9bf4c45ca8e35df258c1878b838f37d9975523f09034071"),
		V:       mustHexDecodeString("5016572f71466c646c119443455d6cb9b952f07d060ec8286d678615d55f954f"),
		Pi:      mustHexDecodeString("8657106690b5526245a92b003bb079ccd1a92130477671f6fc01ad16f26f723f26f8a57ccaed74ee1b190bed1f479d9727d2d0f9b005a6e456a35d4fb0daab1268a1b0db10836d9826a528ca76567805"),
		Beta:    mustHexDecodeString("90cf1df3b703cce59e2a35b925d411164068269d7b2d29f3301c03dd757876ff66b71dda49d2de59d03450451af026798e8f81cd2e333de5cdf4f3e140fdd8ae"),
	},

	{
		Name:    "Example 17",
		SK:      mustHexDecodeString("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"),
		PK:      mustHexDecodeString("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"),
		Alpha:   mustHexDecodeString("72"),
		X:       mustHexDecodeString("68bd9ed75882d52815a97585caf4790a7f6c6b3b7f821c5e259a24b02e502e51"),
		Ctr:     1,
		H:       mustHexDecodeString("5b659fc3d4e9263fd9a4ed1d022d75eaacc20df5e09f9ea937502396598dc551"),
		KString: mustHexDecodeString("42589bbf0c485c3c91c1621bb4bfe04aed7be76ee48f9b00793b2342acb9c167cab856f9f9d4febc311330c20b0a8afd3743d05433e8be8d32522ecdc16cc5ce"),
		K:       mustHexDecodeString("d8c3a66921444cb3427d5d989f9b315aa8ca3375e9ec4d52207711a1fdb44107"),
		U:       mustHexDecodeString("1dcb0a4821a2c48bf53548228b7f170962988f6d12f5439f31987ef41f034ab3"),
		V:       mustHexDecodeString("fd03c0bf498c752161bae4719105a074630a2aa5f200ff7b3995f7bfb1513423"),
		Pi:      mustHexDecodeString("f3141cd382dc42909d19ec5110469e4feae18300e94f304590abdced48aed5933bf0864a62558b3ed7f2fea45c92a465301b3bbf5e3e54ddf2d935be3b67926da3ef39226bbc355bdc9850112c8f4b02"),
		Beta:    mustHexDecodeString("eb4440665d3891d668e7e0fcaf587f1b4bd7fbfe99d0eb2211ccec90496310eb5e33821bc613efb94db5e5b54c70a848a0bef4553a41befc57663b56373a5031"),
	},

	{
		Name:    "Example 18",
		SK:      mustHexDecodeString("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7"),
		PK:      mustHexDecodeString("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025"),
		Alpha:   mustHexDecodeString("af82"),
		X:       mustHexDecodeString("909a8b755ed902849023a55b15c23d11ba4d7f4ec5c2f51b1325a181991ea95c"),
		Ctr:     0,
		H:       mustHexDecodeString("bf4339376f5542811de615e3313d2b36f6f53c0acfebb482159711201192576a"),
		KString: mustHexDecodeString("38b868c335ccda94a088428cbf3ec8bc7955bfaffe1f3bd2aa2c59fc31a0febc59d0e1af3715773ce11b3bbdd7aba8e3505d4b9de6f7e4a96e67e0d6bb6d6c3a"),
		K:       mustHexDecodeString("5ffdbc72135d936014e8ab708585fda379405542b07e3bd2c0bd48437fbac60a"),
		U:       mustHexDecodeString("2bae73e15a64042fcebf062abe7e432b2eca6744f3e8265bc38e009cd577ecd5"),
		V:       mustHexDecodeString("88cba1cb0d4f9b649d9a86026b69de076724a93a65c349c988954f0961c5d506"),
		Pi:      mustHexDecodeString("9bc0f79119cc5604bf02d23b4caede71393cedfbb191434dd016d30177ccbf8096bb474e53895c362d8628ee9f9ea3c0e52c7a5c691b6c18c9979866568add7a2d41b00b05081ed0f58ee5e31b3a970e"),
		Beta:    mustHexDecodeString("645427e5d00c62a23fb703732fa5d892940935942101e456ecca7bb217c61c452118fec1219202a0edcf038bb6373241578be7217ba85a2687f7a0310b2df19f"),
	},
}

func mustHexDecodeString(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}
