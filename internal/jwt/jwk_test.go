package jwt

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"errors"
	"strings"
	"testing"
)

const rfc7517A1 = `{"keys":
  [
    {"kty":"EC",
     "crv":"P-256",
     "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
     "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
     "use":"enc",
     "kid":"1"},

    {"kty":"RSA",
     "n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
     "e":"AQAB",
     "alg":"RS256",
     "kid":"2011-04-29"}
  ]
}`

const rfc8037A2 = `{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`

func mustJWKS(t *testing.T, s string) *jwkSet {
	t.Helper()
	set, err := parseJWKS([]byte(s))
	if err != nil {
		t.Fatalf("parseJWKS: %v", err)
	}
	return set
}

func TestParseJWKSRFC7517(t *testing.T) {
	set := mustJWKS(t, rfc7517A1)
	if len(set.Keys) != 2 {
		t.Fatalf("got %d keys, want 2", len(set.Keys))
	}

	ec, err := set.selectKey("1")
	if err != nil {
		t.Fatalf("selectKey(1): %v", err)
	}
	pub, err := ec.publicKey()
	if err != nil {
		t.Fatalf("EC publicKey: %v", err)
	}
	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("EC key is %T, want *ecdsa.PublicKey", pub)
	}
	if ecPub.Curve != elliptic.P256() {
		t.Fatalf("curve = %v, want P-256", ecPub.Curve.Params().Name)
	}

	rsaJWK, err := set.selectKey("2011-04-29")
	if err != nil {
		t.Fatalf("selectKey(2011-04-29): %v", err)
	}
	pub, err = rsaJWK.publicKey()
	if err != nil {
		t.Fatalf("RSA publicKey: %v", err)
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("RSA key is %T, want *rsa.PublicKey", pub)
	}
	if rsaPub.E != 65537 {
		t.Fatalf("exponent = %d, want 65537", rsaPub.E)
	}
	if got := rsaPub.N.BitLen(); got != 2048 {
		t.Fatalf("modulus is %d bits, want 2048", got)
	}
}

func TestParseJWKSRFC8037(t *testing.T) {
	set := mustJWKS(t, rfc8037A2)
	k, err := set.selectKey("")
	if err != nil {
		t.Fatalf("selectKey: %v", err)
	}
	pub, err := k.publicKey()
	if err != nil {
		t.Fatalf("publicKey: %v", err)
	}
	edPub, ok := pub.(ed25519.PublicKey)
	if !ok {
		t.Fatalf("key is %T, want ed25519.PublicKey", pub)
	}
	if len(edPub) != ed25519.PublicKeySize {
		t.Fatalf("key is %d bytes, want %d", len(edPub), ed25519.PublicKeySize)
	}
}

func TestSelectKey(t *testing.T) {
	tests := []struct {
		name    string
		set     string
		kid     string
		wantErr string
	}{
		{"exact kid", rfc7517A1, "1", ""},
		{"unknown kid", rfc7517A1, "nope", `no JWK with kid "nope"`},
		{"no kid, several keys", rfc7517A1, "", "the token has no kid and the JWK set holds 2 keys"},
		{"no kid, single key", rfc8037A2, "", ""},
		{"kid given, single unkeyed jwk", rfc8037A2, "whatever", ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := mustJWKS(t, tc.set).selectKey(tc.kid)
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case tc.wantErr != "" && err == nil:
				t.Fatalf("expected error containing %q", tc.wantErr)
			case tc.wantErr != "" && !strings.Contains(err.Error(), tc.wantErr):
				t.Fatalf("error = %v, want it to contain %q", err, tc.wantErr)
			}
			if err != nil && !errors.Is(err, ErrKeyUnreadable) {
				t.Fatalf("error does not wrap ErrKeyUnreadable: %v", err)
			}
		})
	}
}

func TestJWKRejectsBadKeys(t *testing.T) {
	tests := []struct {
		name string
		jwk  string
		want string
	}{
		{"no kty", `{"n":"AQAB","e":"AQAB"}`, "no keys in the JWK set"},
		{"unknown kty", `{"kty":"WAT","x":"AA"}`, `unsupported JWK kty "WAT"`},
		{"unknown curve", `{"kty":"EC","crv":"P-999","x":"AA","y":"AA"}`, `unsupported EC curve`},
		{"unknown okp curve", `{"kty":"OKP","crv":"X25519","x":"AA"}`, "unsupported OKP curve"},
		{"short ed25519", `{"kty":"OKP","crv":"Ed25519","x":"AAAA"}`, "Ed25519 x is 3 bytes"},
		{"rsa missing e", `{"kty":"RSA","n":"AQAB"}`, "needs both n and e"},
		{"not base64url", `{"kty":"RSA","n":"!!!","e":"AQAB"}`, "not base64url"},
		{"not json", `nope`, "not valid JSON"},
		{
			"ec point off curve",
			`{"kty":"EC","crv":"P-256","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4"}`,
			"not on curve",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			set, err := parseJWKS([]byte(tc.jwk))
			if err == nil {
				var k *jwk
				k, err = set.selectKey("")
				if err == nil {
					_, err = k.publicKey()
				}
			}
			if err == nil {
				t.Fatalf("expected an error containing %q", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want it to contain %q", err, tc.want)
			}
			if !errors.Is(err, ErrKeyUnreadable) {
				t.Fatalf("error does not wrap ErrKeyUnreadable: %v", err)
			}
		})
	}
}

func TestJWKPrivateAndSymmetric(t *testing.T) {
	tests := []struct {
		name       string
		jwk        string
		private    bool
		asymmetric bool
	}{
		{"public ed25519", rfc8037A2, false, true},
		{"private ed25519", `{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"}`, true, true},
		{"oct secret", `{"kty":"oct","k":"eW91ci0yNTYtYml0LXNlY3JldA"}`, true, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			k, err := mustJWKS(t, tc.jwk).selectKey("")
			if err != nil {
				t.Fatalf("selectKey: %v", err)
			}
			if k.hasPrivate() != tc.private {
				t.Errorf("hasPrivate = %v, want %v", k.hasPrivate(), tc.private)
			}
			if k.isAsymmetric() != tc.asymmetric {
				t.Errorf("isAsymmetric = %v, want %v", k.isAsymmetric(), tc.asymmetric)
			}
		})
	}
}

func TestJWKOctYieldsRawBytes(t *testing.T) {
	k, err := mustJWKS(t, `{"kty":"oct","k":"eW91ci0yNTYtYml0LXNlY3JldA"}`).selectKey("")
	if err != nil {
		t.Fatalf("selectKey: %v", err)
	}
	pub, err := k.publicKey()
	if err != nil {
		t.Fatalf("publicKey: %v", err)
	}
	if got, ok := pub.([]byte); !ok || string(got) != jwtIOSecret {
		t.Fatalf("oct key = %q, want %q", pub, jwtIOSecret)
	}
}
