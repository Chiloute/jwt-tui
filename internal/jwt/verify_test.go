package jwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"testing"

	jwtlib "github.com/golang-jwt/jwt/v5"
)

const (
	rfc7515A1Token = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9" +
		".eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ" +
		".dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	rfc7515A1Key = "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"
)

const (
	jwtIOToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" +
		".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ" +
		".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	jwtIOSecret = "your-256-bit-secret"
)

func TestVerifyRFC7515A1(t *testing.T) {
	got := VerifyToken(rfc7515A1Token, "b64:"+rfc7515A1Key)
	if got.Sig != SigValid {
		t.Fatalf("Sig = %v (%s), want SigValid", got.Sig, got.SigError)
	}
	if got.Alg != "HS256" {
		t.Fatalf("Alg = %q, want HS256", got.Alg)
	}
	if got.SigBytes != 32 {
		t.Fatalf("SigBytes = %d, want 32", got.SigBytes)
	}
}

func TestVerifyJWTIOVector(t *testing.T) {
	if got := VerifyToken(jwtIOToken, jwtIOSecret); got.Sig != SigValid {
		t.Fatalf("Sig = %v (%s), want SigValid", got.Sig, got.SigError)
	}
}

func TestVerifyStates(t *testing.T) {
	tampered := strings.Replace(jwtIOToken,
		"eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ",
		"eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkphbmUgRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ", 1)

	tests := []struct {
		name  string
		token string
		key   string
		want  SigState
	}{
		{"empty", "", jwtIOSecret, SigEmpty},
		{"only whitespace", "   \n", jwtIOSecret, SigEmpty},
		{"two segments", "aaa.bbb", jwtIOSecret, SigMalformed},
		{"header not base64url", "!!!.bbb.ccc", jwtIOSecret, SigMalformed},
		{"header not json", "aGVsbG8.bbb.ccc", jwtIOSecret, SigMalformed},
		{"payload not base64url", "eyJhbGciOiJIUzI1NiJ9.!!!.ccc", jwtIOSecret, SigMalformed},
		{"signature not base64url", "eyJhbGciOiJIUzI1NiJ9.e30.!!!", jwtIOSecret, SigMalformed},
		{"no key", jwtIOToken, "", SigNoKey},
		{"wrong secret", jwtIOToken, "not-the-secret", SigInvalid},
		{"tampered payload", tampered, jwtIOSecret, SigInvalid},
		{"empty signature", "eyJhbGciOiJIUzI1NiJ9.e30.", jwtIOSecret, SigInvalid},
		{"alg none", "eyJhbGciOiJub25lIn0.e30.", jwtIOSecret, SigAlgNone},
		{"alg NONE uppercase", "eyJhbGciOiJOT05FIn0.e30.", jwtIOSecret, SigAlgNone},
		{"alg missing", "eyJ0eXAiOiJKV1QifQ.e30.", jwtIOSecret, SigAlgMissing},
		{"alg not a string", "eyJhbGciOjEyM30.e30.", jwtIOSecret, SigAlgMissing},
		{"unknown alg", "eyJhbGciOiJIUzk5OSJ9.e30.aaaa", jwtIOSecret, SigInvalid},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := VerifyToken(tc.token, tc.key)
			if got.Sig != tc.want {
				t.Fatalf("Sig = %v (%s), want %v", got.Sig, got.SigError, tc.want)
			}
		})
	}
}

func TestAlgNoneNeverVerifies(t *testing.T) {
	forged := "eyJhbGciOiJub25lIn0.eyJhZG1pbiI6dHJ1ZX0.anything"
	if got := VerifyToken(forged, jwtIOSecret); got.Sig == SigValid {
		t.Fatal("alg:none token reported as valid")
	}
}

func TestAlgConfusionIsRefused(t *testing.T) {
	_, pubPEM := generateRSAKeys(t)

	forged, err := jwtlib.NewWithClaims(jwtlib.SigningMethodHS256,
		jwtlib.MapClaims{"admin": true}).SignedString([]byte(pubPEM))
	if err != nil {
		t.Fatalf("forging the token: %v", err)
	}

	got := VerifyToken(forged, pubPEM)
	if got.Sig != SigAlgConfusion {
		t.Fatalf("Sig = %v (%s), want SigAlgConfusion", got.Sig, got.SigError)
	}
}

func TestAsymmetricVerification(t *testing.T) {
	rsaPriv, rsaPub := generateRSAKeys(t)
	ecPriv, ecPub := generateECKeys(t)
	edPriv, edPub := generateEd25519Keys(t)

	tests := []struct {
		alg      string
		signWith crypto.PrivateKey
		privPEM  string
		pubPEM   string
	}{
		{"RS256", mustParseRSAPriv(t, rsaPriv), rsaPriv, rsaPub},
		{"PS256", mustParseRSAPriv(t, rsaPriv), rsaPriv, rsaPub},
		{"ES256", mustParseECPriv(t, ecPriv), ecPriv, ecPub},
		{"EdDSA", mustParseEdPriv(t, edPriv), edPriv, edPub},
	}

	for _, tc := range tests {
		t.Run(tc.alg, func(t *testing.T) {
			token, err := jwtlib.NewWithClaims(jwtlib.GetSigningMethod(tc.alg),
				jwtlib.MapClaims{"sub": "1"}).SignedString(tc.signWith)
			if err != nil {
				t.Fatalf("signing: %v", err)
			}

			if got := VerifyToken(token, tc.pubPEM); got.Sig != SigValid {
				t.Fatalf("with public key: Sig = %v (%s), want SigValid", got.Sig, got.SigError)
			}
			if got := VerifyToken(token, tc.privPEM); got.Sig != SigValid {
				t.Fatalf("with private key: Sig = %v (%s), want SigValid", got.Sig, got.SigError)
			}
			if got := VerifyToken(token, "just-a-string"); got.Sig != SigKeyUnreadable {
				t.Fatalf("with a plain string: Sig = %v (%s), want SigKeyUnreadable", got.Sig, got.SigError)
			}
		})
	}
}

func TestVerifyFromFileAndJWKS(t *testing.T) {
	priv, pub := generateRSAKeys(t)
	token, err := jwtlib.NewWithClaims(jwtlib.SigningMethodRS256,
		jwtlib.MapClaims{"sub": "1"}).SignedString(mustParseRSAPriv(t, priv))
	if err != nil {
		t.Fatalf("signing: %v", err)
	}

	pubFile := writeFile(t, "pub.pem", []byte(pub))
	if got := VerifyToken(token, "@"+pubFile); got.Sig != SigValid {
		t.Fatalf("@file: Sig = %v (%s), want SigValid", got.Sig, got.SigError)
	}

	keyed := jwtlib.NewWithClaims(jwtlib.SigningMethodRS256, jwtlib.MapClaims{"sub": "1"})
	keyed.Header["kid"] = "k1"
	signed, err := keyed.SignedString(mustParseRSAPriv(t, priv))
	if err != nil {
		t.Fatalf("signing keyed token: %v", err)
	}
	jwks := rsaJWKS(t, pub, "k1")
	jwksFile := writeFile(t, "jwks.json", []byte(jwks))
	if got := VerifyToken(signed, "@"+jwksFile); got.Sig != SigValid {
		t.Fatalf("JWKS by kid: Sig = %v (%s), want SigValid", got.Sig, got.SigError)
	}

	other := rsaJWKS(t, pub, "other")
	got := VerifyToken(signed, other)
	if got.Sig != SigKeyUnreadable {
		t.Fatalf("unknown kid: Sig = %v, want SigKeyUnreadable", got.Sig)
	}
	if !strings.Contains(got.SigError, "k1") {
		t.Fatalf("error should name the kid k1: %q", got.SigError)
	}
}

func TestAlgConfusionFromFile(t *testing.T) {
	_, pub := generateRSAKeys(t)
	pubFile := writeFile(t, "pub.pem", []byte(pub))

	forged, err := jwtlib.NewWithClaims(jwtlib.SigningMethodHS256,
		jwtlib.MapClaims{"admin": true}).SignedString([]byte(pub))
	if err != nil {
		t.Fatalf("forging: %v", err)
	}
	if got := VerifyToken(forged, "@"+pubFile); got.Sig != SigAlgConfusion {
		t.Fatalf("Sig = %v (%s), want SigAlgConfusion", got.Sig, got.SigError)
	}
}

func TestWrongAsymmetricKeyIsInvalid(t *testing.T) {
	priv, _ := generateRSAKeys(t)
	_, otherPub := generateRSAKeys(t)

	token, err := jwtlib.NewWithClaims(jwtlib.SigningMethodRS256,
		jwtlib.MapClaims{"sub": "1"}).SignedString(mustParseRSAPriv(t, priv))
	if err != nil {
		t.Fatalf("signing: %v", err)
	}

	if got := VerifyToken(token, otherPub); got.Sig != SigInvalid {
		t.Fatalf("Sig = %v (%s), want SigInvalid", got.Sig, got.SigError)
	}
}

func TestTrailingNewlineInSecret(t *testing.T) {
	got := VerifyToken(jwtIOToken, jwtIOSecret+"\n")
	if got.Sig != SigValid {
		t.Fatalf("Sig = %v (%s), want SigValid", got.Sig, got.SigError)
	}
	if !got.KeyTrimmed {
		t.Fatal("KeyTrimmed not set, the user has no way to know the key differs")
	}
	if got.KeyBytes != len(jwtIOSecret) {
		t.Fatalf("KeyBytes = %d, want %d", got.KeyBytes, len(jwtIOSecret))
	}

	if got := VerifyToken(jwtIOToken, "nope\n"); got.Sig != SigInvalid {
		t.Fatalf("Sig = %v (%s), want SigInvalid", got.Sig, got.SigError)
	}
}

func TestBase64Key(t *testing.T) {
	for _, encoded := range []string{
		"eW91ci0yNTYtYml0LXNlY3JldA==",
		"eW91ci0yNTYtYml0LXNlY3JldA",
	} {
		if got := VerifyToken(jwtIOToken, "b64:"+encoded); got.Sig != SigValid {
			t.Fatalf("%q: Sig = %v (%s), want SigValid", encoded, got.Sig, got.SigError)
		}
	}

	got := VerifyToken(jwtIOToken, "b64:not base64 !!!")
	if got.Sig != SigKeyUnreadable {
		t.Fatalf("Sig = %v (%s), want SigKeyUnreadable", got.Sig, got.SigError)
	}
}

func TestVerifyIgnoresExpiry(t *testing.T) {
	token, err := jwtlib.NewWithClaims(jwtlib.SigningMethodHS256,
		jwtlib.MapClaims{"exp": 1}).SignedString([]byte(jwtIOSecret))
	if err != nil {
		t.Fatalf("signing: %v", err)
	}

	got := VerifyToken(token, jwtIOSecret)
	if got.Sig != SigValid {
		t.Fatalf("Sig = %v (%s), want SigValid", got.Sig, got.SigError)
	}
	if got.Temporal != TempExpired {
		t.Fatalf("Temporal = %v, want TempExpired", got.Temporal)
	}
}

func generateRSAKeys(t *testing.T) (privPEM, pubPEM string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa keygen: %v", err)
	}
	return pkcs8PEM(t, key), pkixPEM(t, &key.PublicKey)
}

func generateECKeys(t *testing.T) (privPEM, pubPEM string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa keygen: %v", err)
	}
	return pkcs8PEM(t, key), pkixPEM(t, &key.PublicKey)
}

func rsaJWKS(t *testing.T, pubPEM, kid string) string {
	t.Helper()
	block, _ := pem.Decode([]byte(pubPEM))
	if block == nil {
		t.Fatal("bad public PEM")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse public key: %v", err)
	}
	rsaPub := pub.(*rsa.PublicKey)
	n := base64.RawURLEncoding.EncodeToString(rsaPub.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(rsaPub.E)).Bytes())
	return fmt.Sprintf(`{"keys":[{"kty":"RSA","kid":%q,"n":%q,"e":%q}]}`, kid, n, e)
}

func generateEd25519Keys(t *testing.T) (privPEM, pubPEM string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 keygen: %v", err)
	}
	return pkcs8PEM(t, priv), pkixPEM(t, pub)
}

func pkcs8PEM(t *testing.T, key crypto.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func pkixPEM(t *testing.T, key crypto.PublicKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func mustParseRSAPriv(t *testing.T, pemStr string) *rsa.PrivateKey {
	t.Helper()
	key, err := jwtlib.ParseRSAPrivateKeyFromPEM([]byte(pemStr))
	if err != nil {
		t.Fatalf("parse RSA private key: %v", err)
	}
	return key
}

func mustParseECPriv(t *testing.T, pemStr string) *ecdsa.PrivateKey {
	t.Helper()
	key, err := jwtlib.ParseECPrivateKeyFromPEM([]byte(pemStr))
	if err != nil {
		t.Fatalf("parse EC private key: %v", err)
	}
	return key
}

func mustParseEdPriv(t *testing.T, pemStr string) crypto.PrivateKey {
	t.Helper()
	key, err := jwtlib.ParseEdPrivateKeyFromPEM([]byte(pemStr))
	if err != nil {
		t.Fatalf("parse Ed25519 private key: %v", err)
	}
	return key
}
