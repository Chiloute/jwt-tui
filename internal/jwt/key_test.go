package jwt

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeFile(t *testing.T, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

func TestResolveKeyInline(t *testing.T) {
	tests := []struct {
		name string
		spec string
		enc  KeyEncoding
		want string
	}{
		{"plain", "hunter2", EncPlain, "hunter2"},
		{"plain untrimmed", "hunter2\n", EncPlain, "hunter2\n"},
		{"b64 std padded", "b64:aHVudGVyMg==", EncPlain, "hunter2"},
		{"b64 url raw", "b64:aHVudGVyMg", EncPlain, "hunter2"},
		{"empty", "", EncNone, ""},
		{"blank", "   ", EncNone, ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			k, err := ResolveKey(tc.spec)
			if err != nil {
				t.Fatalf("ResolveKey: %v", err)
			}
			if k.Encoding != tc.enc {
				t.Fatalf("encoding = %v, want %v", k.Encoding, tc.enc)
			}
			if tc.want != "" && string(k.Bytes) != tc.want {
				t.Fatalf("bytes = %q, want %q", k.Bytes, tc.want)
			}
		})
	}
}

func TestResolveKeyBadBase64(t *testing.T) {
	_, err := ResolveKey("b64:not valid !!!")
	if err == nil || !errors.Is(err, ErrKeyUnreadable) {
		t.Fatalf("err = %v, want ErrKeyUnreadable", err)
	}
	if !strings.Contains(err.Error(), "not valid base64") {
		t.Fatalf("err = %v, want a base64 message", err)
	}
}

func TestResolveKeyFromFile(t *testing.T) {
	_, pubPEM := generateRSAKeys(t)
	path := writeFile(t, "pub.pem", []byte(pubPEM))

	k, err := ResolveKey("@" + path)
	if err != nil {
		t.Fatalf("ResolveKey: %v", err)
	}
	if k.Encoding != EncPEM {
		t.Fatalf("encoding = %v, want EncPEM", k.Encoding)
	}
	if k.Origin != path {
		t.Fatalf("origin = %q, want %q", k.Origin, path)
	}
	if k.Private {
		t.Fatal("public key reported as private")
	}
}

func TestResolveKeyTildeExpansion(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("no home dir: %v", err)
	}
	f, err := os.CreateTemp(home, "jwt-tui-key-*.pem")
	if err != nil {
		t.Skipf("cannot write to home: %v", err)
	}
	defer os.Remove(f.Name())
	_, pubPEM := generateRSAKeys(t)
	f.WriteString(pubPEM)
	f.Close()

	spec := "@~/" + filepath.Base(f.Name())
	k, err := ResolveKey(spec)
	if err != nil {
		t.Fatalf("ResolveKey(%q): %v", spec, err)
	}
	if k.Encoding != EncPEM {
		t.Fatalf("encoding = %v, want EncPEM", k.Encoding)
	}
}

func TestResolveKeyMissingFile(t *testing.T) {
	_, err := ResolveKey("@/no/such/key.pem")
	if err == nil || !errors.Is(err, ErrKeyUnreadable) {
		t.Fatalf("err = %v, want ErrKeyUnreadable", err)
	}
	if strings.Contains(err.Error(), "asn1") {
		t.Fatalf("a missing file should not surface an ASN.1 error: %v", err)
	}
}

func TestResolveKeyPrivateDetection(t *testing.T) {
	rsaPriv, rsaPub := generateRSAKeys(t)
	tests := []struct {
		name    string
		spec    string
		private bool
	}{
		{"rsa public pem", rsaPub, false},
		{"rsa private pem", rsaPriv, true},
		{"hmac secret", "hunter2", true},
		{"jwks public", rfc8037A2, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			k, err := ResolveKey(tc.spec)
			if err != nil {
				t.Fatalf("ResolveKey: %v", err)
			}
			if k.Private != tc.private {
				t.Fatalf("private = %v, want %v", k.Private, tc.private)
			}
		})
	}
}

func TestResolveKeyInlinePEMandJWKS(t *testing.T) {
	if k, _ := ResolveKey(rfc8037A2); k.Encoding != EncJWKS {
		t.Fatalf("inline JWKS: encoding = %v, want EncJWKS", k.Encoding)
	}
	_, pubPEM := generateRSAKeys(t)
	if k, _ := ResolveKey(pubPEM); k.Encoding != EncPEM {
		t.Fatalf("inline PEM: encoding = %v, want EncPEM", k.Encoding)
	}
}

func TestResolveKeyDER(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	path := writeFile(t, "pub.der", der)

	k, err := ResolveKey("@" + path)
	if err != nil {
		t.Fatalf("ResolveKey: %v", err)
	}
	if k.Encoding != EncDER {
		t.Fatalf("encoding = %v, want EncDER", k.Encoding)
	}
	pub, err := k.VerificationKey("RS256", "")
	if err != nil {
		t.Fatalf("VerificationKey: %v", err)
	}
	if _, ok := pub.(*rsa.PublicKey); !ok {
		t.Fatalf("key is %T, want *rsa.PublicKey", pub)
	}
}

func TestVerificationKeyFamilyMismatch(t *testing.T) {
	_, ecPub := generateECKeys(t)
	k, err := ResolveKey(ecPub)
	if err != nil {
		t.Fatalf("ResolveKey: %v", err)
	}
	_, err = k.VerificationKey("RS256", "")
	if err == nil || !strings.Contains(err.Error(), "RS256 needs a RSA key") {
		t.Fatalf("err = %v, want a family-mismatch message", err)
	}
}

func TestSigningKeyRejectsPublic(t *testing.T) {
	_, pubPEM := generateRSAKeys(t)
	k, err := ResolveKey(pubPEM)
	if err != nil {
		t.Fatalf("ResolveKey: %v", err)
	}
	_, err = k.SigningKey("RS256", "")
	if err == nil || !strings.Contains(err.Error(), "private half") {
		t.Fatalf("err = %v, want a 'needs the private half' message", err)
	}
}

func TestSigningKeyFromPrivate(t *testing.T) {
	tests := []struct {
		name string
		gen  func(*testing.T) (string, string)
		alg  string
		want any
	}{
		{"rsa", generateRSAKeys, "RS256", &rsa.PrivateKey{}},
		{"ec", generateECKeys, "ES256", &ecdsa.PrivateKey{}},
		{"ed25519", generateEd25519Keys, "EdDSA", ed25519.PrivateKey{}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			priv, _ := tc.gen(t)
			k, err := ResolveKey(priv)
			if err != nil {
				t.Fatalf("ResolveKey: %v", err)
			}
			signing, err := k.SigningKey(tc.alg, "")
			if err != nil {
				t.Fatalf("SigningKey: %v", err)
			}
			switch tc.want.(type) {
			case *rsa.PrivateKey:
				if _, ok := signing.(*rsa.PrivateKey); !ok {
					t.Fatalf("key is %T, want *rsa.PrivateKey", signing)
				}
			case *ecdsa.PrivateKey:
				if _, ok := signing.(*ecdsa.PrivateKey); !ok {
					t.Fatalf("key is %T, want *ecdsa.PrivateKey", signing)
				}
			case ed25519.PrivateKey:
				if _, ok := signing.(ed25519.PrivateKey); !ok {
					t.Fatalf("key is %T, want ed25519.PrivateKey", signing)
				}
			}
		})
	}
}

func TestVerificationKeyFromPrivatePEM(t *testing.T) {
	priv, _ := generateRSAKeys(t)
	k, err := ResolveKey(priv)
	if err != nil {
		t.Fatalf("ResolveKey: %v", err)
	}
	pub, err := k.VerificationKey("RS256", "")
	if err != nil {
		t.Fatalf("VerificationKey: %v", err)
	}
	if _, ok := pub.(*rsa.PublicKey); !ok {
		t.Fatalf("key is %T, want *rsa.PublicKey", pub)
	}
}

func TestKeyFileCacheInvalidates(t *testing.T) {
	priv1, pub1 := generateRSAKeys(t)
	priv2, _ := generateRSAKeys(t)
	path := writeFile(t, "rotating.pem", []byte(pub1))

	k, _ := ResolveKey("@" + path)
	if !strings.Contains(pemString(t, k.Bytes), "PUBLIC KEY") {
		t.Fatal("first read did not return the public key")
	}

	if err := os.WriteFile(path, []byte(priv2), 0o600); err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	forceNewerMtime(t, path)

	k2, _ := ResolveKey("@" + path)
	if !k2.Private {
		t.Fatal("cache served the stale public key after the file became private")
	}
	_ = priv1
}

func pemString(t *testing.T, b []byte) string {
	t.Helper()
	return string(b)
}

func forceNewerMtime(t *testing.T, path string) {
	t.Helper()
	st, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	newer := st.ModTime().Add(2 * time.Second)
	if err := os.Chtimes(path, newer, newer); err != nil {
		t.Fatalf("chtimes: %v", err)
	}
}

func TestResolveKeyKeepsPEMBytes(t *testing.T) {
	_, pubPEM := generateRSAKeys(t)
	k, _ := ResolveKey(pubPEM)
	block, _ := pem.Decode(k.Bytes)
	if block == nil {
		t.Fatal("resolved PEM no longer decodes")
	}
}
